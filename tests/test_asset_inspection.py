"""Metadata-only render evidence, local bridge opt-in and redaction."""

import json
import os
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import pytest

from ghostmcp.recon.asset_inspection import AssetRecorder, MAX_REQUESTS, safe_url
from ghostmcp.recon.render import RenderReport, render_page


def request(url, previous=None):
    return SimpleNamespace(url=url, method="GET", resource_type="image", redirected_from=previous)


@pytest.mark.asyncio
async def test_variant_fixture_evidence_and_redaction():
    fixture = Path(__file__).parent / "fixtures" / "asset_inspection.html"
    assert "large.png?token=private123" in fixture.read_text()
    rec = AssetRecorder()
    small = request("https://example.test/assets/small.png?token=private123")
    large = request("https://example.test/assets/large.png?token=private123", small)
    ad = request("https://example.test/ads/missing.png?key=private123")
    for req in (small, large, ad):
        rec.on_request(req)
    rec.on_response(SimpleNamespace(request=small, status=200, headers={"content-type": "image/png", "content-length": "567"}))
    rec.on_response(SimpleNamespace(request=large, status=200, headers={"content-type": "image/png"}))
    rec.on_failed(ad)
    page = SimpleNamespace(evaluate=AsyncMock(side_effect=[
        [{"tag": "img", "url": large.url, "label": "Hero variant", "width": 64, "height": 64},
         {"tag": "img", "url": ad.url, "label": "Ad"},
         {"tag": "a", "url": "https://example.test/assets/guide.pdf?signature=private123", "label": "Guide"}],
        {"login": False, "age": False},
    ]))
    report = RenderReport(url="https://example.test/?token=private123", title="Asset fixture", status_code=200)
    result = await rec.finish(page, report)
    assert result["elements"][0]["request_ids"] == [result["requests"][1]["id"]]
    assert result["elements"][0]["url_id"] == result["requests"][1]["url_id"]
    assert result["elements"][0]["evidence"] == "observed_response"
    assert result["elements"][1]["evidence"] == "page_advertised_only"
    assert result["requests"][2]["failure"] is True
    assert result["requests"][1]["redirected_from"] == result["requests"][0]["id"]
    assert result["elements"][2]["tag"] == "a"
    assert "private123" not in json.dumps(result)
    assert "large.png" not in json.dumps(result)


@pytest.mark.asyncio
async def test_gate_and_bounded_requests():
    rec = AssetRecorder()
    for n in range(MAX_REQUESTS + 2):
        rec.on_request(request(f"https://example.test/{n}?auth=private123"))
    page = SimpleNamespace(evaluate=AsyncMock(side_effect=[[], {"login": True, "age": False}]))
    result = await rec.finish(page, RenderReport(url="https://example.test/login", status_code=200))
    assert result["access_state"] == "login"
    assert len(result["requests"]) == MAX_REQUESTS
    assert result["omitted_requests"] == 2
    assert "private123" not in json.dumps(result)


def test_url_redaction_including_userinfo_and_invalid_input():
    assert safe_url("https://user:pass@example.test/private/path?token=123#secret") == {
        "origin": "[redacted]", "path": "[redacted]"}
    assert safe_url("javascript:alert(1)")["origin"] == "[redacted]"
    assert safe_url("https://example.test:invalid/")["origin"] == "[redacted]"


@pytest.mark.asyncio
async def test_inspection_mode_avoids_raw_dom_and_console():
    from tests.test_render import _make_mock_playwright
    mock_pw, _, _, page = _make_mock_playwright()
    page.evaluate = AsyncMock(side_effect=[[], {"login": False, "age": False}])
    mock_async_playwright = AsyncMock()
    mock_async_playwright.__aenter__ = AsyncMock(return_value=mock_pw)
    mock_async_playwright.__aexit__ = AsyncMock(return_value=False)
    with patch("playwright.async_api.async_playwright", return_value=mock_async_playwright):
        result = await render_page("https://example.test/?token=private123", wait_ms=0, inspect_assets=True)
    assert result.asset_inspection is not None
    page.content.assert_not_called()
    assert "console" not in page._event_handlers
    assert "pageerror" not in page._event_handlers


@pytest.mark.asyncio
async def test_bridge_requires_separate_metadata_opt_in():
    from ghostmcp.mcp import _bridge_clients, ghost_render
    report = RenderReport(url="http://localhost:3000", title="Fixture", asset_inspection={"elements": []})
    with patch.dict(_bridge_clients, {"test": {"ports": [3000], "allow_asset_inspection": False}}, clear=True), \
         patch("ghostmcp.recon.render.render_page", new_callable=AsyncMock, return_value=report) as renderer:
        assert "must opt in" in await ghost_render("http://localhost:3000", inspect_assets=True)
        renderer.assert_not_called()
        _bridge_clients["test"]["allow_asset_inspection"] = True
        result = await ghost_render("http://localhost:3000", inspect_assets=True)
        assert json.loads(result) == {"elements": []}
        assert renderer.await_args.kwargs["inspect_assets"] is True


@pytest.mark.asyncio
async def test_resource_filter_does_not_leave_dangling_evidence():
    from ghostmcp.mcp import ghost_render
    result = {"requests": [{"id": "opaque", "resource_type": "image", "url": {"origin": "https://example.test"}, "redirected_from": None}],
              "elements": [{"url": {"origin": "https://example.test"}, "request_ids": ["opaque"], "evidence": "observed_response"}]}
    report = RenderReport(url="https://example.test", asset_inspection=result)
    with patch("ghostmcp.mcp.render_page", new_callable=AsyncMock, return_value=report):
        filtered = json.loads(await ghost_render("https://example.test", inspect_assets=True, asset_resource_type="media"))
    assert filtered["requests"] == []
    assert filtered["elements"][0]["request_ids"] == []
    assert filtered["elements"][0]["evidence"] == "page_advertised_only"


def test_local_client_registration_and_reconfiguration(tmp_path):
    pytest.importorskip("client.ghost_client", reason="local bridge client is not bundled in the server image")
    from client.ghost_client import BridgeConfig
    cfg_file = tmp_path / "client.yaml"
    cfg_file.write_text("server: ws://localhost/bridge\nports: [3000]\nallow_asset_inspection: true\n")
    cfg = BridgeConfig.from_file(str(cfg_file))
    assert cfg.to_registration()["allow_asset_inspection"] is True
    cfg_file.write_text("server: ws://localhost/bridge\nports: [3000]\nallow_asset_inspection: false\n")
    os.utime(cfg_file, (cfg._last_mtime + 2, cfg._last_mtime + 2))
    assert cfg.check_for_changes() is True
    assert cfg.to_registration()["allow_asset_inspection"] is False


def test_bridge_logs_do_not_contain_signed_urls():
    pytest.importorskip("client.ghost_client", reason="local bridge client is not bundled in the server image")
    from client.ghost_client import _safe_log_url
    assert _safe_log_url("https://user:pass@example.test/private?token=private123") == "[redacted]"
    assert _safe_log_url("https://example.test/private?token=private123") == "https://example.test"


def test_bridge_registration_gates_and_revokes_asset_inspection():
    from ghostmcp.mcp import _bridge_clients, build_server_app
    from starlette.testclient import TestClient

    with patch.dict(_bridge_clients, {}, clear=True), TestClient(build_server_app()) as client:
        with client.websocket_connect("/bridge") as ws:
            ws.send_json({"type": "register", "client_id": "fixture", "ports": [3030]})
            assert ws.receive_json()["type"] == "registered"
            assert _bridge_clients["fixture"]["allow_asset_inspection"] is False
            ws.send_json({"type": "register", "ports": [3030], "allow_asset_inspection": True})
            assert ws.receive_json()["type"] == "registered"
            assert _bridge_clients["fixture"]["allow_asset_inspection"] is True
            ws.send_json({"type": "register", "ports": [3030], "allow_asset_inspection": False})
            assert ws.receive_json()["type"] == "registered"
            assert _bridge_clients["fixture"]["allow_asset_inspection"] is False
        assert "fixture" not in _bridge_clients


@pytest.mark.integration
@pytest.mark.asyncio
async def test_real_chromium_fixture_selects_variant():
    """Run inside the GhostMCP image with its actual Playwright/Chromium runtime."""
    fixture = (Path(__file__).parent / "fixtures" / "asset_inspection.html").read_text()

    async def route_handler(route, req):
        if req.url.startswith("https://fixture.test/assets/") and req.url.endswith(".pdf?signature=private123"):
            await route.fulfill(status=200, body=b"%PDF-1.0", content_type="application/pdf")
        elif "/ads/" in req.url:
            await route.abort()
        elif "/assets/" in req.url:
            await route.fulfill(status=200, body=b"image", content_type="image/png")
        else:
            await route.fulfill(status=200, body=fixture, content_type="text/html")

    result = await render_page("https://fixture.test/?token=private123", wait_ms=200,
                               execute_js="document.getElementById('variant').click()",
                               inspect_assets=True, route_handler=route_handler)
    assert result.error is None, result.error
    evidence = result.asset_inspection
    assert evidence["access_state"] == "normal"
    hero = next(el for el in evidence["elements"] if el["label"] == "Hero variant")
    assert hero["evidence"] == "observed_response"
    assert hero["variant"] == "Large"
    assert hero["request_ids"]
    assert hero["url_id"] == next(r["url_id"] for r in evidence["requests"] if r["id"] == hero["request_ids"][0])
    assert any(r["failure"] for r in evidence["requests"])
    assert "private123" not in json.dumps(evidence)
    assert "large.png" not in json.dumps(evidence)


@pytest.mark.asyncio
async def test_sensitive_element_labels_and_header_values_never_returned():
    rec = AssetRecorder()
    req = request("https://example.test/secret?token=private123")
    rec.on_request(req)
    rec.on_response(SimpleNamespace(request=req, status=200, headers={
        "content-type": "text/html\r\nAuthorization: private123", "content-length": "12",
        "set-cookie": "session=private123", "authorization": "Bearer private123",
    }))
    page = SimpleNamespace(evaluate=AsyncMock(side_effect=[
        [{"tag": "img", "url": req.url, "label": "token private123", "advertised": True}],
        {"login": False, "age": False},
    ]))
    result = await rec.finish(page, RenderReport(url=req.url, status_code=200))
    assert result["elements"][0]["label"] == ""
    assert result["elements"][0]["has_advertised_variants"] is True
    assert result["requests"][0]["mime_type"] is None
    assert "private123" not in json.dumps(result)
