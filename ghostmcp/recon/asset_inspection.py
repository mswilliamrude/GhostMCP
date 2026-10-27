"""Bounded, metadata-only evidence collected during a single browser render."""

from __future__ import annotations

import ipaddress
import re
import secrets
import time
from urllib.parse import urlsplit

MAX_REQUESTS = 100
MAX_ELEMENTS = 60
_SAFE_LABEL = re.compile(r"^[\w .()\-]{1,60}$", re.UNICODE)
_SAFE_MIME = re.compile(r"^[a-z0-9.+-]{1,40}/[a-z0-9.+-]{1,40}$")
_SAFE_METHODS = {"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"}
_SAFE_RESOURCES = {"document", "stylesheet", "image", "media", "font", "script", "xhr", "fetch", "other", "websocket", "eventsource", "manifest"}


def safe_url(url: str) -> dict:
    """Never return URL query, fragment, credentials or opaque path segments."""
    try:
        parts = urlsplit(url)
        if parts.scheme not in ("http", "https") or not parts.hostname:
            return {"origin": "[redacted]", "path": "[redacted]"}
        host = parts.hostname.encode("idna").decode("ascii")
        if not re.fullmatch(r"[a-zA-Z0-9.:-]{1,255}", host):
            return {"origin": "[redacted]", "path": "[redacted]"}
        try:
            if isinstance(ipaddress.ip_address(host), ipaddress.IPv6Address):
                host = f"[{host}]"
        except ValueError:
            pass
        if parts.username is not None or parts.password is not None:
            return {"origin": "[redacted]", "path": "[redacted]"}
        port = f":{parts.port}" if parts.port else ""
        return {"origin": f"{parts.scheme}://{host}{port}",
                "path": "/" if parts.path in ("", "/") else "/[redacted]"}
    except (ValueError, UnicodeError):
        return {"origin": "[redacted]", "path": "[redacted]"}


def safe_label(value: str) -> str:
    """Expose only short, simple UI labels (no URLs, tokens or free text)."""
    value = value.strip()
    if not _SAFE_LABEL.fullmatch(value) or re.search(r"\d{4,}|[_-][a-f0-9]{8,}", value, re.I) or any(
        term in value.lower() for term in ("token", "secret", "password", "auth", "key")
    ):
        return ""
    return value


_ELEMENTS_JS = """() => {
  const found = Array.from(document.querySelectorAll('img,video,audio,source,a[href]'));
  return found.slice(0, 61).map(el => {
    const tag = el.tagName.toLowerCase();
    const url = tag === 'a' ? el.href : (el.currentSrc || el.src || '');
    return {
      tag, url,
      label: el.getAttribute('aria-label') || el.getAttribute('alt') || el.getAttribute('title') || '',
      advertised: el.hasAttribute('srcset'),
      type: el.getAttribute('type') || '',
      variant: el.getAttribute('data-variant') || '',
      width: el.naturalWidth || el.videoWidth || el.width || 0,
      height: el.naturalHeight || el.videoHeight || el.height || 0
    };
  });
}"""


class AssetRecorder:
    """Keep raw URLs only inside this per-call recorder for exact-match correlation."""

    def __init__(self) -> None:
        self._records: list[tuple[object, dict]] = []
        self._url_ids: dict[str, str] = {}
        self.omitted_requests = 0
        self.started_at = time.monotonic()

    def url_id(self, url: str) -> str:
        """An opaque per-call reference; never derive it from a signed URL."""
        if not url:
            return ""
        if url not in self._url_ids:
            self._url_ids[url] = secrets.token_hex(8)
        return self._url_ids[url]

    def on_request(self, request) -> None:
        if len(self._records) >= MAX_REQUESTS:
            self.omitted_requests += 1
            return
        record = {
            "id": secrets.token_hex(8),
            "url": safe_url(request.url),
            "url_id": self.url_id(request.url),
            "method": request.method if request.method in _SAFE_METHODS else "other",
            "resource_type": request.resource_type if request.resource_type in _SAFE_RESOURCES else "other",
            "status": None,
            "mime_type": None,
            "length": None,
            "failure": False,
            "redirected_from": None,
            "started_ms": round((time.monotonic() - self.started_at) * 1000),
            "duration_ms": None,
        }
        self._records.append((request, record))
        previous = request.redirected_from
        if previous is not None:
            record["redirected_from"] = next(
                (r["id"] for req, r in self._records if req is previous), None
            )

    def on_response(self, response) -> None:
        record = next((r for req, r in self._records if req is response.request), None)
        if record is None:
            return
        record["status"] = response.status
        record["duration_ms"] = max(0, round((time.monotonic() - self.started_at) * 1000) - record["started_ms"])
        # Only read two known-safe header fields; never retain arbitrary headers.
        headers = response.headers
        mime = headers.get("content-type", "").split(";", 1)[0].strip().lower()
        record["mime_type"] = mime if _SAFE_MIME.fullmatch(mime) else None
        length = headers.get("content-length", "")
        record["length"] = int(length) if length.isdigit() and len(length) <= 16 else None

    def on_failed(self, request) -> None:
        record = next((r for req, r in self._records if req is request), None)
        if record is not None:
            record["failure"] = True  # No raw Playwright error text (may contain URLs).
            record["duration_ms"] = max(0, round((time.monotonic() - self.started_at) * 1000) - record["started_ms"])

    async def finish(self, page, report) -> dict:
        raw_elements = await page.evaluate(_ELEMENTS_JS)
        if not isinstance(raw_elements, list):
            raw_elements = []
        elements = []
        for item in raw_elements[:MAX_ELEMENTS]:
            if not isinstance(item, dict) or item.get("tag") not in ("img", "video", "audio", "source", "a"):
                continue
            url = item.get("url") or ""
            if not isinstance(url, str):
                continue
            # Links to ordinary pages aren't document assets; use actual URL path
            # for classification, but never include it in the returned result.
            if item["tag"] == "a" and not re.search(r"\.(pdf|docx?|xlsx?|pptx?)(?:[?#]|$)", url, re.I):
                continue
            matches = [r["id"] for req, r in self._records if url and req.url == url
                       and r["status"] is not None and 200 <= r["status"] < 400]
            dims = {}
            for key in ("width", "height"):
                value = item.get(key)
                if isinstance(value, (int, float)) and not isinstance(value, bool) and 0 <= value <= 100000:
                    dims[key] = value
            elements.append({
                "tag": item["tag"],
                "url": safe_url(url),
                "url_id": self.url_id(url),
                "label": safe_label(item.get("label", "") if isinstance(item.get("label"), str) else ""),
                "type": safe_label(item.get("type", "") if isinstance(item.get("type"), str) else ""),
                "variant": safe_label(item.get("variant", "") if isinstance(item.get("variant"), str) else ""),
                "dimensions": dims,
                "request_ids": matches[:5],
                "evidence": "observed_response" if matches else "page_advertised_only",
                "has_advertised_variants": item.get("advertised") is True,
            })

        # A login/gate page cannot establish that assets are absent.
        gate = await page.evaluate("""() => ({
          login: !!document.querySelector('input[type=password]'),
          age: !!document.querySelector('[data-age-gate], [id*=age-gate], [class*=age-gate]')
        })""")
        if not isinstance(gate, dict):
            gate = {}
        access = "error" if report.status_code >= 400 or report.error else (
            "login" if gate.get("login") else "age-gate" if gate.get("age") else "normal"
        )
        if access == "normal" and not elements and not self._records:
            access = "unknown"
        return {
            "title": safe_label(report.title),
            "final_url": safe_url(report.final_url or report.url),
            "access_state": access,
            "elements": elements,
            "requests": [r for _, r in self._records],
            "omitted_requests": self.omitted_requests,
            "omitted_elements": max(0, len(raw_elements) - MAX_ELEMENTS),
        }
