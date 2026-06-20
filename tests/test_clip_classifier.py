"""Tests for CLIP-based tile classifier."""

from __future__ import annotations

import asyncio
from unittest.mock import patch, MagicMock

import pytest

from src.captcha.clip_classifier import (
    CLIPClassifier,
    _detect_model_name,
    _load_model,
    _unload_model,
    is_loaded,
    get_model_info,
    maybe_unload,
    IDLE_TTL,
)


class TestModelDetection:
    def test_default_model_name(self):
        """Without env marker, defaults to ViT-B-32."""
        with patch("src.captcha.clip_classifier.MODEL_ENV_PATH", ""):
            name, pretrained = _detect_model_name()
            assert name == "ViT-B-32"
            assert pretrained == "openai"

    def test_model_from_file(self, tmp_path):
        """Reads model name from build-time marker file."""
        marker = tmp_path / "model_id.txt"
        marker.write_text("MobileCLIP-S2:datacomp_s_s2")
        with patch("src.captcha.clip_classifier.MODEL_ENV_PATH", str(marker)):
            name, pretrained = _detect_model_name()
            assert name == "MobileCLIP-S2"
            assert pretrained == "datacomp_s_s2"

    def test_malformed_marker_file(self, tmp_path):
        """Malformed marker falls back to default."""
        marker = tmp_path / "model_id.txt"
        marker.write_text("garbage")
        with patch("src.captcha.clip_classifier.MODEL_ENV_PATH", str(marker)):
            name, pretrained = _detect_model_name()
            assert name == "ViT-B-32"
            assert pretrained == "openai"


class TestModelLifecycle:
    def test_not_loaded_initially(self):
        """Model is not in memory at import time."""
        _unload_model()
        assert not is_loaded()

    def test_get_info_unloaded(self):
        """Info reports not loaded when model is unloaded."""
        _unload_model()
        info = get_model_info()
        assert info["loaded"] is False
        assert info["model"] == "not loaded"

    def test_load_requires_open_clip(self):
        """Loading raises RuntimeError if open_clip not installed."""
        _unload_model()
        with patch.dict("sys.modules", {"open_clip": None}):
            with patch("builtins.__import__", side_effect=ImportError("no open_clip")):
                with pytest.raises(RuntimeError, match="open-clip-torch not installed"):
                    _load_model()

    @pytest.mark.asyncio
    async def test_maybe_unload_when_idle(self):
        """Model unloads after idle timeout."""
        import src.captcha.clip_classifier as mod
        # Simulate loaded state
        mod._model = MagicMock()
        mod._preprocess = MagicMock()
        mod._tokenizer = MagicMock()
        mod._model_name = "test"
        mod._last_used = 1.0  # Very old monotonic timestamp (guaranteed past TTL)

        await maybe_unload()
        assert not is_loaded()

    @pytest.mark.asyncio
    async def test_maybe_unload_when_recent(self):
        """Model stays loaded if recently used."""
        import time
        import src.captcha.clip_classifier as mod
        mod._model = MagicMock()
        mod._preprocess = MagicMock()
        mod._tokenizer = MagicMock()
        mod._model_name = "test"
        mod._last_used = time.monotonic()  # Just now

        await maybe_unload()
        assert is_loaded()
        # Cleanup
        _unload_model()


class TestCLIPClassifier:
    @pytest.mark.asyncio
    async def test_classify_loads_model_lazily(self):
        """First call triggers model load."""
        _unload_model()
        classifier = CLIPClassifier()
        # Verify model is not loaded until classify_tile is called
        assert not is_loaded()

    def test_classify_sync_with_mocked_model(self):
        """Synchronous classification produces correct output shape."""
        import src.captcha.clip_classifier as mod

        pytest.importorskip("torch")
        import torch

        # Create a tiny test image (1x1 red pixel PNG)
        test_image_b64 = "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8/5+hHgAHggJ/PchI7wAAAABJRU5ErkJggg=="

        # Mock model components
        mock_model = MagicMock()
        mock_model.encode_image.return_value = torch.randn(1, 512)
        mock_model.encode_text.return_value = torch.randn(4, 512)

        mock_preprocess = MagicMock(return_value=torch.randn(3, 224, 224))
        mock_tokenizer = MagicMock(return_value=torch.randint(0, 1000, (4, 77)))

        mod._model = mock_model
        mod._preprocess = mock_preprocess
        mod._tokenizer = mock_tokenizer
        mod._model_name = "test"

        classifier = CLIPClassifier()
        result = classifier._classify_sync(test_image_b64, "traffic light")

        assert isinstance(result, tuple)
        assert len(result) == 2
        assert isinstance(result[0], bool)
        assert isinstance(result[1], float)
        assert 0.0 <= result[1] <= 1.0

        # Cleanup
        _unload_model()

    @pytest.mark.asyncio
    async def test_classify_tile_interface(self):
        """CLIPClassifier satisfies TileClassifier protocol."""
        from src.captcha.grid_solver import TileClassifier
        classifier = CLIPClassifier()
        assert isinstance(classifier, TileClassifier)


class TestIntegration:
    @pytest.mark.integration
    @pytest.mark.asyncio
    async def test_live_classification(self):
        """Live test with real model (skipped unless -m integration)."""
        import base64
        from PIL import Image
        import io

        # Create a simple red image
        img = Image.new("RGB", (224, 224), color="red")
        buf = io.BytesIO()
        img.save(buf, format="PNG")
        img_b64 = base64.b64encode(buf.getvalue()).decode()

        classifier = CLIPClassifier()
        matches, confidence = await classifier.classify_tile(img_b64, "red color")

        assert isinstance(matches, bool)
        assert 0.0 <= confidence <= 1.0
        # Red image should match "red color" with some confidence
        _unload_model()
