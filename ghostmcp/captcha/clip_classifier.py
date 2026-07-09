"""CLIP-based tile classifier for CAPTCHA grid solving.

Uses MobileCLIP-S2 (150MB, ~200MB RAM) or ViT-B-32 (340MB, ~400MB RAM)
for zero-shot image classification. Lazy-loads on first use, auto-unloads
after idle timeout to free memory.

Implements the TileClassifier protocol from grid_solver.py.
"""

from __future__ import annotations

import asyncio
import base64
import io
import os
import time
from typing import Optional

# Lazy imports — only loaded when classify_tile is called
_model = None
_preprocess = None
_tokenizer = None
_model_name = ""
_last_used = 0.0
_lock = asyncio.Lock()

# Configuration
IDLE_TTL = 300.0  # Unload model after 5 minutes idle
MODEL_ENV_PATH = os.environ.get("GHOST_CLIP_MODEL_PATH", "")


def _detect_model_name() -> tuple[str, str]:
    """Detect which model to load based on build-time marker or availability."""
    # Check build-time marker first
    if MODEL_ENV_PATH and os.path.exists(MODEL_ENV_PATH):
        with open(MODEL_ENV_PATH) as f:
            parts = f.read().strip().split(":")
            if len(parts) == 2:
                return parts[0], parts[1]
    
    # Default: try MobileCLIP first, fall back to ViT-B-32
    return "ViT-B-32", "openai"


def _load_model():
    """Load CLIP model into memory. Called lazily on first use."""
    global _model, _preprocess, _tokenizer, _model_name
    
    try:
        import open_clip
        import torch
    except ImportError:
        raise RuntimeError(
            "open-clip-torch not installed. "
            "Install with: pip install open-clip-torch torch --index-url https://download.pytorch.org/whl/cpu"
        )
    
    model_name, pretrained = _detect_model_name()
    
    try:
        _model, _, _preprocess = open_clip.create_model_and_transforms(
            model_name, pretrained=pretrained
        )
        _tokenizer = open_clip.get_tokenizer(model_name)
        _model_name = f"{model_name}:{pretrained}"
        _model.eval()
    except Exception:
        # Fallback to ViT-B-32
        _model, _, _preprocess = open_clip.create_model_and_transforms(
            "ViT-B-32", pretrained="openai"
        )
        _tokenizer = open_clip.get_tokenizer("ViT-B-32")
        _model_name = "ViT-B-32:openai"
        _model.eval()


def _unload_model():
    """Unload model from memory to free RAM."""
    global _model, _preprocess, _tokenizer, _model_name
    _model = None
    _preprocess = None
    _tokenizer = None
    _model_name = ""


def is_loaded() -> bool:
    """Check if model is currently in memory."""
    return _model is not None


def get_model_info() -> dict:
    """Get info about the loaded model (or lack thereof)."""
    return {
        "loaded": is_loaded(),
        "model": _model_name or "not loaded",
        "idle_ttl_seconds": IDLE_TTL,
        "last_used_seconds_ago": int(time.monotonic() - _last_used) if _last_used > 0 else -1,
    }


async def maybe_unload():
    """Unload model if idle past TTL. Call periodically (e.g., from a background task)."""
    global _last_used
    async with _lock:
        if _model is not None and _last_used > 0:
            if time.monotonic() - _last_used > IDLE_TTL:
                _unload_model()


class CLIPClassifier:
    """CLIP-based TileClassifier with lazy loading and auto-unload.
    
    Implements the TileClassifier protocol from grid_solver.py.
    
    Usage:
        classifier = CLIPClassifier()
        matches, confidence = await classifier.classify_tile(image_b64, "traffic light")
    """
    
    async def classify_tile(self, image_base64: str, target_label: str) -> tuple[bool, float]:
        """Classify whether an image tile matches the target label.
        
        Args:
            image_base64: Base64-encoded PNG of the tile
            target_label: What to look for ("traffic light", "bicycle", etc.)
            
        Returns:
            (matches: bool, confidence: float 0-1)
        """
        global _last_used
        
        async with _lock:
            # Lazy load
            if _model is None:
                await asyncio.get_event_loop().run_in_executor(None, _load_model)
            _last_used = time.monotonic()
        
        # Run inference in thread pool (model is CPU-bound)
        result = await asyncio.get_event_loop().run_in_executor(
            None, self._classify_sync, image_base64, target_label
        )
        return result
    
    def _classify_sync(self, image_base64: str, target_label: str) -> tuple[bool, float]:
        """Synchronous classification (runs in thread pool)."""
        import torch
        from PIL import Image
        
        # Decode image
        img_bytes = base64.b64decode(image_base64)
        image = Image.open(io.BytesIO(img_bytes)).convert("RGB")
        
        # Preprocess
        image_tensor = _preprocess(image).unsqueeze(0)
        
        # Create text inputs — compare against target + negative
        texts = [
            f"a photo of a {target_label}",
            f"a photo of something that is not a {target_label}",
            "an empty image",
            "a blurry unrecognizable image",
        ]
        text_tokens = _tokenizer(texts)
        
        # Compute similarity
        with torch.no_grad():
            image_features = _model.encode_image(image_tensor)
            text_features = _model.encode_text(text_tokens)
            
            # Normalize
            image_features = image_features / image_features.norm(dim=-1, keepdim=True)
            text_features = text_features / text_features.norm(dim=-1, keepdim=True)
            
            # Cosine similarity
            similarities = (image_features @ text_features.T).squeeze(0)
            
            # Softmax to get probabilities
            probs = similarities.softmax(dim=-1)
            
            # First text is the positive match
            confidence = probs[0].item()
        
        # Threshold: > 0.5 means more similar to target than to negatives
        matches = confidence > 0.5
        
        return (matches, confidence)
