"""Rekor anchor receipt verification (placeholder until the anchor stage)."""

from __future__ import annotations

from typing import Any

from .anchors import AnchorResult


def verify_rekor_receipt(receipt: dict[str, Any], *, segment_hash: str, options: dict[str, Any]) -> AnchorResult:
    return AnchorResult(None, "Rekor receipt verification not implemented yet")
