"""Offline verification of RFC 3161 timestamp receipts on segment hashes.

The token must be a valid TSA signature over SHA-256 of
``"gleipnir/timestamp/v1\\n" || segment_hash``, chaining to a timestamp authority in the
Sigstore trusted root (embedded, or supplied with ``trusted_root``).
"""

from __future__ import annotations

import base64
from typing import Any

from .anchors import AnchorResult

TIMESTAMP_DOMAIN = b"gleipnir/timestamp/v1\n"


def timestamp_message(segment_hash: str) -> bytes:
    return TIMESTAMP_DOMAIN + segment_hash.encode("ascii")


def _authorities(options: dict[str, Any]) -> list[dict[str, Any]]:
    from .rekor import load_trusted_root

    return load_trusted_root(options).get("timestampAuthorities", [])


def verify_timestamp_receipt(receipt: dict[str, Any], *, segment_hash: str, options: dict[str, Any]) -> AnchorResult:
    try:
        from cryptography import x509
        from rfc3161_client import VerifierBuilder, decode_timestamp_response
    except ImportError as exc:  # pragma: no cover - dependency is required by the package
        return AnchorResult(None, f"rfc3161-client not installed: {exc}")
    try:
        raw = base64.b64decode(receipt["receipt"]["response"], validate=True)
        resp = decode_timestamp_response(raw)
    except Exception as exc:  # noqa: BLE001 - hostile input
        return AnchorResult(False, f"malformed timestamp response: {type(exc).__name__}: {exc}")
    message = timestamp_message(segment_hash)
    errors = []
    for tsa in _authorities(options):
        try:
            certs = [x509.load_der_x509_certificate(base64.b64decode(c["rawBytes"]))
                     for c in tsa["certChain"]["certificates"]]
            verifier = VerifierBuilder(tsa_certificate=certs[0], roots=[certs[-1]],
                                       intermediates=certs[1:-1]).build()
            if verifier.verify_message(resp, message):
                gen = resp.tst_info.gen_time
                when = gen.strftime("%Y-%m-%dT%H:%M:%S") + "Z"
                return AnchorResult(True, f"timestamped by {tsa.get('uri', 'TSA')} at {when}", independent=True,
                                    time=when)
        except Exception as exc:  # noqa: BLE001 - try the next authority
            errors.append(f"{type(exc).__name__}: {exc}")
    return AnchorResult(False, "timestamp does not verify against any trusted authority"
                        + (f" ({errors[-1]})" if errors else ""))
