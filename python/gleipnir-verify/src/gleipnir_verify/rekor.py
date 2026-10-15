"""Offline verification of Sigstore Rekor v2 anchor receipts.

A receipt is the transparency log entry Rekor returned when the vendor published a
segment hash, plus the anchor public key. Verification needs no network:

1. The log entry body is a ``hashedrekord`` whose digest is SHA-256 of
   ``"gleipnir/anchor/v1\\n" || segment_hash`` and whose signature verifies with the
   anchor key. So the entry is about this segment, made by the holder of the anchor key.
2. The entry is included in the log: RFC 6962 inclusion proof against the proof's root.
3. That root is in a checkpoint signed by the log's key, pinned in the embedded
   Sigstore trusted root (or one supplied with ``trusted_root``).
"""

from __future__ import annotations

import base64
import hashlib
import json
from functools import lru_cache
from importlib import resources
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519

from . import merkle
from .anchors import AnchorResult

ANCHOR_DOMAIN = b"gleipnir/anchor/v1\n"


def anchor_message(segment_hash: str) -> bytes:
    return ANCHOR_DOMAIN + segment_hash.encode("ascii")


@lru_cache(maxsize=4)
def _embedded_trusted_root() -> dict[str, Any]:
    text = resources.files("gleipnir_verify").joinpath("data/sigstore_trusted_root.json").read_text("utf-8")
    return json.loads(text)


def load_trusted_root(options: dict[str, Any]) -> dict[str, Any]:
    path = options.get("trusted_root")
    if path:
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)
    return _embedded_trusted_root()


def _strict_uint(value: Any) -> int:
    """Non-negative decimal integer as Rekor encodes it (a JSON string of ASCII digits, or an int)."""
    if isinstance(value, bool):
        raise ValueError("not an integer")
    if isinstance(value, int) and value >= 0:
        return value
    if isinstance(value, str) and value.isascii() and value.isdigit():
        return int(value)
    raise ValueError(f"not a decimal integer: {value!r}")


def _b64(text: str) -> bytes:
    return base64.b64decode(text, validate=True)


def _find_log(trusted_root: dict[str, Any], key_id: bytes) -> dict[str, Any] | None:
    for tlog in trusted_root.get("tlogs", []):
        if _b64(tlog["logId"]["keyId"]) == key_id:
            return tlog
    return None


def _verify_note_signature(public_der: bytes, key_details: str, data: bytes, sig: bytes) -> bool:
    key = serialization.load_der_public_key(public_der)
    try:
        if key_details == "PKIX_ED25519" and isinstance(key, ed25519.Ed25519PublicKey):
            key.verify(sig, data)
            return True
        if key_details.startswith("PKIX_ECDSA_P256") and isinstance(key, ec.EllipticCurvePublicKey):
            key.verify(sig, data, ec.ECDSA(hashes.SHA256()))
            return True
    except InvalidSignature:
        return False
    return False


def parse_checkpoint(envelope: str) -> tuple[str, int, bytes, str, list[tuple[str, bytes]]]:
    """Return (origin, size, root, note_text, [(signer_name, sig_bytes_with_keyhash)])."""
    if envelope.count("\n\n") != 1:
        raise ValueError("checkpoint must contain exactly one blank line")
    split = envelope.index("\n\n")
    note = envelope[: split + 1]
    sig_block = envelope[split + 2 :]
    lines = note.rstrip("\n").split("\n")
    if len(lines) < 3:
        raise ValueError("checkpoint note too short")
    origin, size, root = lines[0], int(lines[1]), _b64(lines[2])
    sigs = []
    for line in sig_block.split("\n"):
        if not line.startswith("— "):
            continue
        _, name, sig = line.split(" ", 2)
        sigs.append((name, _b64(sig)))
    return origin, size, root, note, sigs


def verify_rekor_receipt(receipt: dict[str, Any], *, segment_hash: str, options: dict[str, Any]) -> AnchorResult:
    try:
        r = receipt["receipt"]
        entry = r["entry"]
        proof = entry["inclusionProof"]
        anchor_key_der = _b64(r["anchor_key"]["public"])

        # 1. body is a hashedrekord over this segment, signed by the anchor key
        body_bytes = _b64(entry["canonicalizedBody"])
        body = json.loads(body_bytes)
        spec = body["spec"]["hashedRekordV002"]
        message = anchor_message(segment_hash)
        if body.get("kind") != "hashedrekord":
            return AnchorResult(False, "log entry is not a hashedrekord")
        if spec["data"].get("algorithm") != "SHA2_256" or _b64(spec["data"]["digest"]) != hashlib.sha256(
                message).digest():
            return AnchorResult(False, "log entry digest is not this segment")
        verifier = spec["signature"]["verifier"]
        if _b64(verifier["publicKey"]["rawBytes"]) != anchor_key_der:
            return AnchorResult(False, "log entry was made with a different anchor key")
        key = serialization.load_der_public_key(anchor_key_der)
        if not isinstance(key, ec.EllipticCurvePublicKey):
            return AnchorResult(False, "unsupported anchor key type")
        try:
            key.verify(_b64(spec["signature"]["content"]), message, ec.ECDSA(hashes.SHA256()))
        except InvalidSignature:
            return AnchorResult(False, "anchor signature in the log entry does not verify")

        # 2. inclusion proof
        index, size = _strict_uint(proof["logIndex"]), _strict_uint(proof["treeSize"])
        root = _b64(proof["rootHash"])
        path = [_b64(h) for h in proof["hashes"]]
        if not merkle.verify_inclusion(index, size, merkle.leaf_hash(body_bytes), path, root):
            return AnchorResult(False, "inclusion proof does not verify")

        # 3. checkpoint signed by a pinned log key
        trusted = load_trusted_root(options)
        log_key_id = _b64(entry["logId"]["keyId"])
        tlog = _find_log(trusted, log_key_id)
        if tlog is None:
            return AnchorResult(False, "log is not in the trusted root (unknown or newer shard; "
                                       "pass a current Sigstore trusted root with --trusted-root)")
        origin, cp_size, cp_root, note, sigs = parse_checkpoint(proof["checkpoint"]["envelope"])
        expected_origin = tlog["baseUrl"].split("://", 1)[-1].rstrip("/")
        if origin != expected_origin:
            return AnchorResult(False, f"checkpoint origin {origin!r} does not match log {expected_origin!r}")
        if cp_size != size or cp_root != root:
            return AnchorResult(False, "checkpoint does not match the inclusion proof")
        pub = tlog["publicKey"]
        ok = False
        for name, sig in sigs:
            if name == origin and sig[:4] == log_key_id[:4]:
                ok = _verify_note_signature(_b64(pub["rawBytes"]), pub["keyDetails"], note.encode("utf-8"),
                                            sig[4:])
                if ok:
                    break
        if not ok:
            return AnchorResult(False, "checkpoint is not signed by the log key")
        return AnchorResult(True, f"included in {origin} at index {index}", independent=True)
    except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
        return AnchorResult(False, f"malformed Rekor receipt: {type(exc).__name__}: {exc}")
