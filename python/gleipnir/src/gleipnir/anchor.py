"""Anchors publish segment hashes outside the vendor's control.

``LocalFileAnchor`` is for tests and demos: it writes to a local append-only log, so it
is not independent of the vendor. ``RekorAnchor`` publishes to Sigstore Rekor.
"""

from __future__ import annotations

import json
import os
import threading
from pathlib import Path
from typing import Any, Protocol

from gleipnir_verify.anchors import local_log_entry_hash

from .util import Clock, iso, utcnow


class Anchor(Protocol):
    type: str

    def anchor(self, *, segment_hash: str, chain: str, segment_seq: int) -> dict[str, Any]:
        """Publish ``segment_hash`` and return a receipt (JSON object)."""
        ...


class LocalFileAnchor:
    type = "local"

    def __init__(self, path: str | Path, clock: Clock = utcnow):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.clock = clock
        self._lock = threading.Lock()

    def _last(self) -> dict[str, Any] | None:
        if not self.path.exists():
            return None
        last = None
        with open(self.path, encoding="utf-8") as fh:
            for line in fh:
                if line.strip():
                    last = line
        return json.loads(last) if last else None

    def anchor(self, *, segment_hash: str, chain: str, segment_seq: int) -> dict[str, Any]:
        with self._lock:
            last = self._last()
            entry: dict[str, Any] = {
                "v": 1,
                "index": 0 if last is None else last["index"] + 1,
                "chain": chain,
                "segment_seq": segment_seq,
                "segment_hash": segment_hash,
                "time": iso(self.clock()),
            }
            if last is not None:
                entry["prev"] = last["hash"]
            entry["hash"] = local_log_entry_hash(entry)
            with open(self.path, "a", encoding="utf-8") as fh:
                fh.write(json.dumps(entry, sort_keys=True, separators=(",", ":")) + "\n")
                fh.flush()
                os.fsync(fh.fileno())
            return {"index": entry["index"], "entry_hash": entry["hash"], "time": entry["time"],
                    "log": self.path.name}


DEFAULT_REKOR_V2_URL = "https://log2025-1.rekor.sigstore.dev"


class RekorAnchor:
    """Publishes segment hashes to Sigstore Rekor v2 (public, append-only).

    Only a hash, an ECDSA P-256 signature and the anchor public key are sent. Rekor v2 does
    not accept pure Ed25519 for ``hashedrekord`` entries, so anchoring uses a separate
    P-256 key; records themselves stay Ed25519-signed.

    The shard URL changes over time (Sigstore announces shards via its TUF repository);
    pass ``url`` to override the default.
    """

    type = "rekor"

    def __init__(self, home: str | Path = ".gleipnir", *, url: str = DEFAULT_REKOR_V2_URL, timeout: float = 60.0,
                 clock: Clock = utcnow, private_key: Any = None, quiet: bool = False):
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import ec

        self.url = url.rstrip("/")
        self.timeout = timeout
        self.clock = clock
        if private_key is None:
            path = Path(home) / "keys" / "anchor-ecdsa-p256.pem"
            if path.exists():
                private_key = serialization.load_pem_private_key(path.read_bytes(), password=None)
            else:
                from .keys import write_private_file

                private_key = ec.generate_private_key(ec.SECP256R1())
                write_private_file(path, private_key.private_bytes(
                    serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
        if not isinstance(private_key, ec.EllipticCurvePrivateKey) or private_key.curve.name != "secp256r1":
            raise ValueError("Rekor anchor key must be ECDSA P-256")
        self._key = private_key
        self.public_der = private_key.public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)

    def _post(self, body: dict[str, Any]) -> dict[str, Any]:
        import urllib.request

        req = urllib.request.Request(
            f"{self.url}/api/v2/log/entries", data=json.dumps(body).encode(), method="POST",
            headers={"Content-Type": "application/json", "Accept": "application/json",
                     "User-Agent": "gleipnir-sdk"})
        with urllib.request.urlopen(req, timeout=self.timeout) as resp:  # noqa: S310 - fixed https URL
            return json.loads(resp.read())

    def anchor(self, *, segment_hash: str, chain: str, segment_seq: int) -> dict[str, Any]:
        import base64
        import hashlib

        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import ec

        from gleipnir_verify.rekor import anchor_message, verify_rekor_receipt

        message = anchor_message(segment_hash)
        sig = self._key.sign(message, ec.ECDSA(hashes.SHA256()))

        def b64(b: bytes) -> str:
            return base64.b64encode(b).decode()

        body = {"hashedRekordRequestV002": {
            "digest": b64(hashlib.sha256(message).digest()),
            "signature": {"content": b64(sig), "verifier": {
                "publicKey": {"rawBytes": b64(self.public_der)}, "keyDetails": "PKIX_ECDSA_P256_SHA_256"}}}}
        entry = self._post(body)
        receipt = {"log_url": self.url, "entry": entry,
                   "anchor_key": {"alg": "ecdsa-p256-sha256", "public": b64(self.public_der)},
                   "observed_at": iso(self.clock())}
        check = verify_rekor_receipt({"receipt": receipt}, segment_hash=segment_hash, options={})
        if check.ok is not True:
            raise RuntimeError(f"Rekor returned a receipt that does not verify: {check.detail}")
        return receipt
