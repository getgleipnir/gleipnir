"""Signers backed by cloud KMS/HSM, so the record signing key never sits in the agent process.

Ed25519 is used where the KMS supports it (AWS KMS, Google Cloud KMS software keys).
ECDSA P-256 is used otherwise (Azure Key Vault, Cloud KMS HSM keys); verifiers accept both.

    import boto3, gleipnir
    from gleipnir.kms import AwsKmsSigner

    signer = AwsKmsSigner("alias/gleipnir-records", client=boto3.client("kms"))
    rec = gleipnir.Recorder("support-agent", "3.2.4", signer=signer, anchor="rekor")

Each signer calls the KMS once per record. Clients are passed in (boto3, google-cloud-kms,
azure-keyvault-keys); none of those packages is a dependency of the SDK.
"""

from __future__ import annotations

import hashlib
from typing import Any

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

from gleipnir_verify.crypto import (
    encode_p256_public_key,
    encode_p256_signature,
    encode_public_key,
    encode_signature,
    key_id,
)


class _SpkiSigner:
    """Common handling of a public key given as DER SubjectPublicKeyInfo."""

    def _set_public(self, spki_der: bytes) -> None:
        key = serialization.load_der_public_key(spki_der)
        if isinstance(key, ed25519.Ed25519PublicKey):
            raw = key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
            self.alg = "ed25519"
            self._public = encode_public_key(raw)
            self._key_id = key_id(raw)
        elif isinstance(key, ec.EllipticCurvePublicKey) and key.curve.name == "secp256r1":
            self.alg = "ecdsa-p256"
            self._public = encode_p256_public_key(spki_der)
            self._key_id = key_id(("ecdsa-p256", spki_der))
        else:
            raise ValueError("KMS key must be Ed25519 or ECDSA P-256")

    @property
    def key_id(self) -> str:
        return self._key_id

    @property
    def public_key(self) -> str:
        return self._public

    def _encode(self, sig: bytes) -> str:
        return encode_signature(sig) if self.alg == "ed25519" else encode_p256_signature(sig)


class EcdsaP256Signer(_SpkiSigner):
    """Local ECDSA P-256 signer (tests, or keys exported from an HSM-less setup)."""

    def __init__(self, private_key: ec.EllipticCurvePrivateKey | None = None):
        self._key = private_key or ec.generate_private_key(ec.SECP256R1())
        self._set_public(self._key.public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo))

    def sign(self, message: bytes) -> str:
        return self._encode(self._key.sign(message, ec.ECDSA(hashes.SHA256())))


class AwsKmsSigner(_SpkiSigner):
    """AWS KMS key with KeySpec ECC_NIST_EDWARDS25519 (preferred) or ECC_NIST_P256."""

    def __init__(self, key_id: str, client: Any = None):
        if client is None:
            import boto3  # type: ignore[import-not-found]

            client = boto3.client("kms")
        self.client = client
        self.kms_key_id = key_id
        self._set_public(client.get_public_key(KeyId=key_id)["PublicKey"])

    def sign(self, message: bytes) -> str:
        algorithm = "ED25519_SHA_512" if self.alg == "ed25519" else "ECDSA_SHA_256"
        resp = self.client.sign(KeyId=self.kms_key_id, Message=message, MessageType="RAW",
                                SigningAlgorithm=algorithm)
        return self._encode(resp["Signature"])


class GcpKmsSigner(_SpkiSigner):
    """Google Cloud KMS key version with EC_SIGN_ED25519 (software) or EC_SIGN_P256_SHA256 (HSM too)."""

    def __init__(self, key_version_name: str, client: Any = None):
        if client is None:
            from google.cloud import kms  # type: ignore[import-not-found]

            client = kms.KeyManagementServiceClient()
        self.client = client
        self.name = key_version_name
        pem = client.get_public_key(request={"name": key_version_name}).pem
        key = serialization.load_pem_public_key(pem.encode() if isinstance(pem, str) else pem)
        self._set_public(key.public_bytes(serialization.Encoding.DER,
                                          serialization.PublicFormat.SubjectPublicKeyInfo))

    def sign(self, message: bytes) -> str:
        if self.alg == "ed25519":
            resp = self.client.asymmetric_sign(request={"name": self.name, "data": message})
        else:
            resp = self.client.asymmetric_sign(
                request={"name": self.name, "digest": {"sha256": hashlib.sha256(message).digest()}})
        return self._encode(resp.signature)


class AzureKeyVaultSigner(_SpkiSigner):
    """Azure Key Vault / Managed HSM EC key on P-256 (Azure has no Ed25519).

    ``crypto_client`` is an ``azure.keyvault.keys.crypto.CryptographyClient``; ``x`` and ``y`` are the
    key's public coordinates (``key.key.x``, ``key.key.y``).
    """

    def __init__(self, crypto_client: Any, x: bytes, y: bytes):
        self.client = crypto_client
        pub = ec.EllipticCurvePublicNumbers(int.from_bytes(x, "big"), int.from_bytes(y, "big"),
                                            ec.SECP256R1()).public_key()
        self._set_public(pub.public_bytes(serialization.Encoding.DER,
                                          serialization.PublicFormat.SubjectPublicKeyInfo))

    def sign(self, message: bytes) -> str:
        result = self.client.sign("ES256", hashlib.sha256(message).digest())
        raw = result.signature  # JOSE r||s, 64 bytes
        der = encode_dss_signature(int.from_bytes(raw[:32], "big"), int.from_bytes(raw[32:], "big"))
        return self._encode(der)
