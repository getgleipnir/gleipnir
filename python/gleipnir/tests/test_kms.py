"""KMS signers, tested with fake clients that behave like the real APIs (backed by local keys)."""

from types import SimpleNamespace

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

import gleipnir
from gleipnir.kms import AwsKmsSigner, AzureKeyVaultSigner, EcdsaP256Signer, GcpKmsSigner
from gleipnir_verify import verify_bundle


def spki(pub):
    return pub.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)


class FakeAwsKms:
    def __init__(self, key):
        self.key, self.calls = key, []

    def get_public_key(self, KeyId):  # noqa: N803 - AWS parameter names
        return {"PublicKey": spki(self.key.public_key())}

    def sign(self, KeyId, Message, MessageType, SigningAlgorithm):  # noqa: N803
        assert MessageType == "RAW" and len(Message) <= 4096
        self.calls.append(SigningAlgorithm)
        if SigningAlgorithm == "ED25519_SHA_512":
            return {"Signature": self.key.sign(Message)}
        assert SigningAlgorithm == "ECDSA_SHA_256"
        return {"Signature": self.key.sign(Message, ec.ECDSA(hashes.SHA256()))}


class FakeGcpKms:
    def __init__(self, key):
        self.key = key

    def get_public_key(self, request):
        pem = self.key.public_key().public_bytes(serialization.Encoding.PEM,
                                                 serialization.PublicFormat.SubjectPublicKeyInfo).decode()
        return SimpleNamespace(pem=pem)

    def asymmetric_sign(self, request):
        if "data" in request:
            return SimpleNamespace(signature=self.key.sign(request["data"]))
        from cryptography.hazmat.primitives.asymmetric.utils import Prehashed
        return SimpleNamespace(signature=self.key.sign(request["digest"]["sha256"],
                                                       ec.ECDSA(Prehashed(hashes.SHA256()))))


class FakeAzureCrypto:
    def __init__(self, key):
        self.key = key

    def sign(self, algorithm, digest):
        from cryptography.hazmat.primitives.asymmetric.utils import Prehashed
        assert algorithm == "ES256" and len(digest) == 32
        r, s = decode_dss_signature(self.key.sign(digest, ec.ECDSA(Prehashed(hashes.SHA256()))))
        return SimpleNamespace(signature=r.to_bytes(32, "big") + s.to_bytes(32, "big"))


def signers():
    ed = ed25519.Ed25519PrivateKey.generate()
    p1, p2, p3 = (ec.generate_private_key(ec.SECP256R1()) for _ in range(3))
    nums = p3.public_key().public_numbers()
    return [
        ("aws-ed25519", AwsKmsSigner("alias/x", client=FakeAwsKms(ed))),
        ("aws-p256", AwsKmsSigner("alias/y", client=FakeAwsKms(p1))),
        ("gcp-ed25519", GcpKmsSigner("projects/p/keyRings/r/cryptoKeys/k/cryptoKeyVersions/1",
                                     client=FakeGcpKms(ed25519.Ed25519PrivateKey.generate()))),
        ("gcp-p256", GcpKmsSigner("projects/p/.../2", client=FakeGcpKms(p2))),
        ("azure-p256", AzureKeyVaultSigner(FakeAzureCrypto(p3), nums.x.to_bytes(32, "big"),
                                           nums.y.to_bytes(32, "big"))),
        ("local-p256", EcdsaP256Signer()),
    ]


@pytest.mark.parametrize("name,signer", signers(), ids=[n for n, _ in signers()])
def test_kms_signed_chain_verifies(name, signer, tmp_path, clock):
    r = gleipnir.Recorder("a", "1", home=tmp_path, signer=signer, background=False, clock=clock, quiet=True,
                          fsync=False, segment_max_records=3)

    @r.tool(system="s")
    def f(i):
        return i

    for i in range(5):
        f(i)
    path = r.export(tmp_path / "b.zip")
    rep = verify_bundle(path, expect_key=signer.key_id)
    assert rep.valid(strict=True), [x.as_dict() for x in rep.findings]
    assert signer.key_id.startswith("k_ed25519_" if "ed25519" in name else "k_p256_")


def test_p256_tamper_fails(tmp_path, clock):
    import json
    import zipfile

    r = gleipnir.Recorder("a", "1", home=tmp_path, signer=EcdsaP256Signer(), background=False, clock=clock,
                          quiet=True, fsync=False)

    @r.tool(system="s")
    def f(i):
        return i

    f(1)
    path = r.export(tmp_path / "b.zip")
    with zipfile.ZipFile(path) as zf:
        files = {n: zf.read(n) for n in zf.namelist()}
    lines = files["records.jsonl"].decode().split("\n")
    rec = json.loads(lines[1])
    rec["args"]["i"] = 2
    lines[1] = json.dumps(rec)
    files["records.jsonl"] = "\n".join(lines).encode()
    bad = tmp_path / "bad.zip"
    with zipfile.ZipFile(bad, "w") as zf:
        for n, d in files.items():
            zf.writestr(n, d)
    assert "bad_signature" in {f.code for f in verify_bundle(bad).errors}


def test_unsupported_kms_key_rejected():
    from cryptography.hazmat.primitives.asymmetric import rsa

    with pytest.raises(ValueError):
        AwsKmsSigner("k", client=FakeAwsKms(rsa.generate_private_key(public_exponent=65537, key_size=2048)))
