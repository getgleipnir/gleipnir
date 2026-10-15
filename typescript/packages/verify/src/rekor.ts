/**
 * Offline verification of Sigstore Rekor v2 anchor receipts.
 *
 * A receipt is the transparency log entry Rekor returned when the vendor published a segment
 * hash, plus the anchor public key. Verification needs no network:
 *
 * 1. The log entry body is a `hashedrekord` whose digest is SHA-256 of
 *    `"gleipnir/anchor/v1\n" || segment_hash` and whose signature verifies with the anchor
 *    key. So the entry is about this segment, made by the holder of the anchor key.
 * 2. The entry is included in the log: RFC 6962 inclusion proof against the proof's root.
 * 3. That root is in a checkpoint signed by the log's key, pinned in the embedded Sigstore
 *    trusted root (or one supplied with `trustedRoot`).
 */

import { sha256 } from "@noble/hashes/sha2.js";
import { anchorResult, type AnchorOptions, type AnchorResult, type AnchorVerifier } from "./anchors.js";
import { b64decodeStrict, bytesEqual, utf8 } from "./bytes.js";
import { ed25519Verify } from "./crypto.js";
import { DerError } from "./der.js";
import { parseJsonBytes } from "./json.js";
import { leafHash, verifyInclusion } from "./merkle.js";
import { UnsupportedAlgorithm, ecdsaVerifyDigest, parseSpki } from "./pkix.js";
import { PyError, caught, dget, errorText, pyEq, pyIntBig, pyIter, pyRepr, splitlines, sub } from "./py.js";
import { TRUSTED_ROOT } from "./data/trusted-root.js";

export const ANCHOR_DOMAIN = "gleipnir/anchor/v1\n";

export function anchorMessage(segmentHash: string): Uint8Array {
  return utf8(ANCHOR_DOMAIN + segmentHash);
}

/** The Sigstore trusted root embedded in this package. */
export function embeddedTrustedRoot(): unknown {
  return TRUSTED_ROOT;
}

export function loadTrustedRoot(options: AnchorOptions): unknown {
  return options.trustedRoot ?? TRUSTED_ROOT;
}

function findLog(trusted: unknown, logKeyId: Uint8Array): unknown {
  for (const tlog of pyIter(dget(trusted, "tlogs", []))) {
    if (bytesEqual(b64decodeStrict(sub(sub(tlog, "logId"), "keyId")), logKeyId)) return tlog;
  }
  return null;
}

/** Load a DER public key; a ValueError (as `cryptography` raises) when it is not a valid key. */
function loadKey(der: Uint8Array) {
  try {
    return parseSpki(der);
  } catch (exc) {
    if (exc instanceof DerError) throw new PyError("ValueError", `Could not deserialize key data: ${exc.message}`);
    if (exc instanceof UnsupportedAlgorithm) throw new PyError("UnsupportedAlgorithm", exc.message);
    throw exc;
  }
}

function verifyNoteSignature(publicDer: Uint8Array, keyDetails: unknown, data: Uint8Array, sig: Uint8Array): boolean {
  const key = loadKey(publicDer);
  if (typeof keyDetails !== "string") {
    throw new PyError("AttributeError", "'keyDetails' has no attribute 'startswith'");
  }
  if (keyDetails === "PKIX_ED25519" && key.kind === "ed25519") return ed25519Verify(sig, data, key.raw);
  if (keyDetails.startsWith("PKIX_ECDSA_P256") && key.kind === "ec") {
    return ecdsaVerifyDigest(key, sha256(data), sig);
  }
  return false;
}

export interface Checkpoint {
  origin: string;
  size: bigint;
  root: Uint8Array;
  note: string;
  signatures: Array<[string, Uint8Array]>;
}

/** Parse a checkpoint (signed note). Throws ValueError on malformed input. */
export function parseCheckpoint(envelope: unknown): Checkpoint {
  if (typeof envelope !== "string") throw new PyError("AttributeError", "checkpoint envelope is not a string");
  if (envelope.split("\n\n").length - 1 !== 1) throw new PyError("ValueError", "checkpoint must contain exactly one blank line");
  const split = envelope.indexOf("\n\n");
  const note = envelope.slice(0, split + 1);
  const sigBlock = envelope.slice(split + 2);
  const lines = note.replace(/\n+$/, "").split("\n");
  if (lines.length < 3) throw new PyError("ValueError", "checkpoint note too short");
  const origin = lines[0]!;
  const size = pyIntBig(lines[1]!);
  const root = b64decodeStrict(lines[2]!);
  const signatures: Array<[string, Uint8Array]> = [];
  for (const line of splitlines(sigBlock)) {
    if (!line.startsWith("\u2014 ")) continue;
    const parts = pySplitSpace(line, 2);
    if (parts.length !== 3) throw new PyError("ValueError", `not enough values to unpack (expected 3, got ${parts.length})`);
    signatures.push([parts[1]!, b64decodeStrict(parts[2]!)]);
  }
  return { origin, size, root, note, signatures };
}

/** Python `str.split(" ", maxsplit)`. */
function pySplitSpace(s: string, maxsplit: number): string[] {
  const out: string[] = [];
  let rest = s;
  while (out.length < maxsplit) {
    const i = rest.indexOf(" ");
    if (i < 0) break;
    out.push(rest.slice(0, i));
    rest = rest.slice(i + 1);
  }
  out.push(rest);
  return out;
}

/** Python `str.split("://", 1)[-1].rstrip("/")`. */
function originOf(baseUrl: unknown): string {
  if (typeof baseUrl !== "string") throw new PyError("AttributeError", "baseUrl is not a string");
  const i = baseUrl.indexOf("://");
  return (i >= 0 ? baseUrl.slice(i + 3) : baseUrl).replace(/\/+$/, "");
}

export function verifyRekorReceipt(receipt: unknown, segmentHash: string, options: AnchorOptions): AnchorResult {
  try {
    const r = sub(receipt, "receipt");
    const entry = sub(r, "entry");
    const proof = sub(entry, "inclusionProof");
    const anchorKeyDer = b64decodeStrict(sub(sub(r, "anchor_key"), "public"));

    // 1. body is a hashedrekord over this segment, signed by the anchor key
    const bodyBytes = b64decodeStrict(sub(entry, "canonicalizedBody"));
    const body = parseJsonBytes(bodyBytes);
    const spec = sub(sub(body, "spec"), "hashedRekordV002");
    const message = anchorMessage(segmentHash);
    if (!pyEq(dget(body, "kind"), "hashedrekord")) return anchorResult(false, "log entry is not a hashedrekord");
    const data = sub(spec, "data");
    if (!pyEq(dget(data, "algorithm"), "SHA2_256") || !bytesEqual(b64decodeStrict(sub(data, "digest")), sha256(message))) {
      return anchorResult(false, "log entry digest is not this segment");
    }
    const verifier = sub(sub(spec, "signature"), "verifier");
    if (!bytesEqual(b64decodeStrict(sub(sub(verifier, "publicKey"), "rawBytes")), anchorKeyDer)) {
      return anchorResult(false, "log entry was made with a different anchor key");
    }
    const key = loadKey(anchorKeyDer);
    if (key.kind !== "ec") return anchorResult(false, "unsupported anchor key type");
    const sigBytes = b64decodeStrict(sub(sub(spec, "signature"), "content"));
    if (!ecdsaVerifyDigest(key, sha256(message), sigBytes)) {
      return anchorResult(false, "anchor signature in the log entry does not verify");
    }

    // 2. inclusion proof
    const index = pyIntBig(sub(proof, "logIndex"));
    const size = pyIntBig(sub(proof, "treeSize"));
    const root = b64decodeStrict(sub(proof, "rootHash"));
    const path = pyIter(sub(proof, "hashes")).map((h) => b64decodeStrict(h));
    if (!verifyInclusion(index, size, leafHash(bodyBytes), path, root)) {
      return anchorResult(false, "inclusion proof does not verify");
    }

    // 3. checkpoint signed by a pinned log key
    const trusted = loadTrustedRoot(options);
    const logKeyId = b64decodeStrict(sub(sub(entry, "logId"), "keyId"));
    const tlog = findLog(trusted, logKeyId);
    if (tlog === null) {
      return anchorResult(
        false,
        "log is not in the trusted root (unknown or newer shard; pass a current Sigstore trusted root with --trusted-root)",
      );
    }
    const cp = parseCheckpoint(sub(sub(proof, "checkpoint"), "envelope"));
    const expectedOrigin = originOf(sub(tlog, "baseUrl"));
    if (cp.origin !== expectedOrigin) {
      return anchorResult(false, `checkpoint origin ${pyRepr(cp.origin)} does not match log ${pyRepr(expectedOrigin)}`);
    }
    if (cp.size !== size || !bytesEqual(cp.root, root)) {
      return anchorResult(false, "checkpoint does not match the inclusion proof");
    }
    const pub = sub(tlog, "publicKey");
    let ok = false;
    for (const [name, sig] of cp.signatures) {
      if (name === cp.origin && bytesEqual(sig.subarray(0, 4), logKeyId.subarray(0, 4))) {
        ok = verifyNoteSignature(b64decodeStrict(sub(pub, "rawBytes")), sub(pub, "keyDetails"), utf8(cp.note), sig.subarray(4));
        if (ok) break;
      }
    }
    if (!ok) return anchorResult(false, "checkpoint is not signed by the log key");
    return anchorResult(true, `included in ${cp.origin} at index ${index}`, true);
  } catch (exc) {
    if (caught(exc, "KeyError", "TypeError", "ValueError")) {
      return anchorResult(false, `malformed Rekor receipt: ${errorText(exc)}`);
    }
    throw exc;
  }
}

export const verifyRekor: AnchorVerifier = (anchor, { segmentHash, options }) =>
  verifyRekorReceipt(anchor, segmentHash, options);

