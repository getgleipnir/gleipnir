/**
 * @getgleipnir/verify: offline verifier for Gleipnir agent action record bundles.
 *
 * Runs in Node and in browsers (no Node-only APIs in this entry point).
 */

export {
  FORMAT_VERSION,
  ERROR,
  WARN,
  INFO,
  Report,
  actionDigest,
  badBundleReport,
  defaultVerifiers,
  parseKnownHead,
  verifyBundle,
  verifyRecords,
  type AnchorType,
  type Finding,
  type Level,
  type Summary,
  type VerifyOptions,
} from "./verifier.js";
export {
  anchorResult,
  checkLocalLog,
  localLogEntryHash,
  verifyLocal,
  type AnchorContext,
  type AnchorOptions,
  type AnchorResult,
  type AnchorVerifier,
  type LocalAnchorLogSource,
} from "./anchors.js";
export {
  ANCHOR_DOMAIN,
  anchorMessage,
  embeddedTrustedRoot,
  parseCheckpoint,
  verifyRekor,
  verifyRekorReceipt,
} from "./rekor.js";
export {
  TIMESTAMP_DOMAIN,
  decodeTimestampResponse,
  timestampMessage,
  verifyRfc3161,
  verifyTimestampReceipt,
} from "./timestamp.js";
export {
  HASH_PREFIX,
  bytesToHash,
  canonicalize,
  canonicalizeString,
  hashToBytes,
  recordBody,
  recordHash,
  sha256Tagged,
} from "./canon.js";
export {
  P256_PREFIX,
  PUBKEY_PREFIX,
  RECORD_DOMAIN,
  SIG_PREFIX,
  decodePublicKey,
  ed25519PublicFromSeed,
  ed25519Sign,
  ed25519Verify,
  encodeP256PublicKey,
  encodeP256Signature,
  encodePublicKey,
  encodeSignature,
  keyId,
  p256Sign,
  p256Spki,
  p256SpkiFromScalar,
  p256Verify,
  recordMessage,
  verifySignature,
  type P256PublicKey,
  type RecordPublicKey,
} from "./crypto.js";
export { inclusionProof, leafHash, merkleRoot, nodeHash, verifyInclusion } from "./merkle.js";
export { parseJsonl, readBundle } from "./bundle.js";
export { decodeUtf8, encodeUtf8, parseJson, parseJsonBytes, pyDumps, type DumpOptions } from "./json.js";
export { b64decodeStrict, b64encode, b64uDecode, b64uEncode, bytesToHex, concatBytes, hexToBytes, utf8 } from "./bytes.js";
export { BigIntLiteral, PyError, PyFloat } from "./py.js";
export { isoMillis, parseTime, type Micros } from "./time.js";

export const VERSION = "0.1.0";
