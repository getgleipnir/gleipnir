/**
 * Signed approvals: an approval bound to the approver's own key, made outside the agent.
 * Port of python/gleipnir-verify/src/gleipnir_verify/approvals.py, with the same checks and messages.
 *
 * An approval review may carry `review.signature` over `"gleipnir/approval/v1\n" + action_digest`:
 * - `{type: "key", approver_id, public_key, sig}`: Ed25519 or ECDSA P-256 in the record key format;
 * - `{type: "webauthn", approver_id, public_key, rp_id, credential_id, authenticator_data,
 *   client_data_json, signature}`: a passkey assertion (ES256) whose challenge is the 32 raw bytes of
 *   the action digest, checked as WebAuthn Level 3 section 7.2 describes.
 *
 * Who may approve is the buyer's decision: the buyer gives the verifier a registry ({@link loadApprovers}).
 */

import { sha256 } from "@noble/hashes/sha2.js";
import { b64uDecode, b64uEncode, bytesEqual, concatBytes, hexToBytes, utf8 } from "./bytes.js";
import { P256_PREFIX, decodePublicKey, keyId, verifySignature, type RecordPublicKey } from "./crypto.js";
import { decodeUtf8, parseJson } from "./json.js";
import { PyError, dget, hasKey, isDict, isWellFormed, pyEq, pyRepr, type JsonDict } from "./py.js";

export const APPROVAL_DOMAIN = "gleipnir/approval/v1\n";
export const SIGNATURE_TYPES = ["key", "webauthn"] as const;
const DIGEST = /^sha256:[0-9a-f]{64}$/;
const B64U = /^[A-Za-z0-9_-]*$/;

// authenticatorData flags (WebAuthn L3 section 6.1)
const UP = 0x01;
const UV = 0x04;
const BE = 0x08;
const BS = 0x10;
const AT = 0x40;
const ED = 0x80;

type Level = "error" | "warn" | "info";

/** The exact bytes an approver signs for an approval of the action with this digest. */
export function approvalMessage(actionDigest: string): Uint8Array {
  return utf8(APPROVAL_DOMAIN + actionDigest);
}

/** The WebAuthn challenge for an approval: the 32 raw bytes of the action digest. */
export function approvalChallenge(actionDigest: string): Uint8Array {
  if (typeof actionDigest !== "string" || !DIGEST.test(actionDigest)) {
    throw new PyError("ValueError", "action digest must be sha256: followed by 64 lowercase hex characters");
  }
  return hexToBytes(actionDigest.slice("sha256:".length));
}

/** One entry of the buyer's approver registry. */
export interface Approver {
  id: string;
  name: string;
  type: "key" | "webauthn";
  public: RecordPublicKey;
  publicKey: string;
  rpId: string | null;
  credentialId: string | null;
  roles: string[];
}

export type ApproverRegistry = Map<string, Approver>;

function isText(value: unknown): value is string {
  return typeof value === "string" && value.length > 0 && isWellFormed(value);
}

function isB64u(value: unknown): value is string {
  return typeof value === "string" && B64U.test(value) && value.length % 4 !== 1;
}

function tryDecode(text: unknown): RecordPublicKey | null {
  try {
    return decodePublicKey(text);
  } catch {
    return null;
  }
}

const isP256 = (k: RecordPublicKey | null): boolean => k !== null && !(k instanceof Uint8Array);

/** Parse an approver registry (a parsed JSON list). Throws PyError("ValueError") with a message for the person. */
export function loadApprovers(data: unknown): ApproverRegistry {
  const bad = (msg: string) => new PyError("ValueError", msg);
  if (!Array.isArray(data)) throw bad("the approvers file must be a JSON list");
  const out: ApproverRegistry = new Map();
  data.forEach((entry, i) => {
    if (!isDict(entry)) throw bad(`approver #${i} must be a JSON object`);
    const aid = dget(entry, "id");
    if (typeof aid !== "string" || !aid) throw bad(`approver #${i} needs a non-empty string id`);
    const r = pyRepr(aid);
    if (out.has(aid)) throw bad(`approver id ${r} appears twice`);
    const name = dget(entry, "name");
    if (typeof name !== "string") throw bad(`approver ${r} needs a string name`);
    const roles = dget(entry, "roles", []);
    if (!Array.isArray(roles) || !roles.every((x) => typeof x === "string")) throw bad(`approver ${r}: roles must be a list of strings`);
    if (hasKey(entry, "public_key") === hasKey(entry, "webauthn")) throw bad(`approver ${r} needs exactly one of public_key or webauthn`);
    if (hasKey(entry, "public_key")) {
      const pub = tryDecode(entry["public_key"]);
      if (pub === null) throw bad(`approver ${r}: cannot read public_key`);
      out.set(aid, { id: aid, name, type: "key", public: pub, publicKey: entry["public_key"] as string, rpId: null, credentialId: null, roles: [...roles] });
      return;
    }
    const wa = entry["webauthn"];
    if (!isDict(wa)) throw bad(`approver ${r}: webauthn must be a JSON object`);
    const pub = tryDecode(dget(wa, "public_key"));
    if (!isP256(pub)) throw bad(`approver ${r}: webauthn.public_key must be an ECDSA P-256 key`);
    const rpId = dget(wa, "rp_id");
    if (!isText(rpId)) throw bad(`approver ${r}: webauthn.rp_id must be a non-empty string`);
    const cred = dget(wa, "credential_id");
    if (cred !== null && (!isB64u(cred) || !cred)) throw bad(`approver ${r}: webauthn.credential_id must be base64url`);
    out.set(aid, {
      id: aid,
      name,
      type: "webauthn",
      public: pub!,
      publicKey: wa["public_key"] as string,
      rpId,
      credentialId: (cred as string | null) ?? null,
      roles: [...roles],
    });
  });
  return out;
}

export type SignatureFinding = [Level, string, string];

/**
 * Findings (level, code, message) for the signature of one approval review body. Unsigned approvals
 * are errors when the buyer gave a registry or requires signed approvals; a valid signature by a key
 * nobody vouched for (no registry) is a warning, or an error when required.
 */
export function checkSignature(
  body: JsonDict,
  approvers: ApproverRegistry | null,
  origins: readonly string[] | null,
  require: boolean,
): SignatureFinding[] {
  const strict: Level = require ? "error" : "warn";
  if (!hasKey(body, "signature")) {
    return [[require || approvers !== null ? "error" : "warn", "approval_unsigned", "the approval is not signed by the approver, so who approved is only the vendor's word"]];
  }
  const sig = body["signature"];
  if (!isDict(sig)) return [["error", "approval_bad_signature", "the approval signature is not a JSON object"]];
  const typ = dget(sig, "type");
  if (typeof typ !== "string" || !(SIGNATURE_TYPES as readonly string[]).includes(typ)) {
    return [["error", "approval_bad_signature", "the approval signature has an unknown type"]];
  }
  const aid = dget(sig, "approver_id");
  if (typeof aid !== "string" || !aid) return [["error", "approval_bad_signature", "the approval signature names no approver_id"]];
  const r = pyRepr(aid);
  if (hasKey(body, "reviewer") && !pyEq(body["reviewer"], aid)) {
    return [["error", "approval_bad_signature", `the approval names reviewer ${pyRepr(body["reviewer"])} but is signed by ${r}`]];
  }
  const bad = typ === "key" ? "approval_bad_signature" : "approval_webauthn_invalid";
  let pub = tryDecode(dget(sig, "public_key"));
  if (pub === null) return [["error", bad, `cannot read the public key of approver ${r}`]];
  if (typ === "webauthn" && !isP256(pub)) return [["error", bad, `the passkey of approver ${r} is not an ECDSA P-256 key`]];
  let entry: Approver | null = null;
  if (approvers !== null) {
    entry = approvers.get(aid) ?? null;
    if (entry === null) return [["error", "approval_unknown_approver", `approver ${r} is not in the approver registry`]];
    if (entry.type !== typ) return [["error", "approval_unknown_approver", `approver ${r} is registered for ${entry.type} signatures, not ${typ}`]];
    if (keyId(entry.public) !== keyId(pub)) {
      return [["error", "approval_unknown_approver", `approver ${r} signed with a key that is not the one in the approver registry`]];
    }
    pub = entry.public;
  }
  const digest = dget(body, "action_digest");
  if (typeof digest !== "string" || !DIGEST.test(digest)) {
    return [["error", bad, "the approved action digest is malformed, so no signature can cover it"]];
  }
  if (typ === "key") {
    if (!verifySignature(pub, approvalMessage(digest), dget(sig, "sig"))) {
      return [["error", bad, `the signature of approver ${r} does not match the approved action`]];
    }
  } else {
    const rpId = entry !== null ? entry.rpId : dget(sig, "rp_id");
    if (!isText(rpId)) return [["error", bad, "WebAuthn assertion invalid: no valid rp_id"]];
    const allowed = origins && origins.length ? [...origins] : [`https://${rpId}`];
    const detail = webauthnProblem(sig, pub, digest, rpId, allowed, entry !== null ? entry.credentialId : null);
    if (detail !== null) return [["error", bad, `WebAuthn assertion invalid: ${detail}`]];
  }
  if (entry !== null) return [["info", "approval_verified", `approved by ${entry.name} (${aid}), signature verified`]];
  return [
    [strict, "approval_unknown_approver", `the signature by ${r} is valid, but no approver registry was given, so nothing shows whose key it is (pass --approvers)`],
  ];
}

/** Why a WebAuthn assertion does not approve this digest, or null when it does. */
export function webauthnProblem(
  sig: JsonDict,
  pub: RecordPublicKey,
  digest: string,
  rpId: string,
  origins: readonly string[],
  credentialId: string | null,
): string | null {
  const fields = [dget(sig, "authenticator_data"), dget(sig, "client_data_json"), dget(sig, "signature")];
  if (!fields.every(isB64u)) return "authenticator_data, client_data_json and signature must be base64url strings";
  const [auth, cdj] = (fields as string[]).map(b64uDecode) as [Uint8Array, Uint8Array];
  if (auth.length < 37) return "authenticator data is too short";
  let cd: unknown = null;
  try {
    cd = parseJson(decodeUtf8(cdj));
  } catch {
    cd = null;
  }
  if (!isDict(cd)) return "client data is not a JSON object";
  if (!pyEq(dget(cd, "type"), "webauthn.get")) return "client data type is not webauthn.get";
  if (!pyEq(dget(cd, "challenge"), b64uEncode(approvalChallenge(digest)))) return "the challenge is not the approved action digest";
  const origin = dget(cd, "origin");
  if (typeof origin !== "string") return "client data has no origin";
  if (!origins.includes(origin)) return `origin ${pyRepr(origin)} is not allowed`;
  if (dget(cd, "crossOrigin") === true || hasKey(cd, "topOrigin")) return "the assertion was made in a cross-origin frame";
  if (!bytesEqual(auth.subarray(0, 32), sha256(utf8(rpId)))) return "rpIdHash does not match the relying party id";
  const flags = auth[32]!;
  if (!(flags & UP)) return "user presence (UP) flag not set";
  if (!(flags & UV)) return "user verification (UV) flag not set";
  if (flags & AT) return "attested credential data (AT) flag set in an assertion";
  if (flags & BS && !(flags & BE)) return "backup state (BS) set without backup eligibility (BE)";
  if (auth.length > 37 !== Boolean(flags & ED)) return "authenticator data length does not match its flags";
  if (credentialId !== null && !pyEq(dget(sig, "credential_id"), credentialId)) return "the credential id is not the registered one";
  if (!verifySignature(pub, concatBytes(auth, sha256(cdj)), P256_PREFIX + (fields[2] as string))) return "the signature does not verify";
  return null;
}
