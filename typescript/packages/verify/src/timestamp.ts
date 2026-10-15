/**
 * Offline verification of RFC 3161 timestamp receipts on segment hashes, in pure JavaScript.
 *
 * The token must be a valid TSA signature over SHA-256 of
 * `"gleipnir/timestamp/v1\n" || segment_hash`, chaining to a timestamp authority in the
 * Sigstore trusted root (embedded, or supplied with `trustedRoot`). The checks follow the
 * reference verifier (rfc3161-client with the TSA's pinned certificate chain):
 *
 * - `TimeStampResp` status is granted (0) and the token is CMS SignedData over a TSTInfo;
 * - exactly one SignerInfo; the signer certificate is found by issuer and serial number in the
 *   token (or is the pinned TSA certificate) and must be the pinned TSA certificate;
 * - signed attributes: message digest equals the hash of the TSTInfo, content type is TSTInfo;
 *   the signature over the signed attributes verifies with the TSA key (ECDSA, Ed25519, RSA);
 * - the TSA certificate chains to the authority's root, every certificate is valid at the
 *   token's genTime, and the TSA certificate has a critical EKU containing id-kp-timeStamping;
 * - the TSTInfo message imprint (SHA-256/384/512) equals the hash of the message.
 */

import { anchorResult, type AnchorOptions, type AnchorResult, type AnchorVerifier } from "./anchors.js";
import { b64decodeStrict, bytesEqual, concatBytes, utf8 } from "./bytes.js";
import { ed25519Verify } from "./crypto.js";
import {
  DerError,
  OID,
  Reader,
  TAG,
  ctx,
  parseOne,
  readInteger,
  readOid,
  readTime,
  type Tlv,
} from "./der.js";
import {
  HASHES,
  canSignCertificates,
  ecdsaVerifyDigest,
  extKeyUsage,
  hashFromOid,
  isCa,
  issuedBy,
  parseCertificate,
  parseSpki,
  rsaPkcs1Verify,
  type Certificate,
  type HashName,
} from "./pkix.js";
import { dget, errorText, pyIter, sub } from "./py.js";
import { loadTrustedRoot } from "./rekor.js";

export const TIMESTAMP_DOMAIN = "gleipnir/timestamp/v1\n";

export function timestampMessage(segmentHash: string): Uint8Array {
  return utf8(TIMESTAMP_DOMAIN + segmentHash);
}

class VerificationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "VerificationError";
  }
}

interface SignerInfo {
  issuer: Uint8Array;
  serial: bigint;
  digest: HashName;
  signedAttrs: Tlv | undefined;
  signatureAlgorithm: string;
  signature: Uint8Array;
}

export interface TimeStampToken {
  status: bigint;
  eContentType: string;
  tstInfoDer: Uint8Array;
  certificates: Uint8Array[];
  signerInfos: SignerInfo[];
  imprintAlgorithm: string;
  imprint: Uint8Array;
  genTime: bigint;
  genTimeText: string;
}

function algOid(t: Tlv): string {
  return readOid(new Reader(t, TAG.SEQUENCE).next());
}

function parseSignerInfo(t: Tlv): SignerInfo {
  const r = new Reader(t, TAG.SEQUENCE);
  const version = readInteger(r.next());
  if (version !== 1n) throw new DerError("only issuerAndSerialNumber signer identifiers are supported");
  const sid = new Reader(r.next(TAG.SEQUENCE));
  const issuer = sid.next(TAG.SEQUENCE).raw;
  const serial = readInteger(sid.next());
  sid.end();
  const digestOid = algOid(r.next(TAG.SEQUENCE));
  const digest = hashFromOid(digestOid);
  if (!digest) throw new DerError(`unsupported digest algorithm ${digestOid}`);
  const signedAttrs = r.optional(ctx(0, true));
  const signatureAlgorithm = algOid(r.next(TAG.SEQUENCE));
  const signature = r.next(TAG.OCTET_STRING).value;
  r.optional(ctx(1, true));
  r.end();
  return { issuer, serial, digest, signedAttrs, signatureAlgorithm, signature };
}

/** Decode a DER TimeStampResp. Throws DerError on malformed input. */
export function decodeTimestampResponse(der: Uint8Array): TimeStampToken {
  const resp = new Reader(parseOne(der), TAG.SEQUENCE);
  const statusInfo = new Reader(resp.next(TAG.SEQUENCE));
  const status = readInteger(statusInfo.next());
  const tokenTlv = resp.next(TAG.SEQUENCE);
  resp.end();
  const ci = new Reader(tokenTlv);
  if (readOid(ci.next()) !== OID.signedData) throw new DerError("token is not SignedData");
  const sd = new Reader(new Reader(ci.next(ctx(0, true))).next(TAG.SEQUENCE));
  ci.end();
  readInteger(sd.next());
  sd.next(TAG.SET); // digestAlgorithms
  const encap = new Reader(sd.next(TAG.SEQUENCE));
  const eContentType = readOid(encap.next());
  const eContent = new Reader(encap.next(ctx(0, true))).next(TAG.OCTET_STRING).value;
  encap.end();
  const certificates: Uint8Array[] = [];
  const certSet = sd.optional(ctx(0, true));
  if (certSet) {
    const cr = new Reader(certSet);
    while (!cr.done()) {
      const c = cr.next();
      if (c.tag === TAG.SEQUENCE) certificates.push(c.raw);
    }
  }
  sd.optional(ctx(1, true)); // crls
  const signerSet = new Reader(sd.next(TAG.SET));
  const signerInfos: SignerInfo[] = [];
  while (!signerSet.done()) signerInfos.push(parseSignerInfo(signerSet.next()));
  sd.end();

  const tst = new Reader(parseOne(eContent), TAG.SEQUENCE);
  readInteger(tst.next());
  readOid(tst.next()); // policy
  const mi = new Reader(tst.next(TAG.SEQUENCE));
  const imprintAlgorithm = algOid(mi.next(TAG.SEQUENCE));
  const imprint = mi.next(TAG.OCTET_STRING).value;
  mi.end();
  readInteger(tst.next()); // serialNumber
  const genTimeTlv = tst.next(TAG.GENERALIZED_TIME);
  const genTime = readTime(genTimeTlv);
  return {
    status,
    eContentType,
    tstInfoDer: eContent,
    certificates,
    signerInfos,
    imprintAlgorithm,
    imprint,
    genTime,
    genTimeText: new TextDecoder().decode(genTimeTlv.value),
  };
}

function signedAttributes(attrs: Tlv): Map<string, Tlv[]> {
  const out = new Map<string, Tlv[]>();
  const r = new Reader(attrs);
  while (!r.done()) {
    const a = new Reader(r.next(TAG.SEQUENCE));
    const oid = readOid(a.next());
    const values = new Reader(a.next(TAG.SET));
    const list: Tlv[] = [];
    while (!values.done()) list.push(values.next());
    a.end();
    if (out.has(oid)) throw new DerError("duplicate signed attribute");
    out.set(oid, list);
  }
  return out;
}

function verifySignerSignature(cert: Certificate, si: SignerInfo, content: Uint8Array, eContentType: string): void {
  let signedData: Uint8Array;
  if (si.signedAttrs) {
    const attrs = signedAttributes(si.signedAttrs);
    const md = attrs.get(OID.messageDigest);
    if (!md || md.length !== 1 || md[0]!.tag !== TAG.OCTET_STRING) throw new VerificationError("missing message digest");
    if (!bytesEqual(md[0]!.value, HASHES[si.digest](content))) throw new VerificationError("message digest mismatch");
    const ct = attrs.get(OID.contentType);
    if (!ct || ct.length !== 1 || readOid(ct[0]!) !== eContentType) throw new VerificationError("content type mismatch");
    // The signature covers the DER encoding of the attributes as a SET OF.
    signedData = concatBytes(Uint8Array.of(TAG.SET), si.signedAttrs.raw.subarray(1));
  } else {
    signedData = content;
  }
  const key = parseSpki(cert.spki);
  let ok = false;
  if (key.kind === "ec") ok = ecdsaVerifyDigest(key, HASHES[si.digest](signedData), si.signature);
  else if (key.kind === "rsa") ok = rsaPkcs1Verify(key, si.digest, HASHES[si.digest](signedData), si.signature);
  else if (key.kind === "ed25519") ok = ed25519Verify(si.signature, signedData, key.raw);
  if (!ok) throw new VerificationError("signature does not verify");
}

function checkValidAt(cert: Certificate, when: bigint): void {
  if (when < cert.notBefore || when > cert.notAfter) {
    throw new VerificationError("certificate is not valid at the timestamp's time");
  }
}

/** Verify `token` over `message` with a TSA whose chain is [tsa, ...intermediates, root]. Returns true or throws. */
export function verifyTimestampToken(token: TimeStampToken, message: Uint8Array, chain: Certificate[]): true {
  if (token.status !== 0n) throw new VerificationError("PKIStatus is not GRANTED");
  if (token.eContentType !== OID.tstInfo) throw new VerificationError("token does not contain a TSTInfo");
  if (token.signerInfos.length !== 1) throw new VerificationError("expected exactly one SignerInfo");
  const si = token.signerInfos[0]!;
  const tsa = chain[0]!;
  const root = chain[chain.length - 1]!;
  let leaf: Certificate | undefined;
  if (token.certificates.length > 0) {
    for (const raw of token.certificates) {
      const c = parseCertificate(raw);
      if (bytesEqual(c.issuer, si.issuer) && c.serial === si.serial) {
        leaf = c;
        break;
      }
    }
    if (!leaf) throw new VerificationError("No leaf certificate found matching the SignerInfo.");
    if (!bytesEqual(leaf.raw, tsa.raw)) {
      throw new VerificationError("Embedded certificate does not match the one in the Verification Options.");
    }
  } else {
    if (!bytesEqual(tsa.issuer, si.issuer) || tsa.serial !== si.serial) {
      throw new VerificationError("signer is not the TSA certificate");
    }
    leaf = tsa;
  }

  verifySignerSignature(leaf, si, token.tstInfoDer, token.eContentType);

  // certificate chain, valid at genTime
  for (let i = 0; i < chain.length; i++) {
    const c = chain[i]!;
    checkValidAt(c, token.genTime);
    const issuer = chain[i + 1] ?? root;
    if (i + 1 < chain.length && (!isCa(issuer) || !canSignCertificates(issuer))) {
      throw new VerificationError("issuer certificate is not a CA");
    }
    if (!issuedBy(c, issuer)) throw new VerificationError("certificate chain does not verify");
  }

  const eku = extKeyUsage(leaf);
  if (!eku) throw new VerificationError("The certificate does not contain the critical EKU extension.");
  if (!eku.critical) throw new VerificationError("The EKU extension is not critical.");
  if (!eku.oids.includes(OID.kpTimeStamping)) {
    throw new VerificationError("The EKU extension does not have KeyPurposeID id-kp-timeStamping.");
  }

  const hash = hashFromOid(token.imprintAlgorithm);
  if (!hash) throw new VerificationError(`Unsupported hash algorithm ${token.imprintAlgorithm}`);
  if (!bytesEqual(token.imprint, HASHES[hash](message))) throw new VerificationError("Mismatch between messages");
  return true;
}

/** Python `strftime("%Y-%m-%dT%H:%M:%S") + "Z"` of the token's genTime (fractions dropped). */
function genTimeIso(t: TimeStampToken): string {
  const s = t.genTimeText;
  return `${Number(s.slice(0, 4))}-${s.slice(4, 6)}-${s.slice(6, 8)}T${s.slice(8, 10)}:${s.slice(10, 12)}:${s.slice(12, 14)}Z`;
}

export function verifyTimestampReceipt(receipt: unknown, segmentHash: string, options: AnchorOptions): AnchorResult {
  let token: TimeStampToken;
  try {
    const raw = b64decodeStrict(sub(sub(receipt, "receipt"), "response"));
    token = decodeTimestampResponse(raw);
  } catch (exc) {
    return anchorResult(false, `malformed timestamp response: ${errorText(exc)}`);
  }
  const message = timestampMessage(segmentHash);
  const errors: string[] = [];
  let authorities: unknown[];
  try {
    authorities = pyIter(dget(loadTrustedRoot(options), "timestampAuthorities", []));
  } catch (exc) {
    return anchorResult(false, `timestamp does not verify against any trusted authority (${errorText(exc)})`);
  }
  for (const tsa of authorities) {
    try {
      const certs = pyIter(sub(sub(tsa, "certChain"), "certificates")).map((c) =>
        parseCertificate(b64decodeStrict(sub(c, "rawBytes"))),
      );
      if (certs.length === 0) throw new VerificationError("Verifier must have at least one root certificate set");
      if (verifyTimestampToken(token, message, certs)) {
        const when = genTimeIso(token);
        const uri = dget(tsa, "uri", "TSA");
        return anchorResult(true, `timestamped by ${typeof uri === "string" ? uri : String(uri)} at ${when}`, true, when);
      }
    } catch (exc) {
      errors.push(errorText(exc));
    }
  }
  return anchorResult(
    false,
    "timestamp does not verify against any trusted authority" + (errors.length ? ` (${errors[errors.length - 1]})` : ""),
  );
}

export const verifyRfc3161: AnchorVerifier = (anchor, { segmentHash, options }) =>
  verifyTimestampReceipt(anchor, segmentHash, options);
