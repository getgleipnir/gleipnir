// Gleipnir mandate signing page: a company signatory reviews what an AI agent may pay and signs the
// mandate with a passkey, as in a bank's app (spec/mandate.md 3a, 4.3). No backend: nothing is sent anywhere.
// Built into index.html by `npm run build:site` in typescript/.

import { b64uDecode, b64uEncode } from "../../../typescript/packages/verify/src/bytes.js";
import { decodePublicKey, encodeP256PublicKey } from "../../../typescript/packages/verify/src/crypto.js";
import { webauthnProblem } from "../../../typescript/packages/verify/src/approvals.js";
import { duplicateKey, mandateHash, mandateProblem, parseStrict, passkeyChallenge, passkeyDigest } from "../../../typescript/packages/verify/src/mandate.ts";

const $ = (id) => document.getElementById(id);
const els = {
  draft: $("draft"), draftError: $("draft-error"), summary: $("summary"), rows: $("scope-rows"), hash: $("hash"),
  signer: $("signer"), rpId: $("rp-id"), credentialId: $("credential-id"), sign: $("sign"), register: $("register"),
  status: $("status"), out: $("out"), outLabel: $("out-label"), copy: $("copy"), support: $("support"),
};

const STORE = "gleipnir-signer";
const remember = (v) => {
  try {
    localStorage.setItem(STORE, JSON.stringify(v));
  } catch {
    /* per-device convenience only */
  }
};
const recall = () => {
  try {
    return JSON.parse(localStorage.getItem(STORE) || "null");
  } catch {
    return null;
  }
};

function say(text, kind = "") {
  els.status.textContent = text;
  els.status.className = `status ${kind}`;
}

function show(label, value) {
  els.outLabel.textContent = label;
  els.out.value = value;
  els.out.parentElement.hidden = false;
  els.copy.textContent = "Copy";
}

/** The parsed draft, or null with the reason shown. Strict JSON: duplicate keys are refused. */
function currentMandate() {
  els.draftError.hidden = true;
  els.summary.hidden = true;
  const text = els.draft.value.trim();
  if (!text) return null;
  let m;
  try {
    JSON.parse(text); // syntax first, so the message says what is wrong
    const dup = duplicateKey(text);
    if (dup !== null) return fail(`Duplicate key "${dup}": different systems would read this mandate differently. Do not sign.`);
    m = parseStrict(text);
  } catch (exc) {
    return fail(`Not valid JSON: ${exc.message}`);
  }
  const problem = mandateProblem(m);
  if (problem) return fail(`Not a valid mandate: ${problem}. Do not sign; ask whoever sent it.`);
  render(m);
  return m;
}

function fail(text) {
  els.draftError.textContent = text;
  els.draftError.hidden = false;
  return null;
}

/** "23 Oct 2026, 18:16 UTC": the exact instant, in words a signatory reads correctly. */
function when(ts) {
  if (!ts) return "now";
  const d = new Date(ts);
  if (Number.isNaN(d.getTime())) return ts;
  const date = d.toLocaleDateString("en-GB", { day: "numeric", month: "short", year: "numeric", timeZone: "UTC" });
  const time = d.toLocaleTimeString("en-GB", { hour: "2-digit", minute: "2-digit", timeZone: "UTC" });
  return `${date}, ${time} UTC`;
}

/** An account as a signatory reads it: the scheme's own words, not JSON. */
function account(a) {
  const f = {
    iban: () => a.iban,
    us_aba: () => `US routing ${a.routing}, account ${a.account}`,
    uk_sort_code: () => `UK sort code ${a.sort_code}, account ${a.account}`,
    ca_eft: () => `Canada ${a.institution}-${a.transit}, account ${a.account}`,
    au_bsb: () => `BSB ${a.bsb}, account ${a.account}`,
    in_ifsc: () => `IFSC ${a.ifsc}, account ${a.account}`,
    mx_clabe: () => `CLABE ${a.clabe}`,
    swift: () => `SWIFT ${a.bic}, account ${a.account}`,
  }[a.scheme];
  return f ? f() : JSON.stringify(a);
}

function people(m) {
  return m.signer ? [m.signer] : m.signers.of;
}

function render(m) {
  const sc = m.scope;
  const rows = [
    ["Company", `${m.company.name} (${m.company.country})`],
    ["Agent", m.agent.public_key
      ? `${m.agent.name || m.agent.id}\nmust sign every payment with key ${m.agent.public_key.slice(0, 20)}…`
      : `${m.agent.name || m.agent.id}\nWARNING: no agent key, anyone holding this mandate can use it`],
    ["Signed by", m.signer ? m.signer.id : `${m.signers.threshold} of: ${m.signers.of.map((p) => p.id).join(", ")}`],
    ["Pays from", sc.from_accounts.map(account).join("\n")],
    ["Rails", sc.rails ? sc.rails.join(", ") : "any"],
    ["Per payment", `up to ${sc.max_per_payment} ${sc.currency}`],
    ["Per period", sc.max_per_period ? `up to ${sc.max_per_period.amount} ${sc.currency} per ${{ P1D: "day", P7D: "week", P1M: "month" }[sc.max_per_period.period]}` : "no period limit"],
    ["Payees", sc.payees ? sc.payees.map((p) => `${p.name || "?"}: ${account(p.account)}`).join("\n")
      : sc.unlisted_payees ? "none listed" : "ANY payee (no list)"],
    ...(sc.unlisted_payees ? [["Payees not on the list", sc.unlisted_payees === "escalate"
      ? `wait for a signatory's approval before they are paid${sc.max_per_unlisted_payee
        ? `; over ${sc.max_per_unlisted_payee} ${sc.currency} blocked` : ""}`
      : "blocked, unless a signatory approves the payee"]] : []),
    ["Purpose", sc.purpose || "-"],
    ["Valid", `${m.valid_from ? `from ${when(m.valid_from)}` : "from the moment it is signed"} until ${when(m.valid_until)}`],
  ];
  if (m.delegation) rows.push(["Your authority", m.delegation.map((d) => `${d.from.id} -> ${d.to.id}`).join("\n")]);
  if (m.status_url) rows.push(["Revocation status", `checked at ${m.status_url} on every payment`]);
  els.rows.replaceChildren(...rows.map(([k, v]) => {
    const tr = document.createElement("tr");
    const th = document.createElement("th");
    const td = document.createElement("td");
    th.textContent = k;
    td.textContent = v;
    td.style.whiteSpace = "pre-line";
    tr.append(th, td);
    return tr;
  }));
  els.hash.textContent = mandateHash(m);
  const prior = els.signer.value;
  els.signer.replaceChildren(...people(m).map((p) => new Option(`${p.id}${p.role ? ` (${p.role})` : ""}`, p.id)));
  if (prior) els.signer.value = prior;
  els.summary.hidden = false;
}

async function register() {
  const m = currentMandate();
  const id = els.signer.value || (m && people(m)[0].id);
  if (!id) return say("Paste the mandate first, so the passkey is created for the right person.", "bad");
  const rpId = els.rpId.value.trim() || location.hostname;
  try {
    const cred = await navigator.credentials.create({
      publicKey: {
        rp: { id: rpId, name: "Gleipnir mandates" },
        user: { id: new TextEncoder().encode(id), name: id, displayName: id },
        challenge: crypto.getRandomValues(new Uint8Array(32)),
        pubKeyCredParams: [{ type: "public-key", alg: -7 }], // ES256 only
        authenticatorSelection: { residentKey: "preferred", userVerification: "required" },
        attestation: "none",
      },
    });
    const spki = cred.response.getPublicKey && cred.response.getPublicKey();
    if (!spki) return say("This browser does not expose the new passkey's public key. Try a current browser.", "bad");
    const publicKey = encodeP256PublicKey(new Uint8Array(spki));
    const credentialId = b64uEncode(new Uint8Array(cred.rawId));
    els.credentialId.value = credentialId;
    remember({ id, rpId, publicKey, credentialId });
    show("Give this to your bank to enroll your passkey (and to whoever drafts your mandates)",
      JSON.stringify({ id, public_key: publicKey, rp_id: rpId, credential_id: credentialId }, null, 2));
    say("Passkey created. Your bank must enroll this public key for you before mandates you sign count.", "ok");
  } catch (exc) {
    say(`No passkey was created: ${exc && exc.message ? exc.message : exc}`, "bad");
  }
}

async function sign() {
  const m = currentMandate();
  if (!m) return say("Paste a valid mandate first.", "bad");
  const who = people(m).find((p) => p.id === els.signer.value);
  if (!who) return say("Choose who you sign as.", "bad");
  const rpId = els.rpId.value.trim() || location.hostname;
  const credentialId = els.credentialId.value.trim();
  try {
    const opts = { challenge: passkeyChallenge(m), rpId, userVerification: "required", timeout: 120000 };
    if (credentialId) opts.allowCredentials = [{ type: "public-key", id: b64uDecode(credentialId) }];
    const cred = await navigator.credentials.get({ publicKey: opts });
    const r = cred.response;
    const sig = {
      type: "webauthn",
      credential_id: b64uEncode(new Uint8Array(cred.rawId)),
      authenticator_data: b64uEncode(new Uint8Array(r.authenticatorData)),
      client_data_json: b64uEncode(new Uint8Array(r.clientDataJSON)),
      signature: b64uEncode(new Uint8Array(r.signature)),
    };
    // Check it exactly as the bank will, against the key the mandate names for you.
    const problem = webauthnProblem(sig, decodePublicKey(who.public_key), passkeyDigest(m), rpId, [location.origin], null);
    if (problem) {
      return say(`This passkey's signature would be refused: ${problem}. Is the mandate naming your enrolled passkey?`, "bad");
    }
    let signed;
    if (m.signer) signed = { ...m, sig };
    else signed = { ...m, sigs: [...(m.sigs || []).filter((s) => s.signer !== who.id), { signer: who.id, sig }] };
    remember({ ...(recall() || {}), id: who.id, rpId, credentialId: sig.credential_id });
    els.draft.value = JSON.stringify(signed, null, 2);
    const left = m.signers ? Math.max(0, m.signers.threshold - signed.sigs.length) : 0;
    show(left ? `Signed by you. ${left} more signature(s) needed: pass this on` : "Signed mandate: send it back", els.draft.value);
    say(`Signed ${mandateHash(m).slice(0, 19)}…. Nothing was sent: copy the mandate below.`, "ok");
  } catch (exc) {
    say(`Not signed: ${exc && exc.message ? exc.message : exc}`, "bad");
  }
}

els.register.addEventListener("click", register);
els.sign.addEventListener("click", sign);
els.draft.addEventListener("change", currentMandate);
els.draft.addEventListener("input", () => {
  els.draftError.hidden = true;
});
els.copy.addEventListener("click", async () => {
  try {
    await navigator.clipboard.writeText(els.out.value);
    els.copy.textContent = "Copied";
  } catch {
    els.out.select();
    els.copy.textContent = "Select and copy";
  }
});

if (!window.PublicKeyCredential || !window.isSecureContext) {
  els.support.hidden = false;
  els.sign.disabled = true;
  els.register.disabled = true;
}

// Prefill from the link (#mandate=<base64url JSON>&rp-id=...): fragments are never sent to a server.
try {
  const p = new URLSearchParams(location.hash.slice(1));
  if (p.get("mandate")) els.draft.value = new TextDecoder().decode(b64uDecode(p.get("mandate")));
  if (p.get("rp-id")) els.rpId.value = p.get("rp-id");
  const me = recall();
  if (me) {
    if (!els.rpId.value) els.rpId.value = me.rpId || "";
    els.credentialId.value = me.credentialId || "";
  }
  if (els.draft.value) currentMandate();
  if (me && me.id) els.signer.value = me.id;
} catch {
  /* a broken link just leaves the form empty */
}
