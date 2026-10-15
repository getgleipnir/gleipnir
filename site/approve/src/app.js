// Gleipnir passkey approval page: a person approves one exact agent action with a passkey on their
// phone or laptop. The WebAuthn challenge is the action digest; the page shows the signed result to
// paste back to whoever asked (rec.approve(..., signature=...)). No backend: nothing is sent anywhere.
// Built into index.html by `npm run build:site` in typescript/.

import {
  actionDigest,
  approvalChallenge,
  b64uDecode,
  b64uEncode,
  checkSignature,
  encodeP256PublicKey,
  loadApprovers,
  parseJson,
  pyDumps,
} from "@getgleipnir/verify";

const $ = (id) => document.getElementById(id);
const els = {
  tool: $("tool"),
  system: $("system"),
  args: $("args"),
  digest: $("digest"),
  digestError: $("digest-error"),
  approverId: $("approver-id"),
  approverName: $("approver-name"),
  rpId: $("rp-id"),
  publicKey: $("public-key"),
  credentialId: $("credential-id"),
  register: $("register"),
  approve: $("approve"),
  status: $("status"),
  out: $("out"),
  outLabel: $("out-label"),
  copy: $("copy"),
  support: $("support"),
};

const STORE = "gleipnir-approver";
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
  els.out.closest(".result").hidden = false;
}

/** The digest to approve: computed from tool, system and arguments when they are given. */
function currentDigest() {
  const tool = els.tool.value.trim();
  const system = els.system.value.trim();
  const argsText = els.args.value.trim();
  let digest = els.digest.value.trim();
  els.digestError.hidden = true;
  if (tool && system && argsText) {
    let args;
    try {
      args = parseJson(argsText);
    } catch {
      return fail("The arguments are not valid JSON.");
    }
    if (!args || typeof args !== "object" || Array.isArray(args)) return fail("The arguments must be a JSON object.");
    const computed = actionDigest(tool, system, args);
    if (digest && digest !== computed) return fail("The digest does not match these arguments: do not approve, ask the requester.");
    digest = computed;
    els.digest.value = computed;
  }
  try {
    approvalChallenge(digest);
  } catch {
    return fail("Enter the action digest (sha256: and 64 hex characters), or the tool, system and arguments.");
  }
  return digest;
}

function fail(text) {
  els.digestError.textContent = text;
  els.digestError.hidden = false;
  return null;
}

async function register() {
  const id = els.approverId.value.trim();
  const rpId = els.rpId.value.trim() || location.hostname;
  if (!id) return say("Enter your approver id first (as the buyer's approvers file will list you).", "bad");
  try {
    const cred = await navigator.credentials.create({
      publicKey: {
        rp: { id: rpId, name: "Gleipnir approvals" },
        user: { id: new TextEncoder().encode(id), name: id, displayName: els.approverName.value.trim() || id },
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
    els.publicKey.value = publicKey;
    els.credentialId.value = credentialId;
    remember({ id, name: els.approverName.value.trim(), rpId, publicKey, credentialId });
    const entry = { id, name: els.approverName.value.trim() || id, webauthn: { public_key: publicKey, rp_id: rpId, credential_id: credentialId } };
    loadApprovers([entry]); // same validation as the verifier
    show("Send this entry to the buyer for their approvers file", pyDumps(entry));
    say("Passkey created. The buyer adds the entry below to their approvers file.", "ok");
  } catch (exc) {
    say(`No passkey was created: ${exc && exc.message ? exc.message : exc}`, "bad");
  }
}

async function approve() {
  const digest = currentDigest();
  if (!digest) return;
  const id = els.approverId.value.trim();
  const rpId = els.rpId.value.trim() || location.hostname;
  const publicKey = els.publicKey.value.trim();
  const credentialId = els.credentialId.value.trim();
  if (!id || !publicKey) return say("Enter your approver id and passkey public key (or create a passkey on this device first).", "bad");
  try {
    const opts = {
      challenge: approvalChallenge(digest),
      rpId,
      userVerification: "required",
      timeout: 120000,
    };
    if (credentialId) opts.allowCredentials = [{ type: "public-key", id: b64uDecode(credentialId) }];
    const cred = await navigator.credentials.get({ publicKey: opts });
    const r = cred.response;
    const signature = {
      type: "webauthn",
      approver_id: id,
      public_key: publicKey,
      rp_id: rpId,
      credential_id: b64uEncode(new Uint8Array(cred.rawId)),
      authenticator_data: b64uEncode(new Uint8Array(r.authenticatorData)),
      client_data_json: b64uEncode(new Uint8Array(r.clientDataJSON)),
      signature: b64uEncode(new Uint8Array(r.signature)),
    };
    // Check it exactly as a verifier will, before handing it over.
    const findings = checkSignature({ action_digest: digest, reviewer: id, signature }, null, [location.origin], false);
    const bad = findings.find((f) => f[0] === "error");
    if (bad) return say(`The passkey signature does not check out: ${bad[2]}`, "bad");
    remember({ ...(recall() || {}), id, rpId, publicKey, credentialId: signature.credential_id });
    show("Your approval: send this to whoever asked", pyDumps(signature));
    say(`Approved ${digest.slice(0, 19)}…. Nothing was sent: copy the approval below.`, "ok");
  } catch (exc) {
    say(`Not approved: ${exc && exc.message ? exc.message : exc}`, "bad");
  }
}

els.register.addEventListener("click", register);
els.approve.addEventListener("click", approve);
for (const input of [els.tool, els.system, els.args, els.digest]) input.addEventListener("change", currentDigest);
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
  els.approve.disabled = true;
  els.register.disabled = true;
}

// Prefill from the link (#digest=...&tool=...&system=...&args=...): fragments are never sent to a server.
try {
  const p = new URLSearchParams(location.hash.slice(1));
  for (const [k, input] of [["digest", els.digest], ["tool", els.tool], ["system", els.system], ["args", els.args], ["approver", els.approverId], ["rp-id", els.rpId]]) {
    if (p.get(k)) input.value = p.get(k);
  }
  const me = recall();
  if (me) {
    if (!els.approverId.value) els.approverId.value = me.id || "";
    els.approverName.value = me.name || "";
    if (!els.rpId.value) els.rpId.value = me.rpId || "";
    els.publicKey.value = me.publicKey || "";
    els.credentialId.value = me.credentialId || "";
  }
  if (!els.rpId.value) els.rpId.value = location.hostname;
  if (els.digest.value || els.args.value) currentDigest();
} catch {
  /* no prefill */
}
