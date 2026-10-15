// Gleipnir browser verifier: runs @getgleipnir/verify on a dropped bundle.zip or proof.zip.
// Everything happens in this tab; the file is read with FileReader and never sent anywhere.
// Built into verify.js by `npm run build:site` in typescript/.

import { parseKnownHead, readBundle, verifyBundle } from "@getgleipnir/verify";

const $ = (id) => document.getElementById(id);
const els = {
  input: $("file"),
  drop: $("drop"),
  dropName: $("drop-name"),
  expectKey: $("expect-key"),
  knownHead: $("known-head"),
  knownHeadError: $("known-head-error"),
  rekor: $("req-rekor"),
  rfc3161: $("req-rfc3161"),
  result: $("result"),
  status: $("status"),
};

let current = null; // { name, bytes }

function el(tag, attrs = {}, ...children) {
  const n = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (v === undefined || v === null || v === false) continue;
    if (k === "class") n.className = v;
    else if (k === "text") n.textContent = v;
    else n.setAttribute(k, v === true ? "" : String(v));
  }
  for (const c of children) if (c !== null && c !== undefined) n.append(c);
  return n;
}

function options() {
  const opts = { expectKey: els.expectKey.value.trim() || null };
  const head = els.knownHead.value.trim();
  els.knownHeadError.hidden = true;
  els.knownHead.removeAttribute("aria-invalid");
  if (head) {
    const parsed = parseKnownHead(head);
    if (parsed === null) {
      els.knownHeadError.hidden = false;
      els.knownHead.setAttribute("aria-invalid", "true");
      return null;
    }
    opts.knownHead = parsed;
  }
  const req = [];
  if (els.rekor.checked) req.push("rekor");
  if (els.rfc3161.checked) req.push("rfc3161");
  if (req.length) opts.requireAnchor = req;
  return opts;
}

function load(file) {
  if (!file) return;
  els.dropName.textContent = file.name;
  const reader = new FileReader();
  reader.onload = () => {
    current = { name: file.name, bytes: new Uint8Array(reader.result) };
    run();
  };
  reader.onerror = () => showError(`Could not read ${file.name}. Choose the file again.`);
  reader.readAsArrayBuffer(file);
}

function showError(text) {
  els.result.replaceChildren(el("p", { class: "error", text }));
}

function run() {
  if (!current) return;
  const opts = options();
  if (opts === null) return;
  els.status.textContent = `Verifying ${current.name}`;
  els.result.setAttribute("aria-busy", "true");
  // Let the browser paint the busy state before the synchronous verification.
  setTimeout(() => {
    let report;
    try {
      report = verifyBundle(current.bytes, opts);
    } catch (exc) {
      els.result.removeAttribute("aria-busy");
      showError(String(exc && exc.message ? exc.message : exc));
      return;
    }
    let records = null;
    try {
      records = readBundle(current.bytes)[1];
    } catch {
      records = null;
    }
    render(report, records);
    els.result.removeAttribute("aria-busy");
    const valid = report.valid();
    els.status.textContent = `${current.name}: ${valid ? "valid" : "invalid"}, ${report.findings.length} finding${report.findings.length === 1 ? "" : "s"}`;
  }, 20);
}

const fmt = (x) => (x === null || x === undefined ? "none" : typeof x === "object" ? JSON.stringify(x) : String(x));

function code(text) {
  return el("code", { text: fmt(text) });
}

function render(report, records) {
  const valid = report.valid();
  const s = report.summary || {};
  const isProof = s.type === "proof";
  const errors = report.errors.length;
  const warnings = report.warnings.length;

  const verdict = el(
    "div",
    { class: `verdict ${valid ? "is-valid" : "is-invalid"}` },
    el("p", { class: "verdict-word", text: valid ? "Valid" : "Invalid" }),
    el("p", {
      class: "verdict-line",
      text: valid
        ? isProof
          ? "This action was signed by the chain's key and is included in a signed segment. Nothing in the proof was changed."
          : "No record was edited, removed, reordered or inserted after it was written, and every segment checks out."
        : `${errors} problem${errors === 1 ? "" : "s"} found. The records cannot be trusted as they are.`,
    }),
    warnings ? el("p", { class: "verdict-sub", text: `${warnings} warning${warnings === 1 ? "" : "s"}: valid, but read them below.` }) : null,
  );

  const parts = [verdict];
  const ribbon = records && Array.isArray(records) ? buildRibbon(report, records, isProof) : null;
  if (ribbon) parts.push(ribbon);
  if (Object.keys(s).length) parts.push(buildSummary(s, isProof));
  parts.push(buildFindings(report));
  if (!isProof && s.head && s.head.hash && valid) {
    parts.push(
      el(
        "p",
        { class: "hint" },
        "Keep the head. Next time, paste it into “Known head” to check that this history was not cut short or rewritten.",
      ),
    );
  }
  els.result.replaceChildren(...parts);
}

/** Segment ranges from the records, and the findings that fall inside each. */
function buildRibbon(report, records, isProof) {
  const segs = records.filter((r) => r && typeof r === "object" && r.kind === "segment" && r.segment && typeof r.segment === "object");
  if (!segs.length) return null;
  const bySeq = (lo, hi) => report.findings.filter((f) => typeof f.seq === "number" && f.seq >= lo && f.seq <= hi);
  const items = [];
  if (isProof) {
    const seg = segs[0];
    const n = Number(seg.segment.count) || 0;
    const action = records[1] && typeof records[1] === "object" ? records[1] : {};
    const pos = Number(action.seq) - Number(seg.segment.from);
    const bad = report.errors.length > 0;
    const cells = [];
    const shown = Math.min(n, 64);
    for (let i = 0; i < shown; i++) {
      const at = shown < n ? Math.floor((pos / n) * shown) === i : i === pos;
      cells.push(el("span", { class: `cell${at ? (bad ? " is-target is-fail" : " is-target") : ""}` }));
    }
    return el(
      "figure",
      { class: "ribbon" },
      el("div", { class: "ribbon-track proof", role: "img", "aria-label": `Record ${pos + 1} of ${n} in segment ${seg.seq}` }, ...cells),
      el("figcaption", { text: `Record ${pos + 1} of ${n} in segment ${fmt(seg.seq)} (seq ${fmt(seg.segment.from)}..${Number(seg.segment.from) + n - 1}).` }),
    );
  }
  let total = 0;
  for (const seg of segs) {
    const from = Number(seg.segment.from);
    const hi = Number(seg.seq);
    const fs = bySeq(from, hi);
    const state = fs.some((f) => f.level === "error") ? "fail" : fs.some((f) => f.level === "warn") ? "warn" : "ok";
    const count = Number(seg.segment.count) || 0;
    total += count + 1;
    items.push({ weight: count + 1, state, label: `segment ${seg.seq}: seq ${from}..${hi}, ${state === "ok" ? "no findings" : `${fs.length} finding${fs.length === 1 ? "" : "s"}`}` });
  }
  const last = Number(segs[segs.length - 1].seq);
  const tail = records.filter((r) => r && typeof r.seq === "number" && r.seq > last && r.kind !== "anchor").length;
  if (tail) {
    total += tail;
    items.push({ weight: tail, state: "tail", label: `${tail} record${tail === 1 ? "" : "s"} after the last segment, not yet sealed` });
  }
  const track = el("ol", { class: "ribbon-track", "aria-label": "Segments of the chain, in order" });
  for (const it of items) {
    const li = el("li", { class: `band is-${it.state}`, title: it.label, style: `flex-grow:${Math.max(it.weight, total / 120)}` }, el("span", { class: "sr-only", text: it.label }));
    track.append(li);
  }
  const fails = items.filter((i) => i.state === "fail").length;
  return el(
    "figure",
    { class: "ribbon" },
    track,
    el("figcaption", {
      text: `${segs.length} segment${segs.length === 1 ? "" : "s"}, sized by record count${fails ? `; ${fails} with errors` : ""}${tail ? "; hatched: records not yet sealed in a segment" : ""}.`,
    }),
  );
}

function row(term, ...value) {
  return [el("dt", { text: term }), el("dd", {}, ...value)];
}

function buildSummary(s, isProof) {
  const dl = el("dl", { class: "summary" });
  const keys = Array.isArray(s.keys) ? s.keys : [];
  dl.append(...row(keys.length > 1 ? "Signing keys" : "Signing key", ...keys.flatMap((k, i) => (i ? [el("br"), code(k)] : [code(k)]))));
  dl.append(...row("Chain", code(s.chain)));
  if (isProof) {
    dl.append(...row("Action", code(s.action), ` at seq ${fmt(s.action_seq)}`));
    dl.append(...row("Segment", `seq ${fmt(s.segment_seq)}`));
    const ind = Array.isArray(s.anchors_independent) ? s.anchors_independent : [];
    dl.append(...row("Independent anchors", ind.length ? ind.join(", ") : "none"));
  } else if (!("head" in s)) {
    // The verifier stops before segment and anchor checks when records themselves are broken.
    dl.append(...row("Records", `${fmt(s.records)} (seq ${fmt(s.first_seq)} to ${fmt(s.last_seq)})`));
    dl.append(...row("Segments and anchors", "not checked: fix the errors in the records first"));
  } else {
    dl.append(...row("Records", `${fmt(s.records)} (seq ${fmt(s.first_seq)} to ${fmt(s.last_seq)})${s.partial ? ", partial bundle" : ""}`));
    dl.append(...row("Segments", `${fmt(s.segments)}, ${fmt(s.segments_anchored)} anchored`));
    dl.append(...row("Independent anchors", `${fmt(s.anchors_independent)} segment${s.anchors_independent === 1 ? "" : "s"}`));
    dl.append(
      ...row(
        "Trusted time",
        s.segments_timestamped
          ? `${s.segments_timestamped} segment${s.segments_timestamped === 1 ? "" : "s"} timestamped (RFC 3161), up to ${fmt(s.trusted_time_until)}, at most ${fmt(s.max_timestamp_delay_s)} s after closing`
          : "none (times are the vendor's clock)",
      ),
    );
    if (s.covered_from !== undefined) {
      dl.append(...row("Covers", s.covered_until ? `${fmt(s.covered_from)} to ${fmt(s.covered_until)}` : `from ${fmt(s.covered_from)}, no closed segment yet`));
    }
    if (s.head && s.head.hash) {
      const value = `${s.head.seq}:${s.head.hash}`;
      const btn = el("button", { type: "button", class: "copy", text: "Copy" });
      btn.addEventListener("click", async () => {
        try {
          await navigator.clipboard.writeText(value);
          btn.textContent = "Copied";
        } catch {
          btn.textContent = "Select and copy";
        }
      });
      dl.append(...row("Head", code(value), " ", btn));
    }
  }
  return el("section", { "aria-labelledby": "summary-h" }, el("h2", { id: "summary-h", text: "Summary" }), dl);
}

const LEVEL = { error: "Error", warn: "Warning", info: "Note" };

function buildFindings(report) {
  const h = el("h2", { id: "findings-h", text: "Findings" });
  if (!report.findings.length) {
    return el("section", { "aria-labelledby": "findings-h" }, h, el("p", { class: "muted", text: "None." }));
  }
  const order = { error: 0, warn: 1, info: 2 };
  const sorted = [...report.findings].sort((a, b) => order[a.level] - order[b.level]);
  const list = el("ul", { class: "findings" });
  for (const f of sorted) {
    list.append(
      el(
        "li",
        { class: `finding is-${f.level}` },
        el("span", { class: "level", text: LEVEL[f.level] || f.level }),
        el("span", { class: "fcode" }, el("code", { text: f.code }), f.seq !== undefined ? ` at seq ${fmt(f.seq)}` : ""),
        el("span", { class: "fmsg", text: f.message }),
      ),
    );
  }
  return el("section", { "aria-labelledby": "findings-h" }, h, list);
}

// ---- wiring --------------------------------------------------------------------------------
els.input.addEventListener("change", () => load(els.input.files && els.input.files[0]));
for (const ev of ["dragenter", "dragover"]) {
  els.drop.addEventListener(ev, (e) => {
    e.preventDefault();
    els.drop.classList.add("is-over");
  });
}
for (const ev of ["dragleave", "drop"]) {
  els.drop.addEventListener(ev, () => els.drop.classList.remove("is-over"));
}
els.drop.addEventListener("drop", (e) => {
  e.preventDefault();
  const f = e.dataTransfer && e.dataTransfer.files && e.dataTransfer.files[0];
  if (f) load(f);
});
// Dropping a file anywhere else must not navigate away (which would open the zip).
window.addEventListener("dragover", (e) => e.preventDefault());
window.addEventListener("drop", (e) => {
  e.preventDefault();
  const f = e.dataTransfer && e.dataTransfer.files && e.dataTransfer.files[0];
  if (f) load(f);
});
for (const input of [els.expectKey, els.knownHead]) input.addEventListener("change", run);
for (const input of [els.rekor, els.rfc3161]) input.addEventListener("change", run);
document.getElementById("checks").addEventListener("submit", (e) => {
  e.preventDefault();
  run();
});

// Prefill checks from the URL fragment (#expect-key=...&require-anchor=rekor), never sent to a server.
try {
  const params = new URLSearchParams(location.hash.slice(1));
  if (params.get("expect-key")) els.expectKey.value = params.get("expect-key");
  if (params.get("known-head")) els.knownHead.value = params.get("known-head");
  for (const a of params.getAll("require-anchor")) {
    if (a === "rekor") els.rekor.checked = true;
    if (a === "rfc3161") els.rfc3161.checked = true;
  }
  if ([...params.keys()].length) document.getElementById("checks-details").open = true;
} catch {
  /* no prefill */
}
