/**
 * A strict, small XML reader for ISO 20022 messages (spec 6.2): elements, attributes, text, comments, the five
 * predefined entities and character references, namespaces. No DTD, no other entities, no CDATA, no processing
 * instructions except the XML declaration; callers screen for those first (and for characters XML does not allow).
 * Throws on anything malformed, including what expat rejects: `--` in comments, `]]>` in text, unbound or empty
 * prefixes, duplicate attributes after namespace expansion. Prefixed attributes are keyed `{namespace}local`.
 */

export interface XmlElement {
  ns: string;
  local: string;
  attrs: Record<string, string>;
  children: XmlElement[];
  text: string;
}

const NAME = /^[A-Za-z_][A-Za-z0-9._-]*(?::[A-Za-z_][A-Za-z0-9._-]*)?/;
const MAX_DEPTH = 64;

function decode(raw: string): string {
  if (/[\x00-\x08\x0B\x0C\x0E-\x1F]/.test(raw)) throw new Error("control character in XML");
  return raw.replace(/&(#x[0-9A-Fa-f]+|#[0-9]+|[a-z]+);|&/g, (m, ent: string | undefined) => {
    if (ent === undefined) throw new Error("bare & in XML text");
    if (ent.startsWith("#")) {
      const cp = ent.startsWith("#x") ? parseInt(ent.slice(2), 16) : parseInt(ent.slice(1), 10);
      const ok = cp === 0x9 || cp === 0xa || cp === 0xd || (cp >= 0x20 && cp <= 0xd7ff) || (cp >= 0xe000 && cp <= 0xfffd)
        || (cp >= 0x10000 && cp <= 0x10ffff);
      if (!ok) throw new Error("character reference to a character XML does not allow");
      return String.fromCodePoint(cp);
    }
    const named: Record<string, string> = { lt: "<", gt: ">", amp: "&", quot: '"', apos: "'" };
    if (!Object.prototype.hasOwnProperty.call(named, ent)) throw new Error(`unknown entity &${ent};`);
    return named[ent]!;
  });
}

function comment(text: string, i: number): number {
  const end = text.indexOf("-->", i + 4);
  if (end < 0) throw new Error("unterminated comment");
  const body = text.slice(i + 4, end);
  if (body.includes("--") || body.endsWith("-")) throw new Error("-- in a comment");
  return end + 3;
}

function chars(raw: string): string {
  if (raw.includes("]]>")) throw new Error("]]> in text");
  return decode(raw);
}

export function parseXml(text: string): XmlElement {
  let i = 0;
  if (text.startsWith("<?xml")) {
    const end = text.indexOf("?>");
    if (end < 0) throw new Error("unterminated XML declaration");
    i = end + 2;
  }
  const skipMisc = () => {
    for (;;) {
      while (i < text.length && " \t\r\n".includes(text[i]!)) i++;
      if (text.startsWith("<!--", i)) i = comment(text, i);
      else return;
    }
  };
  const element = (scope: Record<string, string>, depth: number): XmlElement => {
    if (depth > MAX_DEPTH) throw new Error("XML nested too deeply");
    if (text[i] !== "<") throw new Error("expected an element");
    i++;
    const nm = NAME.exec(text.slice(i, i + 200));
    if (!nm) throw new Error("bad element name");
    const qname = nm[0];
    i += qname.length;
    const raw: Record<string, string> = {};
    for (;;) {
      const ws = /^[ \t\r\n]*/.exec(text.slice(i, i + 1000))![0];
      i += ws.length;
      if (text[i] === "/" || text[i] === ">") break;
      if (!ws) throw new Error("expected whitespace before an attribute");
      const an = NAME.exec(text.slice(i, i + 200));
      if (!an) throw new Error("bad attribute name");
      i += an[0].length;
      const eq = /^[ \t\r\n]*=[ \t\r\n]*/.exec(text.slice(i, i + 100));
      if (!eq) throw new Error("expected = after attribute name");
      i += eq[0].length;
      const q = text[i];
      if (q !== '"' && q !== "'") throw new Error("attribute value must be quoted");
      const end = text.indexOf(q, i + 1);
      if (end < 0) throw new Error("unterminated attribute value");
      const value = text.slice(i + 1, end);
      if (value.includes("<")) throw new Error("< in attribute value");
      if (Object.prototype.hasOwnProperty.call(raw, an[0])) throw new Error(`duplicate attribute ${an[0]}`);
      raw[an[0]] = decode(value);
      i = end + 1;
    }
    const ns: Record<string, string> = { ...scope };
    const attrs: Record<string, string> = {};
    for (const [k, v] of Object.entries(raw)) {
      if (k === "xmlns") ns[""] = v;
      else if (k.startsWith("xmlns:")) {
        if (v === "") throw new Error(`empty namespace for prefix ${k.slice(6)}`);
        ns[k.slice(6)] = v;
      }
    }
    for (const [k, v] of Object.entries(raw)) {
      if (k === "xmlns" || k.startsWith("xmlns:")) continue;
      let key = k;
      if (k.includes(":")) {
        const [p, l] = k.split(":") as [string, string];
        if (!Object.prototype.hasOwnProperty.call(ns, p)) throw new Error(`unbound prefix ${p}`);
        key = `{${ns[p]!}}${l}`;
      }
      if (Object.prototype.hasOwnProperty.call(attrs, key)) throw new Error(`duplicate attribute ${key}`);
      attrs[key] = v;
    }
    const [prefix, local] = qname.includes(":") ? qname.split(":") as [string, string] : ["", qname];
    if (!Object.prototype.hasOwnProperty.call(ns, prefix) && prefix !== "") throw new Error(`unbound prefix ${prefix}`);
    const el: XmlElement = { ns: ns[prefix] ?? "", local, attrs, children: [], text: "" };
    if (text[i] === "/") {
      if (text[i + 1] !== ">") throw new Error("expected />");
      i += 2;
      return el;
    }
    i++; // >
    for (;;) {
      const lt = text.indexOf("<", i);
      if (lt < 0) throw new Error(`unclosed element ${qname}`);
      el.text += chars(text.slice(i, lt));
      i = lt;
      if (text.startsWith("<!--", i)) {
        i = comment(text, i);
      } else if (text.startsWith("</", i)) {
        const close = `</${qname}`;
        if (!text.startsWith(close, i)) throw new Error(`mismatched end tag for ${qname}`);
        i += close.length;
        const tail = /^[ \t\r\n]*>/.exec(text.slice(i, i + 100));
        if (!tail) throw new Error("bad end tag");
        i += tail[0].length;
        return el;
      } else {
        el.children.push(element(ns, depth + 1));
      }
    }
  };
  skipMisc();
  const root = element({ xml: "http://www.w3.org/XML/1998/namespace" }, 1);
  skipMisc();
  if (i !== text.length) throw new Error("content after the root element");
  return root;
}
