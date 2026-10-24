"""ISO 20022 for mandates (spec 6.2): the pain.001 credit transfer a checked payment becomes, and the check that a
pain.001 the bank is about to execute is the payment the checker allowed.

    xml = pain001(mandate, payment, decision)              # Document, pain.001.001.09, one transaction
    problems = pain001_problems(xml, mandate, payment, decision)   # [] if it matches

The transaction carries the mandate, payment and decision hashes in its SupplementaryData envelope, so the
reference travels inside the bank's own payment message. A bank that executes pain.001 files checks each
transaction against the payment it was allowed as: same end-to-end id (the payment id), amount, currency,
debtor account, creditor account, and the Gleipnir envelope.

Everything else in the message must be exactly what ``pain001`` writes for this payment (one payment
information block with one transaction, the same payment method, type and control sums, no other elements);
only names, remittance text, message and block ids and dates may differ. A file with a second transaction, or
an intermediary agent or a cheque payment method added, is ``unexpected_content``.

XML is parsed strictly: no DTD, entities, CDATA or processing instructions (other than the XML declaration),
every element in the pain.001 namespace (the envelope in the Gleipnir namespace), at most 1 MiB.
"""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET  # noqa: S405 - input is pre-screened: no DTD, entities, CDATA or PIs
from typing import Any

from . import mandate as M

NS = "urn:iso:std:iso:20022:tech:xsd:pain.001.001.09"
GNS = f"urn:gleipnir:payment:{M.V}"
MAX_XML = 1 << 20
MAX_XML_DEPTH = 64
# Clearing system of each domestic scheme (ISO 20022 ExternalClearingSystemIdentification1Code).
CLEARING = {"us_aba": ("USABA", "routing"), "uk_sort_code": ("GBDSC", "sort_code"), "ca_eft": ("CACPA", None),
            "au_bsb": ("AUBSB", "bsb"), "in_ifsc": ("INFSC", "ifsc")}


def _esc(text: str) -> str:
    return (text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")
            .replace("'", "&apos;"))


def _el(name: str, *children: str, text: str | None = None, attrs: str = "") -> str:
    inner = _esc(text) if text is not None else "".join(children)
    return f"<{name}{attrs}>{inner}</{name}>"


def _member(acc: dict) -> str | None:
    """The clearing system member id of a domestic account, or None."""
    if acc["scheme"] not in CLEARING:
        return None
    field = CLEARING[acc["scheme"]][1]
    return "0" + acc["institution"] + acc["transit"] if field is None else acc[field]


def _account(acc: dict) -> str:
    if acc["scheme"] == "iban":
        return _el("Id", _el("IBAN", text=acc["iban"]))
    if acc["scheme"] == "mx_clabe":
        return _el("Id", _el("Othr", _el("Id", text=acc["clabe"]), _el("SchmeNm", _el("Prtry", text="CLABE"))))
    return _el("Id", _el("Othr", _el("Id", text=acc["account"])))


def _agent(acc: dict) -> str:
    if acc["scheme"] == "swift":
        return _el("FinInstnId", _el("BICFI", text=acc["bic"]))
    member = _member(acc)
    if member is not None:
        code = CLEARING[acc["scheme"]][0]
        return _el("FinInstnId", _el("ClrSysMmbId", _el("ClrSysId", _el("Cd", text=code)), _el("MmbId", text=member)))
    return _el("FinInstnId", _el("Othr", _el("Id", text="NOTPROVIDED")))


def _payment_type(rail: str) -> str:
    if rail == "sepa":
        return _el("PmtTpInf", _el("SvcLvl", _el("Cd", text="SEPA")))
    if rail == "sepa_instant":
        return _el("PmtTpInf", _el("SvcLvl", _el("Cd", text="SEPA")), _el("LclInstrm", _el("Cd", text="INST")))
    return _el("PmtTpInf", _el("LclInstrm", _el("Prtry", text=rail)))


def _envelope(mandate: dict, payment: dict, decision: dict | None) -> str:
    parts = [_el("Mandate", text=M.mandate_hash(mandate)), _el("Payment", text=M.obj_hash(payment, "agent_sig"))]
    if decision is not None:
        parts.append(_el("Decision", text=M.obj_hash(decision)))
    return _el("SplmtryData", _el("PlcAndNm", text="Gleipnir"),
               _el("Envlp", _el("Gleipnir", *parts, attrs=f' xmlns="{GNS}"')))


def pain001(mandate: dict, payment: dict, decision: dict | None = None) -> str:
    """The pain.001.001.09 Document for one checked payment. Raises ValueError for a malformed payment."""
    problem = M.mandate_problem(mandate) or M.payment_problem(payment)
    if problem:
        raise ValueError(problem)
    p, co = payment, mandate["company"]["name"]
    tx = [_el("PmtId", _el("EndToEndId", text=p["id"])),
          _el("Amt", _el("InstdAmt", text=p["amount"], attrs=f' Ccy="{p["currency"]}"')),
          _el("CdtrAgt", _agent(p["payee"]["account"])),
          _el("Cdtr", _el("Nm", text=p["payee"].get("name") or "NOTPROVIDED")),
          _el("CdtrAcct", _account(p["payee"]["account"]))]
    if p.get("reference"):
        tx.append(_el("RmtInf", _el("Ustrd", text=p["reference"])))
    tx.append(_envelope(mandate, payment, decision))
    pmt = _el("PmtInf", _el("PmtInfId", text=p["id"]), _el("PmtMtd", text="TRF"), _el("NbOfTxs", text="1"),
              _el("CtrlSum", text=p["amount"]), _payment_type(p["rail"]),
              _el("ReqdExctnDt", _el("Dt", text=p["requested_at"][:10])), _el("Dbtr", _el("Nm", text=co)),
              _el("DbtrAcct", _account(p["from_account"])), _el("DbtrAgt", _agent(p["from_account"])),
              _el("CdtTrfTxInf", *tx))
    hdr = _el("GrpHdr", _el("MsgId", text=p["id"]), _el("CreDtTm", text=p["requested_at"]),
              _el("NbOfTxs", text="1"), _el("CtrlSum", text=p["amount"]), _el("InitgPty", _el("Nm", text=co)))
    return '<?xml version="1.0" encoding="UTF-8"?>' + _el("Document", _el("CstmrCdtTrfInitn", hdr, pmt),
                                                          attrs=f' xmlns="{NS}"')


# ---------- reading ----------

class _Bad(Exception):
    pass


# Characters XML 1.0 allows, minus U+FEFF (a byte order mark has no place in a decoded string).
_BAD_CHAR = re.compile("[^\t\n\r\x20-\ud7ff\ue000-\ufefe\uff00-\ufffd\U00010000-\U0010ffff]")
_DECL = re.compile(r"""<\?xml[ \t\r\n]+version[ \t\r\n]*=[ \t\r\n]*(["'])1\.0\1"""
                   r"""(?:[ \t\r\n]+encoding[ \t\r\n]*=[ \t\r\n]*(["'])(?:UTF|utf)-8\2)?"""
                   r"""(?:[ \t\r\n]+standalone[ \t\r\n]*=[ \t\r\n]*(["'])(?:yes|no)\3)?[ \t\r\n]*\?>""")
_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9._-]*")
_WS = " \t\r\n"  # XML whitespace, the only characters trimmed from values


def _screen(xml: str) -> None:
    """The same strict subset in every implementation, before any parser sees the text."""
    if not isinstance(xml, str) or _BAD_CHAR.search(xml) or len(xml.encode("utf-8")) > MAX_XML:
        raise _Bad("xml_malformed")
    upper = xml.upper()
    if "<!DOCTYPE" in upper or "<!ENTITY" in upper or "<![CDATA[" in upper:
        raise _Bad("xml_malformed")
    for match in re.finditer(r"<\?", xml):
        if match.start() != 0 or not _DECL.match(xml):
            raise _Bad("xml_malformed")


def _names_ok(root: ET.Element) -> None:
    """Element and attribute names are ASCII XML names, as every implementation reads them."""
    for el in root.iter():
        names = [el.tag, *el.attrib]
        if any(not _NAME.fullmatch(n.rsplit("}", 1)[-1]) for n in names):
            raise _Bad("xml_malformed")


def _local(tag: str, ns: str) -> str:
    if not tag.startswith("{" + ns + "}"):
        raise _Bad("xml_malformed")
    return tag[len(ns) + 2:]


def _check_ns(el: ET.Element, ns: str) -> None:
    """Every element in the pain.001 namespace, except the Gleipnir envelope's content."""
    for child in el:
        name = _local(child.tag, ns)
        if name == "Envlp":
            for g in child:
                _local(g.tag, GNS)
                for x in g.iter():
                    _local(x.tag, GNS)
        else:
            _check_ns(child, ns)


def _find(el: ET.Element | None, path: str, ns: str) -> ET.Element | None:
    for part in path.split("/"):
        if el is None:
            return None
        hits = [c for c in el if c.tag == "{" + ns + "}" + part]
        if len(hits) != 1:
            return None
        el = hits[0]
    return el


def _text(el: ET.Element | None, path: str, ns: str = NS) -> str | None:
    found = _find(el, path, ns)
    if found is None or len(found):
        return None
    return (found.text or "").strip(_WS)


def _read_account(acct: ET.Element | None, agent: ET.Element | None, like: dict) -> dict | None:
    """The account an Acct and Agt element pair describe, read the way the expected scheme is written."""
    scheme = like["scheme"]
    if scheme == "iban":
        v = _text(acct, "Id/IBAN")
        return {"scheme": "iban", "iban": v} if v is not None else None
    if scheme == "mx_clabe":
        if _text(acct, "Id/Othr/SchmeNm/Prtry") != "CLABE":
            return None
        v = _text(acct, "Id/Othr/Id")
        return {"scheme": "mx_clabe", "clabe": v} if v is not None else None
    number = _text(acct, "Id/Othr/Id")
    if number is None:
        return None
    if scheme == "swift":
        bic = _text(agent, "FinInstnId/BICFI")
        return {"scheme": "swift", "bic": bic, "account": number} if bic is not None else None
    code, field = CLEARING[scheme]
    if _text(agent, "FinInstnId/ClrSysMmbId/ClrSysId/Cd") != code:
        return None
    member = _text(agent, "FinInstnId/ClrSysMmbId/MmbId")
    if member is None:
        return None
    if field is None:  # Canada: 0 + institution (3) + transit (5)
        if len(member) != 9 or not member.startswith("0"):
            return None
        return {"scheme": "ca_eft", "institution": member[1:4], "transit": member[4:], "account": number}
    return {"scheme": scheme, field: member, "account": number}


def pain001_problems(xml: Any, mandate: dict, payment: dict, decision: dict | None = None) -> list[str]:
    """Why this pain.001 is not exactly the payment the checker decided on, or [] if it is (spec 6.2).

    Finds the one transaction whose EndToEndId is the payment id, and compares what moves money: amount,
    currency, debtor and creditor accounts, and the Gleipnir envelope (mandate, payment and, if given, decision
    hash). Names, remittance text and dates are not compared.
    """
    if M.mandate_problem(mandate) or M.payment_problem(payment):
        return ["payment_malformed"]
    try:
        _screen(xml)
        try:
            root = ET.fromstring(xml)  # noqa: S314 - screened above
        except ET.ParseError as e:
            raise _Bad("xml_malformed") from e
        _names_ok(root)
        stack = [(root, 1)]
        while stack:  # the same depth limit as every other implementation
            el, depth = stack.pop()
            if depth > MAX_XML_DEPTH:
                raise _Bad("xml_malformed")
            stack.extend((c, depth + 1) for c in el)
        if root.tag != f"{{{NS}}}Document":
            raise _Bad("xml_not_pain001")
        _check_ns(root, NS)
        initn = _find(root, "CstmrCdtTrfInitn", NS)
        if initn is None:
            raise _Bad("xml_not_pain001")
        doc = root
        hits = [(pmt, tx) for pmt in initn if pmt.tag == f"{{{NS}}}PmtInf"
                for tx in pmt if tx.tag == f"{{{NS}}}CdtTrfTxInf" and _text(tx, "PmtId/EndToEndId") == payment["id"]]
    except _Bad as b:
        return [str(b)]
    except RecursionError:
        return ["xml_malformed"]
    if not hits:
        return ["end_to_end_id_not_found"]
    if len(hits) > 1:
        return ["end_to_end_id_not_unique"]
    pmt, tx = hits[0]
    problems = []
    amt = _find(tx, "Amt/InstdAmt", NS)
    if amt is None or len(amt) or (amt.text or "").strip(_WS) != payment["amount"]:
        problems.append("amount_mismatch")
    if amt is None or amt.get("Ccy") != payment["currency"]:
        problems.append("currency_mismatch")
    debtor = _read_account(_find(pmt, "DbtrAcct", NS), _find(pmt, "DbtrAgt", NS), payment["from_account"])
    if debtor != payment["from_account"]:
        problems.append("debtor_account_mismatch")
    payee = payment["payee"]["account"]
    if _read_account(_find(tx, "CdtrAcct", NS), _find(tx, "CdtrAgt", NS), payee) != payee:
        problems.append("creditor_account_mismatch")
    env = _find(tx, "SplmtryData/Envlp", NS)
    g = [c for c in env if c.tag == f"{{{GNS}}}Gleipnir"] if env is not None else []
    gl = g[0] if len(g) == 1 else None
    if _text(gl, "Mandate", GNS) != M.mandate_hash(mandate):
        problems.append("mandate_reference_mismatch")
    if _text(gl, "Payment", GNS) != M.obj_hash(payment, "agent_sig"):
        problems.append("payment_reference_mismatch")
    if decision is not None and _text(gl, "Decision", GNS) != M.obj_hash(decision):
        problems.append("decision_reference_mismatch")
    expected = ET.fromstring(pain001(mandate, payment, decision))  # noqa: S314 - our own output
    if not _same_shape(_node(doc), _node(expected), (), decision is None):
        problems.append("unexpected_content")
    return problems


# Leaves whose text may differ from what pain001 writes (names, remittance text, ids, dates), and leaves whose
# text the checks above already compare, so a changed amount or account is reported as itself.
_FREE = {"MsgId", "CreDtTm", "PmtInfId", "Dt", "Nm", "Ustrd"}
_COMPARED = {"InstdAmt", "IBAN", "BICFI", "MmbId", "Mandate", "Payment", "Decision"}


def _node(el: ET.Element) -> dict:
    """An element as (namespace, name, attributes, text, children), the same in every implementation."""
    ns, _, local = el.tag[1:].partition("}")
    text = (el.text or "") + "".join(c.tail or "" for c in el)
    return {"ns": ns, "local": local, "attrs": dict(el.attrib), "text": text, "children": [_node(c) for c in el]}


def _same_shape(a: dict, e: dict, path: tuple[str, ...], no_decision: bool) -> bool:
    """``a`` is ``e`` except for free leaves, leaves compared elsewhere, remittance text and a decision hash."""
    if a["ns"] != e["ns"] or a["local"] != e["local"]:
        return False
    name = a["local"]
    if name == "InstdAmt":
        if set(a["attrs"]) != set(e["attrs"]):
            return False
    elif a["attrs"] != e["attrs"]:
        return False
    if not e["children"]:
        if a["children"]:
            return False
        in_account = "DbtrAcct" in path or "CdtrAcct" in path
        return name in _FREE or name in _COMPARED or (name == "Id" and in_account) \
            or a["text"].strip(_WS) == e["text"].strip(_WS)
    if a["text"].strip(_WS):
        return False
    ac, ec = a["children"], e["children"]
    if name == "CdtTrfTxInf":  # remittance information is optional and free, but only as unstructured text
        rmt = [c for c in ac if c["local"] == "RmtInf"]
        if len(rmt) > 1 or any(len(r["children"]) != 1 or r["children"][0]["local"] != "Ustrd" or r["attrs"]
                               or r["text"].strip(_WS) for r in rmt):
            return False
        ac = [c for c in ac if c["local"] != "RmtInf"]
        ec = [c for c in ec if c["local"] != "RmtInf"]
    if name == "Gleipnir" and no_decision:  # a decision hash the caller did not ask about
        ac = [c for c in ac if c["local"] != "Decision"]
    if len(ac) != len(ec):
        return False
    return all(_same_shape(x, y, (*path, name), no_decision) for x, y in zip(ac, ec, strict=True))
