"""Fixtures for the third audit regressions (24.10.2026): deterministic keys, a fixed clock."""
from __future__ import annotations

from datetime import datetime, timezone

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from gleipnir_verify import mandate as M

NOW = datetime(2026, 10, 23, 9, 14, 2, tzinfo=timezone.utc)
CO = {"name": "Nordhafen Logistik GmbH", "country": "AT"}
DEBTOR = M.iban("AT483200000012345864")
BRENNER = {"name": "Brenner Stahl AG", "account": M.iban("AT611904300234573201")}
UNTIL = "2026-12-31T23:59:59.000Z"


def seed(n: int) -> bytes:
    return bytes([n]) * 32


class K:
    def __init__(self, n: int) -> None:
        self.seed = seed(n)
        self.sk = Ed25519PrivateKey.from_private_bytes(self.seed)
        self.pk = M.public_key_of(self.sk)


NAMES = ("ceo", "cfo", "a", "b", "c", "agent", "bank", "officer", "evil")
KEYS = {n: K(i + 1) for i, n in enumerate(NAMES)}
P = {n: {"id": f"{n}@nordhafen.at", "public_key": KEYS[n].pk} for n in NAMES}


def kyb_default() -> dict:
    return {P["ceo"]["id"]: M.AuthorityResult("bank_kyb", (KEYS["ceo"].pk,)),
            P["cfo"]["id"]: M.AuthorityResult("bank_kyb", (KEYS["cfo"].pk,), may_sign=False),
            P["a"]["id"]: M.AuthorityResult("bank_kyb", (KEYS["a"].pk,)),
            P["b"]["id"]: M.AuthorityResult("bank_kyb", (KEYS["b"].pk,)),
            P["c"]["id"]: M.AuthorityResult("bank_kyb", (KEYS["c"].pk,))}


def holds(company, account):
    return "cust:n" if account == DEBTOR else None


def bank(kyb: dict, by_name_only: bool = True, **kw) -> M.Checker:
    def authority(c, pid):
        if by_name_only and c.get("name") != CO["name"]:
            return None
        return kyb.get(pid)
    return M.Checker(id="bank:t", sk=KEYS["bank"].sk, authority=kw.pop("authority", authority),
                     ledger=kw.pop("ledger", M.InMemoryLedger()), clock=kw.pop("clock", lambda: NOW),
                     holds=kw.pop("holds", holds), **kw)


def scope(**kw):
    s = {"rails": ["sepa"], "currency": "EUR", "max_per_payment": "1000.00",
         "max_per_period": {"amount": "5000.00", "period": "P1M"}, "payees": [BRENNER],
         "from_accounts": [DEBTOR], **kw}
    return {k: v for k, v in s.items() if v is not None}


def mandate(signer="a", mid="m_1", company=CO, **kw):
    m = M.issue(id=mid, company=company, agent={"id": "agent", "public_key": KEYS["agent"].pk},
                signer=P[signer], scope=kw.pop("scope", None) or scope(), valid_until=UNTIL,
                issued_at="2026-10-01T00:00:00.000Z", **kw)
    return M.sign_mandate(m, KEYS[signer].sk)


def multi(names, threshold, signed=None, mid="m_multi", **kw):
    m = M.issue(id=mid, company=kw.pop("company", CO), agent={"id": "agent", "public_key": KEYS["agent"].pk},
                signers={"threshold": threshold, "of": [P[n] for n in names]},
                scope=kw.pop("scope", None) or scope(), valid_until=UNTIL,
                issued_at="2026-10-01T00:00:00.000Z", **kw)
    for n in (signed or names):
        m = M.cosign(m, KEYS[n].sk, P[n]["id"])
    return m


def pay(m, pid, amount="100.00", **kw):
    return M.attach(m, id=pid, rail=kw.pop("rail", "sepa"), amount=amount, currency="EUR",
                    payee=kw.pop("payee", BRENNER), agent_sk=KEYS["agent"].sk, requested_at=M.fmt_ts(NOW), **kw)


def override(decision, signers, outcome="allow", oid="o_1", decided_at=None):
    o = M.make_override(decision, outcome=outcome, id=oid, decided_at=decided_at or M.fmt_ts(NOW))
    for n in signers:
        o = M.sign_override(o, KEYS[n].sk, P[n])
    return o


def brief(d):
    return d["outcome"], d["reasons"], d["checks"]
