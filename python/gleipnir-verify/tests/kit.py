"""Shared test accounts: the company's own (debtor) account and a holds() hook for it."""

from gleipnir_verify import mandate as M

DEBTOR_IBAN = "AT483200000012345864"
DEBTOR = M.iban(DEBTOR_IBAN)


def holds(company, account):
    """The bank's books: the company holds DEBTOR here, nothing else."""
    return account == DEBTOR
