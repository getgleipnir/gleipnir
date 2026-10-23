"""Shared test accounts: the company's own (debtor) account and a holds() hook for it."""

from gleipnir_verify import mandate as M

DEBTOR_IBAN = "AT483200000012345864"
DEBTOR = M.iban(DEBTOR_IBAN)


CUSTOMER = "cust:nordhafen"


def holds(company, account):
    """The bank's books: its customer Nordhafen holds DEBTOR here, nothing else."""
    return CUSTOMER if account == DEBTOR else None
