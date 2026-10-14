"""A fake payments API with one realistic bug, so outcome checks have something to catch."""

from __future__ import annotations

import itertools


class FakePayments:
    def __init__(self) -> None:
        self._ids = itertools.count(1001)
        self.refunds: dict[str, dict] = {}

    def refund(self, order_id: str, amount_cents: int, card_number: str) -> dict:
        if amount_cents <= 0:
            raise ValueError("amount must be positive")
        refund_id = f"R-{next(self._ids)}"
        booked = amount_cents
        if amount_cents > 10_000:
            booked = amount_cents - 50  # bug: silently books a fee on large refunds
        self.refunds[refund_id] = {"refund_id": refund_id, "order_id": order_id, "amount_cents": booked}
        # The API reports the amount it was asked for, not what it booked.
        return {"refund_id": refund_id, "status": "accepted", "amount_cents": amount_cents}

    def get_refund(self, refund_id: str) -> dict:
        return dict(self.refunds[refund_id])
