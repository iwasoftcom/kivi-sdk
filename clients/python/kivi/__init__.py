"""kivi Python SDK — the untrusting client for the kivi event ledger.

    from kivi import KiviClient
    c = KiviClient("localhost:4741", token="...")
    r = c.append("property", {"subject": "dog", "attribute": "sound", "value": "bark"})
    a = c.table("dog", "sound")        # TracedAnswer(value, trace, scope)
    receipts = c.why(a.trace)          # the actual ledger records
    for rec in c.replay():             # client-side verified stream (default ON)
        ...

Async variant: `from kivi.aio import AsyncKiviClient`.
"""

from .client import (KiviClient, Receipt, TracedAnswer, ViewState, VerifyReport,
                     SimilarHit, SimilarAnswer, Session, ViewEntry, ViewPage,
                     KiviError, NotFound, Unauthenticated, PreconditionFailed,
                     InvalidArgument, Unavailable, ResourceExhausted, body_as)
from .verify import VerificationError, ChainChecker, ed25519_verify

__all__ = ["KiviClient", "Receipt", "TracedAnswer", "ViewState", "VerifyReport",
           "SimilarHit", "SimilarAnswer", "Session", "ViewEntry", "ViewPage",
           "KiviError", "NotFound", "Unauthenticated", "PreconditionFailed",
           "InvalidArgument", "Unavailable", "ResourceExhausted", "body_as",
           "VerificationError", "ChainChecker", "ed25519_verify"]
