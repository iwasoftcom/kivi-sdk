"""kivi Python SDK — synchronous client (PLAN3 G3.1, K2+K3).

The SDK constitution, enforced here and tested by the conformance suite:
  - an answer without a trace is UNREPRESENTABLE (TracedAnswer refuses);
  - client-side verification is ON by default (the untrusting client):
    replay recomputes every record's hash, checks chain linkage and gapless
    numbering, and verifies Ed25519 seals — a lying server or wire is caught;
  - honest refusals map to native exceptions (NotFound is never a None);
  - the wrapper is thin: behaviour lives in the proto and the server.

Runtime dependency: grpcio only. Numbers travel as JSON strings end to end,
so int64 values round-trip exactly (see conformance S2).
"""

import dataclasses
import json
import typing
from dataclasses import dataclass, field
from typing import Any, Iterator, Optional, Type, TypeVar

import grpc

from . import kivi_pb2 as pb
from . import kivi_pb2_grpc as rpcstub
from .verify import ChainChecker, RecordIntegrityChecker, VerificationError  # re-exported

__all__ = ["KiviClient", "Receipt", "TracedAnswer", "ViewState", "VerifyReport",
           "SimilarHit", "SimilarAnswer", "Session", "ViewEntry", "ViewPage",
           "KiviError", "NotFound", "Unauthenticated", "PreconditionFailed",
           "InvalidArgument", "Unavailable", "ResourceExhausted", "VerificationError"]


class KiviError(Exception):
    pass


class NotFound(KiviError):
    pass


class Unauthenticated(KiviError):
    pass


class PreconditionFailed(KiviError):
    pass


class InvalidArgument(KiviError):
    pass


class Unavailable(KiviError):
    pass


class ResourceExhausted(KiviError):
    pass


_CODES = {
    grpc.StatusCode.NOT_FOUND: NotFound,
    grpc.StatusCode.UNAUTHENTICATED: Unauthenticated,
    grpc.StatusCode.FAILED_PRECONDITION: PreconditionFailed,
    grpc.StatusCode.INVALID_ARGUMENT: InvalidArgument,
    grpc.StatusCode.UNAVAILABLE: Unavailable,
    grpc.StatusCode.RESOURCE_EXHAUSTED: ResourceExhausted,
}


def wrap_rpc_error(e: grpc.RpcError) -> KiviError:
    return _CODES.get(e.code(), KiviError)(e.details())


def dumps(v: Any) -> str:
    # a dataclass event is the "entity in" write: convert to a plain dict
    # (recursively, nested dataclasses included) before serializing.
    if dataclasses.is_dataclass(v) and not isinstance(v, type):
        v = dataclasses.asdict(v)
    return json.dumps(v, ensure_ascii=False, separators=(",", ":"))


T = TypeVar("T")


def _from_dict(cls: Type[T], data: Any) -> Any:
    """Build a (possibly nested) dataclass instance from a decoded dict — the
    'entity out' read. Handles nested dataclasses and List[...] of them; any
    other type passes through untouched."""
    if data is None:
        return None
    if not (dataclasses.is_dataclass(cls) and isinstance(cls, type)):
        return data
    hints = typing.get_type_hints(cls)
    kwargs = {}
    for f in dataclasses.fields(cls):
        if f.name not in data:
            continue
        kwargs[f.name] = _coerce(hints.get(f.name, f.type), data[f.name])
    return cls(**kwargs)


def _coerce(ftype: Any, value: Any) -> Any:
    if dataclasses.is_dataclass(ftype) and isinstance(ftype, type):
        return _from_dict(ftype, value)
    origin = typing.get_origin(ftype)
    if origin in (list, tuple) and value is not None:
        args = typing.get_args(ftype)
        elem = args[0] if args else Any
        return [_coerce(elem, x) for x in value]
    return value


def body_as(cls: Type[T], record: dict) -> T:
    """Decode an already-fetched record's BODY into a typed dataclass — the
    'entity out' for records from replay/subscribe/why/get_record."""
    return _from_dict(cls, record.get("body"))


@dataclass(frozen=True)
class Receipt:
    no: int
    offset: int
    hash: str


@dataclass(frozen=True)
class TracedAnswer:
    """value + the events that established it + the ledger scope it was derived
    from. Constructing one without a trace raises — by design."""
    value: Any
    trace: tuple
    scope: int

    def __post_init__(self):
        if not self.trace:
            raise ValueError("an answer without a trace is unrepresentable")


@dataclass(frozen=True)
class ViewState:
    state: Any
    scope: int
    hash: str


@dataclass(frozen=True)
class VerifyReport:
    ok: bool
    records: int
    seals: int
    unsealed_tail: int
    torn_tail: bool
    defect_no: int = 0
    defect_reason: str = ""
    has_defect: bool = field(default=False)


@dataclass(frozen=True)
class SimilarHit:
    """One traced similarity result: the record's address, its score, and the
    receipt itself — an untraced score does not exist."""
    no: int
    score: float
    record: Any


@dataclass(frozen=True)
class SimilarAnswer:
    hits: tuple
    scope: int   # history covered by the index at answer time
    model: str   # which ruler measured the similarity


@dataclass(frozen=True)
class Session:
    """The result of a login: the bearer token plus its honest envelope."""
    token: str
    role: str
    expires_unix: int


@dataclass(frozen=True)
class ViewEntry:
    """One row of a paged view read: canonical key + decoded value (trace inside)."""
    key: str
    value: Any


@dataclass(frozen=True)
class ViewPage:
    """One page of a keyset walk over a compiled view. next_key == "" means
    done. scope/hash stamp the SNAPSHOT: pass scope back as as_of and every
    later page keeps describing that same moment."""
    entries: tuple
    next_key: str
    scope: int
    hash: str


class KiviClient:
    """Synchronous kivi client. `verify=True` (default) turns on client-side
    stream verification; pass verify=False only when you consciously trust the
    server and the wire."""

    def __init__(self, addr: str, token: Optional[str] = None,
                 verify: bool = True, channel: Optional[grpc.Channel] = None):
        self._channel = channel or grpc.insecure_channel(addr)
        self._stub = rpcstub.KiviStub(self._channel)
        self._md = (("authorization", f"Bearer {token}"),) if token else ()
        self.verify_streams = verify
        self._owns_channel = channel is None

    def close(self):
        # a with_bearer view never closes the shared channel
        if self._owns_channel:
            self._channel.close()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()

    def _call(self, fn, req):
        try:
            return fn(req, metadata=self._md)
        except grpc.RpcError as e:
            raise wrap_rpc_error(e) from None

    # -- identity plane --------------------------------------------------------

    def login(self, username: str, password: str) -> Session:
        """Authenticate as a kivi USER and install the session token on this
        client: from here on every call runs with that user's role and every
        write is receipted under their name. Security stays in ONE center —
        the server's identity plane; the client only carries the credential."""
        r = self._call(self._stub.Login,
                       pb.LoginRequest(username=username, password=password))
        self.set_token(r.token)
        return Session(r.token, r.role, r.expires_unix)

    def set_token(self, token: Optional[str]):
        """Swap the bearer credential (after login or on rotation)."""
        self._md = (("authorization", f"Bearer {token}"),) if token else ()

    def with_bearer(self, token: str) -> "KiviClient":
        """A shallow view of this client that calls with ANOTHER identity —
        the same channel, a different credential per view. This is what makes
        stateless multi-tenant frontends possible (one connection, many
        callers); the server decides everything, per call."""
        c = KiviClient.__new__(KiviClient)
        c._channel = self._channel
        c._stub = self._stub
        c._md = (("authorization", f"Bearer {token}"),) if token else ()
        c.verify_streams = self.verify_streams
        c._owns_channel = False  # closing the view must not cut the shared wire
        return c

    # -- write plane ---------------------------------------------------------

    def append(self, event_type: str, body: Any) -> Receipt:
        r = self._call(self._stub.Append,
                       pb.AppendRequest(type=event_type, body_json=dumps(body)))
        return Receipt(r.no, r.offset, r.hash)

    def append_private(self, event_type: str, body: Any) -> Receipt:
        r = self._call(self._stub.AppendPrivate,
                       pb.AppendRequest(type=event_type, body_json=dumps(body)))
        return Receipt(r.no, r.offset, r.hash)

    def erase(self, no: int, reason: str) -> Receipt:
        r = self._call(self._stub.Erase, pb.EraseRequest(no=no, reason=reason))
        return Receipt(r.no, r.offset, r.hash)

    def seal(self) -> Receipt:
        r = self._call(self._stub.Seal, pb.Empty())
        return Receipt(r.no, r.offset, r.hash)

    def rotate(self) -> dict:
        r = self._call(self._stub.Rotate, pb.Empty())
        return {"period": r.period, "archive": r.archive,
                "archive_sha256": r.archive_sha256, "first_no": r.first_no}

    # -- read plane ----------------------------------------------------------

    def verify_ledger(self) -> VerifyReport:
        r = self._call(self._stub.Verify, pb.Empty())
        return VerifyReport(r.ok, r.records, r.seals, r.unsealed_tail,
                            r.torn_tail, r.defect_no, r.defect_reason, r.has_defect)

    def head(self) -> tuple:
        """The cheap orientation call: (head_no, head_hash) — no audit runs.
        Page a tail with this; use verify_ledger when integrity is the question."""
        r = self._call(self._stub.Head, pb.Empty())
        return (r.head_no, r.head_hash)

    def table(self, subject: str, attribute: str,
              as_of: Optional[int] = None) -> TracedAnswer:
        """Traced read; as_of=N answers "what did we know when the ledger
        stopped at record N" — time travel is free by design."""
        req = pb.TableRequest(subject=subject, attribute=attribute)
        if as_of is not None:
            req.as_of = as_of
        r = self._call(self._stub.QueryTable, req)
        return TracedAnswer(json.loads(r.value_json), tuple(r.trace), r.scope)

    def subject(self, subject: str, as_of: Optional[int] = None) -> TracedAnswer:
        """table()'s whole-row sibling (G15): every attribute known about one
        subject, plus the union of every event that established one of them —
        "what do we know about X?" without knowing which attributes to ask
        for first. Same traced contract as table()."""
        req = pb.SubjectRequest(subject=subject)
        if as_of is not None:
            req.as_of = as_of
        r = self._call(self._stub.QuerySubject, req)
        return TracedAnswer(json.loads(r.value_json), tuple(r.trace), r.scope)

    def view_page(self, view: str, after_key: str = "", limit: int = 0,
                  as_of: Optional[int] = None) -> ViewPage:
        """Keyset pagination over a compiled view (table|graph|series).
        Pin a consistent walk by passing page 1's scope as as_of."""
        req = pb.ViewPageRequest(view=view, after_key=after_key, limit=limit)
        if as_of is not None:
            req.as_of = as_of
        r = self._call(self._stub.QueryViewPage, req)
        entries = tuple(ViewEntry(e.key, json.loads(e.value_json)) for e in r.entries)
        return ViewPage(entries, r.next_key, r.scope, r.hash)

    def similar(self, query: str, k: int = 5) -> SimilarAnswer:
        """Traced semantic search: every hit is a record number + score + the
        receipt itself; the answer names the model and the covered scope."""
        r = self._call(self._stub.Similar, pb.SimilarRequest(query=query, k=k))
        hits = tuple(SimilarHit(h.no, h.score,
                                json.loads(h.record_json) if h.record_json else None)
                     for h in r.hits)
        return SimilarAnswer(hits, r.scope, r.model)

    def graph(self) -> ViewState:
        r = self._call(self._stub.QueryGraph, pb.Empty())
        return ViewState(json.loads(r.state_json), r.scope, r.hash)

    def series(self, series: str = "") -> ViewState:
        r = self._call(self._stub.QuerySeries, pb.SeriesRequest(series=series))
        return ViewState(json.loads(r.state_json), r.scope, r.hash)

    def why(self, trace) -> list:
        r = self._call(self._stub.Why, pb.WhyRequest(trace=list(trace)))
        return [json.loads(x.record_json) for x in r.records]

    def get_record(self, no: int, unseal: bool = False) -> dict:
        r = self._call(self._stub.GetRecord, pb.GetRecordRequest(no=no, unseal=unseal))
        return json.loads(r.record_json)

    def get_record_as(self, cls: Type[T], no: int, unseal: bool = False) -> T:
        """Fetch record `no` and decode its body into a typed dataclass `cls`."""
        return body_as(cls, self.get_record(no, unseal))

    def audit(self, view: str = "table") -> dict:
        r = self._call(self._stub.Audit, pb.AuditRequest(view=view))
        return {"view": r.view, "clean": r.clean, "expected": r.expected,
                "found": r.found, "receipt_no": r.receipt_no}

    def replay(self, start: int = 0, follow: bool = False,
               verify: Optional[bool] = None,
               check_seals: bool = True) -> Iterator[dict]:
        """Stream records. With verification on (the default), every record is
        re-hashed, the chain and numbering are checked, and seals are verified
        with Ed25519 — CLIENT-SIDE. A lying stream raises VerificationError."""
        do_verify = self.verify_streams if verify is None else verify
        checker = ChainChecker(check_seals=check_seals) if do_verify else None
        try:
            for reply in self._stub.Replay(
                    pb.ReplayRequest(**{"from": start, "follow": follow}),
                    metadata=self._md):
                rec = json.loads(reply.record_json)
                if checker is not None:
                    checker.check(rec)
                yield rec
        except grpc.RpcError as e:
            raise wrap_rpc_error(e) from None

    def subscribe(self, start: int = 0, follow: bool = False, types=None,
                   verify: Optional[bool] = None,
                   check_seals: bool = True) -> Iterator[dict]:
        """Stream only the given types (G14) — Replay's type-filtered sibling.
        The server drops non-matching records before they cross the wire.

        Honesty note: because the server may drop records, this does NOT
        carry replay()'s gapless/chain-adjacency guarantee. With verification
        on (the default), each delivered record's OWN hash is recomputed (and
        its Ed25519 signature checked, for kivi.seal records) — proving
        "byte-exact what the ledger holds" — but numbering gaps and
        prev_hash discontinuities are EXPECTED and never raise
        VerificationError. A consumer that must prove it received every
        record uses replay() instead."""
        do_verify = self.verify_streams if verify is None else verify
        checker = RecordIntegrityChecker(check_seals=check_seals) if do_verify else None
        try:
            for reply in self._stub.Subscribe(
                    pb.SubscribeRequest(**{"from": start, "follow": follow,
                                           "types": list(types or [])}),
                    metadata=self._md):
                rec = json.loads(reply.record_json)
                if checker is not None:
                    checker.check(rec)
                yield rec
        except grpc.RpcError as e:
            raise wrap_rpc_error(e) from None
