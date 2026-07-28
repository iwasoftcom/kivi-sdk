"""kivi Python SDK — asynchronous client (grpc.aio). Same constitution, same
verification, async idiom: every method awaits, replay is an async iterator."""

import json
from typing import Any, AsyncIterator, Optional

import grpc
import grpc.aio

from . import kivi_pb2 as pb
from . import kivi_pb2_grpc as rpcstub
from .client import (Receipt, TracedAnswer, ViewState, VerifyReport,
                     SimilarHit, SimilarAnswer, Session, ViewEntry, ViewPage,
                     dumps, wrap_rpc_error)
from .verify import ChainChecker, RecordIntegrityChecker

__all__ = ["AsyncKiviClient"]


class AsyncKiviClient:
    def __init__(self, addr: str, token: Optional[str] = None,
                 verify: bool = True, channel: Optional[grpc.aio.Channel] = None):
        self._channel = channel or grpc.aio.insecure_channel(addr)
        self._stub = rpcstub.KiviStub(self._channel)
        self._md = (("authorization", f"Bearer {token}"),) if token else ()
        self.verify_streams = verify
        self._owns_channel = channel is None

    async def close(self):
        # a with_bearer view never closes the shared channel
        if self._owns_channel:
            await self._channel.close()

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        await self.close()

    async def _call(self, fn, req):
        try:
            return await fn(req, metadata=self._md)
        except grpc.aio.AioRpcError as e:
            raise wrap_rpc_error(e) from None

    # -- identity plane --------------------------------------------------------

    async def login(self, username: str, password: str) -> Session:
        """Authenticate as a kivi USER and install the session token (see the
        sync client for the one-center contract)."""
        r = await self._call(self._stub.Login,
                             pb.LoginRequest(username=username, password=password))
        self.set_token(r.token)
        return Session(r.token, r.role, r.expires_unix)

    def set_token(self, token: Optional[str]):
        self._md = (("authorization", f"Bearer {token}"),) if token else ()

    def with_bearer(self, token: str) -> "AsyncKiviClient":
        """A shallow view over the same channel with ANOTHER identity —
        per-caller credentials for stateless multi-tenant frontends."""
        c = AsyncKiviClient.__new__(AsyncKiviClient)
        c._channel = self._channel
        c._stub = self._stub
        c._md = (("authorization", f"Bearer {token}"),) if token else ()
        c.verify_streams = self.verify_streams
        c._owns_channel = False  # closing the view must not cut the shared wire
        return c

    async def append(self, event_type: str, body: Any) -> Receipt:
        r = await self._call(self._stub.Append,
                             pb.AppendRequest(type=event_type, body_json=dumps(body)))
        return Receipt(r.no, r.offset, r.hash)

    async def append_private(self, event_type: str, body: Any) -> Receipt:
        r = await self._call(self._stub.AppendPrivate,
                             pb.AppendRequest(type=event_type, body_json=dumps(body)))
        return Receipt(r.no, r.offset, r.hash)

    async def erase(self, no: int, reason: str) -> Receipt:
        r = await self._call(self._stub.Erase, pb.EraseRequest(no=no, reason=reason))
        return Receipt(r.no, r.offset, r.hash)

    async def seal(self) -> Receipt:
        r = await self._call(self._stub.Seal, pb.Empty())
        return Receipt(r.no, r.offset, r.hash)

    async def verify_ledger(self) -> VerifyReport:
        r = await self._call(self._stub.Verify, pb.Empty())
        return VerifyReport(r.ok, r.records, r.seals, r.unsealed_tail,
                            r.torn_tail, r.defect_no, r.defect_reason, r.has_defect)

    async def head(self) -> tuple:
        """(head_no, head_hash) without an audit — cheap orientation."""
        r = await self._call(self._stub.Head, pb.Empty())
        return (r.head_no, r.head_hash)

    async def table(self, subject: str, attribute: str,
                    as_of: Optional[int] = None) -> TracedAnswer:
        req = pb.TableRequest(subject=subject, attribute=attribute)
        if as_of is not None:
            req.as_of = as_of
        r = await self._call(self._stub.QueryTable, req)
        return TracedAnswer(json.loads(r.value_json), tuple(r.trace), r.scope)

    async def subject(self, subject: str, as_of: Optional[int] = None) -> TracedAnswer:
        """table()'s whole-row sibling (G15) — see client.py's subject()."""
        req = pb.SubjectRequest(subject=subject)
        if as_of is not None:
            req.as_of = as_of
        r = await self._call(self._stub.QuerySubject, req)
        return TracedAnswer(json.loads(r.value_json), tuple(r.trace), r.scope)

    async def view_page(self, view: str, after_key: str = "", limit: int = 0,
                        as_of: Optional[int] = None) -> ViewPage:
        req = pb.ViewPageRequest(view=view, after_key=after_key, limit=limit)
        if as_of is not None:
            req.as_of = as_of
        r = await self._call(self._stub.QueryViewPage, req)
        entries = tuple(ViewEntry(e.key, json.loads(e.value_json)) for e in r.entries)
        return ViewPage(entries, r.next_key, r.scope, r.hash)

    async def similar(self, query: str, k: int = 5) -> SimilarAnswer:
        r = await self._call(self._stub.Similar, pb.SimilarRequest(query=query, k=k))
        hits = tuple(SimilarHit(h.no, h.score,
                                json.loads(h.record_json) if h.record_json else None)
                     for h in r.hits)
        return SimilarAnswer(hits, r.scope, r.model)

    async def why(self, trace) -> list:
        r = await self._call(self._stub.Why, pb.WhyRequest(trace=list(trace)))
        return [json.loads(x.record_json) for x in r.records]

    async def replay(self, start: int = 0, follow: bool = False,
                     verify: Optional[bool] = None,
                     check_seals: bool = True) -> AsyncIterator[dict]:
        do_verify = self.verify_streams if verify is None else verify
        checker = ChainChecker(check_seals=check_seals) if do_verify else None
        try:
            async for reply in self._stub.Replay(
                    pb.ReplayRequest(**{"from": start, "follow": follow}),
                    metadata=self._md):
                rec = json.loads(reply.record_json)
                if checker is not None:
                    checker.check(rec)
                yield rec
        except grpc.aio.AioRpcError as e:
            raise wrap_rpc_error(e) from None

    async def subscribe(self, start: int = 0, follow: bool = False, types=None,
                        verify: Optional[bool] = None,
                        check_seals: bool = True) -> AsyncIterator[dict]:
        """Replay's type-filtered sibling (G14) — see client.py's subscribe()
        for the full honesty note: gaps are expected on purpose here, and
        never raise VerificationError, unlike replay()'s stricter checker."""
        do_verify = self.verify_streams if verify is None else verify
        checker = RecordIntegrityChecker(check_seals=check_seals) if do_verify else None
        try:
            async for reply in self._stub.Subscribe(
                    pb.SubscribeRequest(**{"from": start, "follow": follow,
                                           "types": list(types or [])}),
                    metadata=self._md):
                rec = json.loads(reply.record_json)
                if checker is not None:
                    checker.check(rec)
                yield rec
        except grpc.aio.AioRpcError as e:
            raise wrap_rpc_error(e) from None
