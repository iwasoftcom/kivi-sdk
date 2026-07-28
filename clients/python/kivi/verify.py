"""Client-side verification (K3) — the untrusting client.

Canonical hashing per FORMAT.md §3 (the golden vectors are the arbiters) plus
a pure-Python Ed25519 VERIFIER (RFC 8032, verify-only: no keys are ever
generated or used for signing here). Self-contained on purpose: the SDK's
runtime dependency stays grpcio alone.
"""

import hashlib
import json

CORE_KEYS = ("no", "time", "type", "body", "prev_hash")
SEAL_TYPE = "kivi.seal"


class VerificationError(Exception):
    """The server (or the wire) lied — a record failed client-side checks."""


def canonical(core: dict) -> bytes:
    return json.dumps(core, sort_keys=True, ensure_ascii=False,
                      separators=(",", ":")).encode("utf-8")


def record_hash(rec: dict) -> str:
    return hashlib.sha256(canonical({k: rec[k] for k in CORE_KEYS})).hexdigest()


def check_record_integrity(rec: dict, check_seals: bool = True) -> None:
    """Verifies ONE record's OWN hash (and Ed25519 seal signature, for
    kivi.seal records) — the part every stream checker shares, regardless of
    whether gaps between records are expected."""
    no = rec.get("no")
    if record_hash(rec) != rec.get("hash"):
        raise VerificationError(
            f"record {no}: hash mismatch — content altered in flight or at rest")
    if check_seals and rec.get("type") == SEAL_TYPE:
        body = rec.get("body") or {}
        try:
            pk = bytes.fromhex(body["pk"])
            sig = bytes.fromhex(rec["sig"])
        except (KeyError, TypeError, ValueError):
            raise VerificationError(f"seal {no}: malformed key or signature")
        if not ed25519_verify(sig, canonical({k: rec[k] for k in CORE_KEYS}), pk):
            raise VerificationError(f"seal {no}: Ed25519 signature invalid")


class ChainChecker:
    """Verifies a replay stream record by record: hash, gapless numbering,
    chain linkage, and (optionally) Ed25519 seal signatures."""

    def __init__(self, check_seals: bool = True):
        self.check_seals = check_seals
        self._prev_hash = None
        self._next_no = None

    def check(self, rec: dict) -> dict:
        no = rec.get("no")
        check_record_integrity(rec, self.check_seals)
        if self._next_no is not None and no != self._next_no:
            raise VerificationError(
                f"record numbering broken: expected {self._next_no}, got {no}")
        if self._prev_hash is not None and rec.get("prev_hash") != self._prev_hash:
            raise VerificationError(f"record {no}: chain linkage broken")
        self._prev_hash = rec.get("hash")
        self._next_no = (no + 1) if isinstance(no, int) else None
        return rec


class RecordIntegrityChecker:
    """Subscribe's checker (G14): each record's OWN hash/signature is
    verified, but — unlike ChainChecker — numbering gaps and prev_hash
    discontinuities are EXPECTED (server-side type filtering causes them by
    design) and are never treated as tampering."""

    def __init__(self, check_seals: bool = True):
        self.check_seals = check_seals

    def check(self, rec: dict) -> dict:
        check_record_integrity(rec, self.check_seals)
        return rec


# ---- Ed25519 verify (RFC 8032), pure Python, verify-only -------------------

_P = 2**255 - 19
_L = 2**252 + 27742317777372353535851937790883648493
_D = (-121665 * pow(121666, _P - 2, _P)) % _P
_I = pow(2, (_P - 1) // 4, _P)


def _sha512(b: bytes) -> bytes:
    return hashlib.sha512(b).digest()


def _xrecover(y: int) -> int:
    xx = (y * y - 1) * pow(_D * y * y + 1, _P - 2, _P)
    x = pow(xx, (_P + 3) // 8, _P)
    if (x * x - xx) % _P != 0:
        x = (x * _I) % _P
    if (x * x - xx) % _P != 0:
        raise VerificationError("point not on curve")
    if x % 2 != 0:
        x = _P - x
    return x


_BY = (4 * pow(5, _P - 2, _P)) % _P
_BX = _xrecover(_BY)
_B = (_BX, _BY, 1, (_BX * _BY) % _P)  # extended coordinates


def _edwards_add(p, q):
    x1, y1, z1, t1 = p
    x2, y2, z2, t2 = q
    a = ((y1 - x1) * (y2 - x2)) % _P
    b = ((y1 + x1) * (y2 + x2)) % _P
    c = (2 * t1 * t2 * _D) % _P
    dd = (2 * z1 * z2) % _P
    e, f, g, h = b - a, dd - c, dd + c, b + a
    return ((e * f) % _P, (g * h) % _P, (f * g) % _P, (e * h) % _P)


def _scalarmult(p, e: int):
    q = (0, 1, 1, 0)  # neutral
    while e > 0:
        if e & 1:
            q = _edwards_add(q, p)
        p = _edwards_add(p, p)
        e >>= 1
    return q


def _decompress(s: bytes):
    y = int.from_bytes(s, "little") & ((1 << 255) - 1)
    sign = s[31] >> 7
    x = _xrecover(y % _P)
    if x & 1 != sign:
        x = _P - x
    if not _on_curve(x, y % _P):
        raise VerificationError("public key or R not on curve")
    return (x, y % _P, 1, (x * (y % _P)) % _P)


def _on_curve(x: int, y: int) -> bool:
    return (-x * x + y * y - 1 - _D * x * x * y * y) % _P == 0


def _compress(p) -> bytes:
    x, y, z, _ = p
    zi = pow(z, _P - 2, _P)
    x, y = (x * zi) % _P, (y * zi) % _P
    return (y | ((x & 1) << 255)).to_bytes(32, "little")


def ed25519_verify(sig: bytes, msg: bytes, pk: bytes) -> bool:
    if len(sig) != 64 or len(pk) != 32:
        return False
    try:
        a = _decompress(pk)
        r_enc = sig[:32]
        _decompress(r_enc)  # R must be a valid point
    except VerificationError:
        return False
    s = int.from_bytes(sig[32:], "little")
    if s >= _L:
        return False
    k = int.from_bytes(_sha512(r_enc + pk + msg), "little") % _L
    # check: [s]B == R + [k]A  (encoded comparison)
    sb = _scalarmult(_B, s)
    rka = _edwards_add(_decompress(r_enc), _scalarmult(a, k))
    return _compress(sb) == _compress(rka)
