"""Gate, a pass or a block for an agent or a service before a call to it."""

from __future__ import annotations

import logging
import threading
import time
from dataclasses import dataclass

from . import _protocol as p
from .client import AsyncSealKeeper, Clock, SealKeeper
from .errors import BadTargetError, SealKeeperError, UnavailableError
from .lookup import Lookup
from .seal import SEAL_BROKEN_REASONS, SUBJECT_KINDS, VerifiedSeal, card_url_of

# What a pass says. sealed is a current SEAL at bronze or above. The other
# three are a target with no SEAL let through by allow_unsealed.
PASS_CODES = ("sealed", "not_found", "checking", "no_seal")

# Every code a block can carry. The broken SEAL reasons come last.
BLOCK_CODES = (
    "unavailable",
    "bad_target",
    "error",
    "not_found",
    "checking",
    "no_seal",
    "withheld",
    "delisted",
    "unknown",
    "wrong_url",
    "wrong_kind",
    "below_bronze",
    *SEAL_BROKEN_REASONS,
)

CACHE_TTL_MAX_SECONDS = 86400
# The most targets the cache holds. The oldest goes first once full.
CACHE_MAX_ENTRIES = 1024

_UNSEALED = ("not_found", "checking", "no_seal")
_LOG = logging.getLogger("sealkeeper")


@dataclass(frozen=True)
class Pass:
    """Go ahead. seal is the verified SEAL, None for a target let through
    unsealed, which code then names."""

    code: str
    seal: VerifiedSeal | None = None

    @property
    def passed(self) -> bool:
        return True


@dataclass(frozen=True)
class Block:
    """Do not call. code is one of BLOCK_CODES, reason one line of why."""

    code: str
    reason: str

    @property
    def passed(self) -> bool:
        return False


Decision = Pass | Block

_REASONS = {
    "not_found": "SealKeeper knows no agent or service by that target",
    "checking": "SealKeeper is still checking it, so it holds no SEAL yet",
    "no_seal": "it holds no SEAL, it has been dormant",
    "delisted": "SealKeeper no longer lists it",
    "unknown": "it holds no SEAL and SealKeeper says nothing more",
    "wrong_url": "the SEAL is for another URL than the one asked for",
    "below_bronze": "its SEAL is below bronze",
}

# Each kind's SEAL as a reason names it.
_SEAL_NAMES = {"agent": "an Agent SEAL", "service": "a Service SEAL"}


def decide(target: str, kind: str, lookup: Lookup, allow_unsealed: bool) -> Decision:
    """The decision for a lookup of target when kind is expected.

    A SEAL that verified must name the URL asked for when the target is a
    listed URL, be of kind and be bronze or above. Without a SEAL, only
    not_found, checking and no_seal pass, and only with allow_unsealed.
    """
    seal = lookup.seal
    if seal is not None:
        if p.is_listed_url(target) and card_url_of(seal) != p.host_lowered(target):
            return Block("wrong_url", _REASONS["wrong_url"])
        if seal.kind != kind:
            return Block(
                "wrong_kind",
                f"it holds {_SEAL_NAMES[seal.kind]}, not {_SEAL_NAMES[kind]}",
            )
        if seal.level == "none":
            return Block("below_bronze", _REASONS["below_bronze"])
        return Pass("sealed", seal)
    code = lookup.code
    if code == "broken" and lookup.broken in SEAL_BROKEN_REASONS:
        return Block(lookup.broken, f"broken SEAL: {lookup.broken}")
    if code in _UNSEALED:
        return Pass(code) if allow_unsealed else Block(code, _REASONS[code])
    if code == "withheld":
        why = lookup.reason or "no reason given"
        return Block("withheld", f"SealKeeper withholds its SEAL, reason {why}")
    if code == "delisted":
        return Block("delisted", _REASONS["delisted"])
    return Block("unknown", _REASONS["unknown"])


def block_of(error: Exception) -> Block:
    """The block for a lookup that raised."""
    if isinstance(error, BadTargetError):
        return Block("bad_target", str(error))
    if isinstance(error, UnavailableError):
        return Block("unavailable", str(error))
    if isinstance(error, SealKeeperError):
        return Block("error", str(error))
    return Block("error", f"unexpected {type(error).__name__}")


class _Cache:
    """Lookups by target, each kept for ttl seconds and a SEAL only while
    current. The oldest entry goes once CACHE_MAX_ENTRIES are held."""

    def __init__(self, ttl: float) -> None:
        self._ttl = ttl
        self._entries: dict[str, tuple[float, Lookup]] = {}
        self._lock = threading.Lock()

    def get(self, target: str, now: float) -> Lookup | None:
        with self._lock:
            entry = self._entries.get(target)
            if entry is None:
                return None
            stored, lookup = entry
            fresh = 0 <= now - stored < self._ttl
            if fresh and (lookup.seal is None or lookup.seal.is_current(now)):
                return lookup
            del self._entries[target]
            return None

    def put(self, target: str, lookup: Lookup, now: float) -> None:
        if self._ttl <= 0:
            return
        with self._lock:
            self._entries.pop(target, None)
            while len(self._entries) >= CACHE_MAX_ENTRIES:
                del self._entries[next(iter(self._entries))]
            self._entries[target] = (now, lookup)


class Gate:
    """Decides whether to call an agent or a service, from its SEAL.

    check and acheck answer Pass or Block and never raise for a decision.
    A pass needs a current, valid SEAL of the expected kind at bronze or
    above. allow_unsealed also lets through a target SealKeeper does not
    know, one it is still checking and one with no SEAL for dormancy.
    cache_ttl is how long a lookup is kept per target, 0 to 86400 seconds,
    0 for none. client and async_client are the clients to look up with,
    made on first use when not given, with clock.
    """

    def __init__(
        self,
        *,
        allow_unsealed: bool = False,
        cache_ttl: float = 300,
        client: SealKeeper | None = None,
        async_client: AsyncSealKeeper | None = None,
        clock: Clock | None = None,
    ) -> None:
        if (
            isinstance(cache_ttl, bool)
            or not isinstance(cache_ttl, (int, float))
            or not 0 <= cache_ttl <= CACHE_TTL_MAX_SECONDS
        ):
            raise ValueError(f"cache_ttl must be 0 to {CACHE_TTL_MAX_SECONDS} seconds")
        self._allow_unsealed = allow_unsealed
        self._cache = _Cache(cache_ttl)
        self._clock: Clock = clock if clock is not None else time.time
        self._client = client
        self._async_client = async_client
        self._owns = (client is None, async_client is None)

    def check(self, target: str, kind: str) -> Decision:
        """Pass or Block for target, expected to be of kind agent or service."""
        _check_kind(kind)
        now = self._clock()
        lookup = self._cached(target, now)
        if lookup is None:
            if self._client is None:
                self._client = SealKeeper(clock=self._clock)
            try:
                lookup = self._client.lookup(target)
            except Exception as error:
                return _logged(target, kind, None, block_of(error))
            self._cache.put(target, lookup, now)
        return _logged(target, kind, lookup, self._decide(target, kind, lookup))

    async def acheck(self, target: str, kind: str) -> Decision:
        """check, awaited."""
        _check_kind(kind)
        now = self._clock()
        lookup = self._cached(target, now)
        if lookup is None:
            if self._async_client is None:
                self._async_client = AsyncSealKeeper(clock=self._clock)
            try:
                lookup = await self._async_client.lookup(target)
            except Exception as error:
                return _logged(target, kind, None, block_of(error))
            self._cache.put(target, lookup, now)
        return _logged(target, kind, lookup, self._decide(target, kind, lookup))

    def close(self) -> None:
        """Closes the sync client the gate made."""
        if self._owns[0] and self._client is not None:
            self._client.close()

    async def aclose(self) -> None:
        """Closes the async client the gate made."""
        if self._owns[1] and self._async_client is not None:
            await self._async_client.aclose()

    def _cached(self, target: object, now: float) -> Lookup | None:
        return self._cache.get(target, now) if isinstance(target, str) else None

    def _decide(self, target: str, kind: str, lookup: Lookup) -> Decision:
        return decide(target, kind, lookup, self._allow_unsealed)


def _check_kind(kind: object) -> None:
    if kind not in SUBJECT_KINDS:
        raise ValueError('kind must be "agent" or "service"')


def _logged(
    target: object, kind: str, lookup: Lookup | None, decision: Decision
) -> Decision:
    """decision, after one INFO line on the sealkeeper logger.

    The line names the agent by the handle SealKeeper answered, else a URL
    target by its host alone, and never carries a SEAL or a full URL.
    """
    subject = ""
    if lookup is not None and lookup.handle is not None:
        subject = f" agent={lookup.handle}"
    elif isinstance(target, str) and p.is_http_url(target):
        host = p.host_of(target)
        subject = f" host={host}" if host else ""
    outcome = "pass" if decision.passed else "block"
    _LOG.info("gate %s %s kind=%s%s", outcome, decision.code, kind, subject)
    return decision
