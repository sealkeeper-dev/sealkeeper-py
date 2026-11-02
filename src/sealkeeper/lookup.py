"""Reading a get_trust answer into a Lookup, with its SEAL verified."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .errors import SealKeeperError
from .seal import VerifiedSeal, is_agent_id


@dataclass(frozen=True)
class Lookup:
    """What get_trust answered for a target, with its SEAL verified here.

    seal is the VerifiedSeal, set only when the SEAL checked out. Otherwise
    code says why there is none.

      broken      the SEAL did not verify, broken is the reason
      withheld    SealKeeper withholds the SEAL, reason is why, since when
      no_seal     the agent has no SEAL, dormant_days how long it is quiet
      checking    the agent is still being checked
      delisted    the agent is no longer listed
      not_found   the target names no agent
      unknown     a shown answer with no SEAL that says nothing more

    A code or a status this version does not know is passed through as it
    came, with the whole answer in raw. handle is the agent's handle as the
    answer gives it, unsigned and for display only. Level, kind and Trust
    Score are only ever read from seal.
    """

    status: str
    seal: VerifiedSeal | None = None
    code: str | None = None
    broken: str | None = None
    reason: str | None = None
    since: str | None = None
    dormant_days: int | None = None
    handle: str | None = None
    raw: dict[str, Any] | None = field(default=None, repr=False, compare=False)

    @property
    def verified(self) -> bool:
        return self.seal is not None

    @property
    def kind(self) -> str | None:
        return self.seal.kind if self.seal else None

    @property
    def level(self) -> str | None:
        return self.seal.level if self.seal else None

    @property
    def trust(self) -> int | None:
        return self.seal.trust if self.seal else None


def _text(value: object) -> str | None:
    return value if isinstance(value, str) else None


def seal_to_check(
    answer: dict[str, Any], named_id: str | None
) -> tuple[str, str] | None:
    """The SEAL of a shown answer and the agent id to check it against.

    The id is the one the target named when it named one, else the
    answer's agent id. None when the answer carries no SEAL.
    """
    seal = answer.get("seal")
    if answer.get("status") != "shown" or seal is None:
        return None
    if not isinstance(seal, str):
        raise SealKeeperError("SealKeeper's answer has a SEAL that is not a string")
    agent = answer.get("agent")
    agent_id = agent.get("id") if isinstance(agent, dict) else None
    expected = named_id if named_id is not None else agent_id
    if not is_agent_id(expected):
        raise SealKeeperError("SealKeeper's answer names no agent id for its SEAL")
    return seal, expected


def lookup_of(
    answer: dict[str, Any], seal: VerifiedSeal | None, broken: str | None
) -> Lookup:
    """The Lookup of a get_trust answer, given what its SEAL verified to."""
    status = _text(answer.get("status")) or "unknown"
    agent = answer.get("agent")
    handle = _text(agent.get("handle")) if isinstance(agent, dict) else None
    if seal is not None:
        return Lookup(status, seal=seal, handle=handle)
    if broken is not None:
        return Lookup(status, code="broken", broken=broken, handle=handle)
    if status in ("checking", "delisted", "not_found"):
        return Lookup(status, code=status, handle=handle)
    if status != "shown":
        return Lookup(status, code="unknown", handle=handle, raw=answer)
    withheld = answer.get("withheld")
    if not isinstance(withheld, dict) or not isinstance(withheld.get("code"), str):
        return Lookup(status, code="unknown", handle=handle, raw=answer)
    code = withheld["code"]
    if code == "withheld":
        return Lookup(
            status,
            code=code,
            reason=_text(withheld.get("reason")),
            since=_text(withheld.get("since")),
            handle=handle,
        )
    if code == "no_seal":
        days = withheld.get("dormant_days")
        whole = isinstance(days, int) and not isinstance(days, bool) and days >= 0
        return Lookup(
            status, code=code, dormant_days=days if whole else None, handle=handle
        )
    if code == "checking":
        return Lookup(status, code=code, handle=handle)
    return Lookup(status, code=code, handle=handle, raw=answer)
