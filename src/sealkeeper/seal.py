"""Verifying a SEAL offline, the steps of the SEAL Standard in their order.

Every function here is pure. The clients fetch the keys and call
verify_with_keys with them.
"""

from __future__ import annotations

import base64
import json
import math
import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any, TypeGuard

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .errors import SealBroken

# Every SEAL version this library reads. Any other ver is a broken SEAL.
SEAL_VERSIONS = (1, 2, 3, 4, 5, 6, 7, 8, 9)

# Why a SEAL is broken, one per step of verification.
SEAL_BROKEN_REASONS = (
    "malformed",
    "unknown_kid",
    "bad_signature",
    "wrong_issuer",
    "unsupported_version",
    "expired",
    "not_yet_valid",
    "wrong_agent",
)

ISSUER = "sealkeeper.run"
# The issuer's old name, accepted only before LEGACY_ISSUER_UNTIL, Unix
# seconds of 2 October 2026 00:00 UTC.
LEGACY_ISSUERS = ("vouched.run",)
LEGACY_ISSUER_UNTIL = 1790899200
# How far ahead of the clock iat may be before a SEAL is not yet valid.
CLOCK_SKEW_SECONDS = 300
# The longest a SEAL lives, from iat to exp.
MAX_TTL_SECONDS = 24 * 3600

LEVELS = ("none", "bronze", "silver", "gold")
SUBJECT_KINDS = ("agent", "service")

_JWS_MAX_CHARS = 262144
_JWS = re.compile(r"[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+")
_KID_MAX_UNITS = 128
_B64URL = re.compile(r"[A-Za-z0-9_-]*")
# The largest whole number a JSON reader holds exactly.
_SAFE_INT = 2**53 - 1

# An agent id, a raw 32 byte Ed25519 public key in base64url, 43
# characters. Only some last characters are canonical.
AGENT_ID = re.compile(r"[A-Za-z0-9_-]{42}[AEIMQUYcgkosw048]")

DID_KEY_PREFIX = "did:key:z"
_BASE58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_DID_KEY = re.compile(rf"did:key:z6Mk[{_BASE58}]{{44}}")
_ED25519_MULTICODEC = b"\xed\x01"


@dataclass(frozen=True)
class VerifiedSeal:
    """A SEAL that checked out. Every field is read from the signed payload.

    kind is agent or service, level none, bronze, silver or gold. trust is
    the Trust Score, None before version 4. issued_at and expires_at are
    Unix seconds. payload is the payload as signed.
    """

    agent_id: str
    kind: str
    level: str
    trust: int | None
    issued_at: int
    expires_at: int
    payload: dict[str, Any] = field(repr=False, compare=False)

    def is_current(self, now: float) -> bool:
        """Whether the SEAL has not expired at now, Unix seconds."""
        return math.floor(self.expires_at - now) > 0


def b64url_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def b64url_decode(text: str) -> bytes:
    """Base64url with no padding, refusing any text that is not canonical."""
    if not _B64URL.fullmatch(text) or len(text) % 4 == 1:
        raise ValueError("not base64url")
    raw = base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
    if b64url_encode(raw) != text:
        raise ValueError("not canonical base64url")
    return raw


def is_agent_id(value: object) -> TypeGuard[str]:
    return isinstance(value, str) and AGENT_ID.fullmatch(value) is not None


def agent_id_from_did_key(did: str) -> str | None:
    """The agent id a did:key names, or None for anything else.

    The shape is checked first, so the base58 decode only ever reads 44
    characters. The decode must give exactly 34 bytes, the ed25519-pub
    multicodec 0xed 0x01 and then the key.
    """
    if not isinstance(did, str) or not _DID_KEY.fullmatch(did):
        return None
    body = did[len(DID_KEY_PREFIX) :]
    zeros = len(body) - len(body.lstrip("1"))
    number = 0
    for char in body:
        number = number * 58 + _BASE58.index(char)
    digits = number.to_bytes((number.bit_length() + 7) // 8, "big")
    raw = b"\x00" * zeros + digits
    if len(raw) != 34 or raw[:2] != _ED25519_MULTICODEC:
        return None
    return b64url_encode(raw[2:])


def accepted_issuer(iss: object, now: float) -> bool:
    if iss == ISSUER:
        return True
    return isinstance(iss, str) and iss in LEGACY_ISSUERS and now < LEGACY_ISSUER_UNTIL


def read_keys(doc: object) -> dict[str, str]:
    """The keys of a key document, kid to x. Raises ValueError for none.

    Only an Ed25519 key with a kid and a canonical x is kept, at most 16,
    and the first of a repeated kid wins.
    """
    if not isinstance(doc, dict) or not isinstance(doc.get("keys"), list):
        raise ValueError("not a key document")
    keys: dict[str, str] = {}
    for key in doc["keys"][:16]:
        if not isinstance(key, dict):
            continue
        kid, x = key.get("kid"), key.get("x")
        if (
            key.get("kty") == "OKP"
            and key.get("crv") == "Ed25519"
            and key.get("alg") == "EdDSA"
            and _is_kid(kid)
            and is_agent_id(x)
        ):
            keys.setdefault(kid, x)
    if not keys:
        raise ValueError("the key document has no Ed25519 key")
    return keys


def seal_kid(seal: object) -> str:
    """The kid a SEAL's header names. Raises SealBroken malformed."""
    if not isinstance(seal, str):
        raise SealBroken("malformed")
    header, _, _ = _split(seal.strip())
    return _kid_of(header)


def verify_with_keys(
    seal: object, keys: Mapping[str, str], now: float, agent: str
) -> VerifiedSeal:
    """Verifies a SEAL against keys, kid to x, at now, Unix seconds.

    The steps of the standard in order. The header, the key its kid names,
    the signature over the exact header.payload bytes and only then the
    payload as JSON, the issuer, the version and the shape, exp then iat,
    and last sub against agent, the agent id the caller expects. Raises
    SealBroken with the reason of the first step that fails.
    """
    if not isinstance(seal, str):
        raise SealBroken("malformed")
    header, payload, signature = _split(seal.strip())
    x = keys.get(_kid_of(header))
    if x is None:
        raise SealBroken("unknown_kid")
    if not _signature_ok(x, header, payload, signature):
        raise SealBroken("bad_signature")
    try:
        raw = _json_part(payload)
    except (ValueError, RecursionError):
        raise SealBroken("malformed") from None
    return _check_payload(raw, now, agent)


def _split(jws: str) -> tuple[str, str, str]:
    if len(jws) > _JWS_MAX_CHARS or not _JWS.fullmatch(jws):
        raise SealBroken("malformed")
    header, payload, signature = jws.split(".")
    return header, payload, signature


def _reject_constant(name: str) -> None:
    raise ValueError(f"{name} is not JSON")


def _json_part(part: str) -> object:
    # utf-8-sig drops a leading byte order mark, as a web decoder does.
    text = b64url_decode(part).decode("utf-8-sig")
    return json.loads(text, parse_constant=_reject_constant)


def _is_kid(kid: object) -> bool:
    # A kid's length is counted in UTF-16 code units.
    return (
        isinstance(kid, str)
        and 1 <= len(kid.encode("utf-16-le")) // 2 <= _KID_MAX_UNITS
    )


def _kid_of(header: str) -> str:
    try:
        parsed = _json_part(header)
    except (ValueError, RecursionError):
        raise SealBroken("malformed") from None
    if (
        not isinstance(parsed, dict)
        or set(parsed) != {"alg", "kid"}
        or parsed["alg"] != "EdDSA"
        or not _is_kid(parsed["kid"])
    ):
        raise SealBroken("malformed")
    return parsed["kid"]


def _signature_ok(x: str, header: str, payload: str, signature: str) -> bool:
    try:
        sig = b64url_decode(signature)
        public = b64url_decode(x)
    except ValueError:
        return False
    if len(sig) != 64 or len(public) != 32:
        return False
    try:
        key = Ed25519PublicKey.from_public_bytes(public)
        key.verify(sig, f"{header}.{payload}".encode("ascii"))
    except (InvalidSignature, ValueError):
        return False
    return True


def _whole(value: object) -> int | None:
    """value as a whole number a JSON reader holds exactly, else None."""
    if isinstance(value, bool):
        return None
    if isinstance(value, float) and value.is_integer():
        value = int(value)
    if isinstance(value, int) and -_SAFE_INT <= value <= _SAFE_INT:
        return value
    return None


def _check_payload(raw: object, now: float, agent: str) -> VerifiedSeal:
    if not isinstance(raw, dict) or not accepted_issuer(raw.get("iss"), now):
        raise SealBroken("wrong_issuer")
    ver = _whole(raw.get("ver"))
    if ver not in SEAL_VERSIONS:
        raise SealBroken("unsupported_version")
    seal = _read_fields(raw, ver)
    if not seal.is_current(now):
        raise SealBroken("expired")
    if seal.issued_at - now > CLOCK_SKEW_SECONDS:
        raise SealBroken("not_yet_valid")
    if seal.agent_id != agent:
        raise SealBroken("wrong_agent")
    return seal


def _read_fields(raw: dict[str, Any], ver: int) -> VerifiedSeal:
    """The fields this library reads, each checked for its shape at ver.

    Only these are checked, so a payload with a bad field this library
    never reads still verifies here. Raises SealBroken malformed.
    """
    sub = raw.get("sub")
    iat, exp = _whole(raw.get("iat")), _whole(raw.get("exp"))
    level = raw.get("level")
    if (
        not is_agent_id(sub)
        or iat is None
        or exp is None
        or iat < 0
        or not iat < exp <= iat + MAX_TTL_SECONDS
        or level not in LEVELS
    ):
        raise SealBroken("malformed")
    # trust is in version 4 on, subject in version 7 on and listing in
    # version 5 on. A SEAL of an earlier version that carries one is
    # malformed, and one before version 7 is an agent's.
    trust: int | None = None
    if ver >= 4:
        trust = _whole(raw.get("trust"))
        if trust is None or trust < 0:
            raise SealBroken("malformed")
    elif "trust" in raw:
        raise SealBroken("malformed")
    kind = "agent"
    if ver >= 7:
        subject = raw.get("subject")
        kind = subject.get("kind") if isinstance(subject, dict) else None
        if kind not in SUBJECT_KINDS:
            raise SealBroken("malformed")
    elif "subject" in raw:
        raise SealBroken("malformed")
    if ver >= 5:
        if "listing" in raw and not _listing_ok(raw["listing"]):
            raise SealBroken("malformed")
    elif "listing" in raw:
        raise SealBroken("malformed")
    return VerifiedSeal(
        agent_id=sub,
        kind=kind,
        level=level,
        trust=trust,
        issued_at=iat,
        expires_at=exp,
        payload=raw,
    )


def _listing_ok(listing: object) -> bool:
    if not isinstance(listing, dict):
        return False
    card_url = listing.get("card_url")
    return isinstance(card_url, str) and card_url.startswith(("http://", "https://"))


def card_url_of(seal: VerifiedSeal) -> str | None:
    """The card URL a listed SEAL names, None for a SEAL with no listing."""
    listing = seal.payload.get("listing")
    return listing["card_url"] if isinstance(listing, dict) else None
