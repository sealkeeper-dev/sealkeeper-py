"""The requests the clients send and how they read the answers.

Pure functions and one small key cache. The sync and async clients only
move bytes, so both read every answer the same way.
"""

from __future__ import annotations

import json
import re
from collections.abc import Mapping
from datetime import datetime, timezone
from typing import Any
from urllib.parse import unquote, urlsplit

from ._version import __version__
from .errors import BadTargetError, SealKeeperError, UnavailableError
from .seal import DID_KEY_PREFIX, agent_id_from_did_key, is_agent_id

MCP_URL = "https://api.sealkeeper.run/mcp"
KEYS_URL = "https://sealkeeper.run/.well-known/seal.json"
PAGE_ORIGIN = ("sealkeeper.run", "https")
API_ORIGIN = ("api.sealkeeper.run", "https")
MCP_PROTOCOL_VERSION = "2025-11-25"

TIMEOUT_SECONDS = 5.0
ANSWER_MAX_BYTES = 64 * 1024
# How long a copy of the keys is used before it is fetched again.
KEYS_MAX_AGE_SECONDS = 300

# The longest line of server text an exception carries.
_TEXT_MAX_CHARS = 500
_SUFFIX = re.compile(r"[!-~]+(?: [!-~]+)*")
_SUFFIX_MAX_CHARS = 128
_PAGE_PATH = re.compile(r"/agents/([^/]+)(?:/([^/]+))?/?")
_API_CARD_PATH = re.compile(r"/v1/agents/([A-Za-z0-9_-]{43})/card/?")
_URL = re.compile(r"([A-Za-z][A-Za-z0-9+.-]*://)([^/?#]*)(.*)", re.DOTALL)
_HTTP_URL = re.compile(r"https?://", re.IGNORECASE)


def user_agent(suffix: str | None) -> str:
    """sealkeeper-py/<version>, then suffix, such as a wrapper's own name."""
    base = f"sealkeeper-py/{__version__}"
    if suffix is None:
        return base
    if (
        not isinstance(suffix, str)
        or len(suffix) > _SUFFIX_MAX_CHARS
        or not _SUFFIX.fullmatch(suffix)
    ):
        raise ValueError("user_agent_suffix must be printable ASCII words")
    return f"{base} {suffix}"


def mcp_headers(agent: str) -> dict[str, str]:
    return {
        "content-type": "application/json",
        "accept": "application/json, text/event-stream",
        "mcp-protocol-version": MCP_PROTOCOL_VERSION,
        "user-agent": agent,
    }


def keys_headers(agent: str) -> dict[str, str]:
    return {"accept": "application/json", "user-agent": agent}


def tool_call(name: str, arguments: Mapping[str, Any]) -> bytes:
    """One stateless JSON-RPC tools/call, the whole request body."""
    message = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {"name": name, "arguments": dict(arguments)},
    }
    return json.dumps(message, separators=(",", ":")).encode("utf-8")


def retry_wait(status: int, headers: Mapping[str, str], attempt: int) -> float | None:
    """The seconds to wait before the one retry of a 429, else None.

    Only the first answer is retried, and only when Retry-After names
    whole seconds no longer than the timeout.
    """
    if status != 429 or attempt > 0:
        return None
    value = headers.get("retry-after", "").strip()
    if not value.isascii() or not value.isdigit():
        return None
    seconds = int(value)
    return float(seconds) if seconds <= TIMEOUT_SECONDS else None


def _short(text: str) -> str:
    return text if len(text) <= _TEXT_MAX_CHARS else text[:_TEXT_MAX_CHARS] + "..."


def _json(body: bytes) -> object:
    try:
        return json.loads(body.decode("utf-8"))
    except (ValueError, RecursionError):
        return None


def _error_message(parsed: object) -> str:
    error = parsed.get("error") if isinstance(parsed, dict) else None
    message = error.get("message") if isinstance(error, dict) else None
    return _short(message) if isinstance(message, str) else "no message"


def read_answer(status: int, body: bytes) -> dict[str, Any]:
    """The structuredContent of a tools/call answer, or the error it is.

    A 429 or a 5xx is UnavailableError. A tool error is BadTargetError with
    the server's line. Any other status, a JSON-RPC error or an answer
    that is not a tool result is SealKeeperError.
    """
    if status == 429:
        raise UnavailableError("SealKeeper is rate limiting this caller")
    if status >= 500:
        raise UnavailableError(f"SealKeeper answered HTTP {status}")
    parsed = _json(body)
    if status != 200:
        raise SealKeeperError(
            f"SealKeeper refused the request, HTTP {status}: {_error_message(parsed)}"
        )
    if not isinstance(parsed, dict):
        raise SealKeeperError("SealKeeper's answer is not a JSON object")
    if "error" in parsed:
        raise SealKeeperError(f"SealKeeper answered an error: {_error_message(parsed)}")
    result = parsed.get("result")
    if not isinstance(result, dict):
        raise SealKeeperError("SealKeeper's answer has no result")
    if result.get("isError") is True:
        raise BadTargetError(_first_text(result))
    data = result.get("structuredContent")
    if not isinstance(data, dict):
        raise SealKeeperError("SealKeeper's answer has no structuredContent")
    return data


def _first_text(result: dict[str, Any]) -> str:
    content = result.get("content")
    if isinstance(content, list):
        for item in content:
            if isinstance(item, dict) and isinstance(item.get("text"), str):
                return _short(item["text"])
    return "SealKeeper refused the input"


def read_keys_answer(status: int, body: bytes) -> object:
    """The key document of a 200 answer. Anything else is UnavailableError."""
    if status != 200:
        raise UnavailableError(f"could not load the SealKeeper keys, HTTP {status}")
    parsed = _json(body)
    if parsed is None:
        raise UnavailableError("the SealKeeper key document is not JSON")
    return parsed


def page_url(agent_id: str) -> str:
    return f"https://sealkeeper.run/agents/{agent_id}"


def own_url_id(target: str) -> tuple[bool, str | None]:
    """Whether target is a SealKeeper page or API card URL, and its agent id.

    A page is /agents/<first>/<name> or /agents/<id> on sealkeeper.run, a
    card /v1/agents/<id>/card on api.sealkeeper.run. Only the id forms name
    an id.
    """
    if not _HTTP_URL.match(target):
        return False, None
    try:
        parts = urlsplit(target)
        port = parts.port
    except ValueError:
        return False, None
    origin = (parts.hostname, parts.scheme) if port in (None, 443) else None
    path = parts.path
    if origin == PAGE_ORIGIN:
        page = _PAGE_PATH.fullmatch(path)
        if page is None:
            return False, None
        first = unquote(page.group(1))
        return True, first if page.group(2) is None and is_agent_id(first) else None
    if origin == API_ORIGIN:
        card = _API_CARD_PATH.fullmatch(path)
        if card is None:
            return False, None
        return True, card.group(1) if is_agent_id(card.group(1)) else None
    return False, None


def trust_target(target: object) -> tuple[str, str | None]:
    """What get_trust is sent for target, and the agent id target names.

    A bare agent id goes as its page URL, and a did:key as the page URL of
    the id it names. Every other target goes as given.
    """
    if not isinstance(target, str) or not target.strip():
        raise BadTargetError("the target must be a non-empty string")
    text = target.strip()
    if text.startswith(DID_KEY_PREFIX):
        agent_id = agent_id_from_did_key(text)
        if agent_id is None:
            raise BadTargetError("the target is not an Ed25519 did:key")
        return page_url(agent_id), agent_id
    if is_agent_id(text):
        return page_url(text), text
    return target, own_url_id(text)[1]


def is_http_url(target: str) -> bool:
    return _HTTP_URL.match(target.strip()) is not None


def is_listed_url(target: str) -> bool:
    """Whether target is an http or https URL other than SealKeeper's own."""
    return is_http_url(target) and not own_url_id(target.strip())[0]


def host_lowered(url: str) -> str:
    """url with only its host in lower case, and an empty path read as /."""
    match = _URL.fullmatch(url.strip())
    if match is None:
        return url
    scheme, authority, rest = match.groups()
    userinfo, at, host = authority.rpartition("@")
    return f"{scheme}{userinfo}{at}{host.lower()}{rest or '/'}"


def host_of(url: str) -> str | None:
    try:
        return urlsplit(url.strip()).hostname
    except ValueError:
        return None


def verify_arguments(
    seal: str, agent: str | None, at: datetime | str | None
) -> dict[str, str]:
    """verify_seal's arguments. A datetime at must carry its time zone."""
    arguments = {"seal": seal}
    if agent is not None:
        arguments["agent"] = agent
    if isinstance(at, datetime):
        if at.tzinfo is None:
            raise ValueError("at must carry its time zone")
        utc = at.astimezone(timezone.utc)
        arguments["at"] = (
            utc.strftime("%Y-%m-%dT%H:%M:%S.") + f"{utc.microsecond // 1000:03d}Z"
        )
    elif at is not None:
        arguments["at"] = at
    return arguments


class KeyCache:
    """The last key document fetched, kid to x, and when it was fetched."""

    def __init__(self) -> None:
        self._keys: dict[str, str] = {}
        self._fetched_at: float | None = None

    def usable(self, kid: str, now: float) -> dict[str, str] | None:
        """The keys while the copy is younger than five minutes and knows kid.

        A copy dated after now counts as too old.
        """
        if self._fetched_at is None or kid not in self._keys:
            return None
        age = now - self._fetched_at
        return self._keys if 0 <= age < KEYS_MAX_AGE_SECONDS else None

    def store(self, keys: dict[str, str], now: float) -> None:
        self._keys, self._fetched_at = keys, now
