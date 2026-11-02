"""Test data and a recorded SealKeeper served through httpx.MockTransport.

No test reaches the network unless SEALKEEPER_LIVE=1 is set.
"""

from __future__ import annotations

import base64
import json
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

import httpx
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from sealkeeper import AsyncSealKeeper, SealKeeper

HERE = Path(__file__).parent
FIXTURES = HERE / "fixtures"
RECORDED = HERE / "recorded"

INDEX = json.loads((FIXTURES / "index.json").read_text())
PINNED = INDEX["clocks"]["pinnedSeconds"]
NOW_FROM = datetime.fromisoformat(
    INDEX["clocks"]["nowFrom"].replace("Z", "+00:00")
).timestamp()
FIXTURE_AGENT = json.loads((FIXTURES / "agent.json").read_text())
FIXTURE_KEYS = json.loads((FIXTURES / "keys.json").read_text())

MCP_URL = "https://api.sealkeeper.run/mcp"
KEYS_URL = "https://sealkeeper.run/.well-known/seal.json"
MODES = ["sync", "async"]


def seal_file(name: str) -> str:
    return (FIXTURES / "seals" / f"{name}.txt").read_text()


def recorded(name: str) -> dict[str, Any]:
    return json.loads((RECORDED / f"{name}.json").read_text())


def b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def payload_of(seal: str) -> dict[str, Any]:
    part = seal.split(".")[1]
    return json.loads(base64.urlsafe_b64decode(part + "=" * (-len(part) % 4)))


# The production answer for sealkeeper/test-agent, its SEAL and the keys
# document of the same day. The SEAL verifies at TEST_AGENT_CLOCK.
TEST_AGENT_ANSWER = recorded("get-trust-shown")
TEST_AGENT_SEAL = TEST_AGENT_ANSWER["body"]["result"]["structuredContent"]["seal"]
TEST_AGENT_ID = TEST_AGENT_ANSWER["body"]["result"]["structuredContent"]["agent"]["id"]
TEST_AGENT_CLOCK = payload_of(TEST_AGENT_SEAL)["iat"] + 3600
PRODUCTION_KEYS = recorded("keys-production")["body"]

# A test signing key, fixed so every SEAL it signs is the same bytes.
TEST_KID = "test-1"
_TEST_KEY = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
TEST_X = b64url(_TEST_KEY.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw))
TEST_KEYS = {TEST_KID: TEST_X}


def sign(payload: Any, kid: str = TEST_KID, header: Any = None) -> str:
    """A compact JWS of payload signed with the test key, header as given."""
    head = header if header is not None else {"alg": "EdDSA", "kid": kid}
    text = payload if isinstance(payload, bytes) else json.dumps(payload).encode()
    signing_input = f"{b64url(json.dumps(head).encode())}.{b64url(text)}"
    return f"{signing_input}.{b64url(_TEST_KEY.sign(signing_input.encode()))}"


def key_document(keys: dict[str, str]) -> dict[str, Any]:
    return {
        "keys": [
            {"kid": kid, "kty": "OKP", "crv": "Ed25519", "alg": "EdDSA", "x": x}
            for kid, x in keys.items()
        ]
    }


def tool_result(data: dict[str, Any]) -> dict[str, Any]:
    """A tools/call answer the way SealKeeper writes one."""
    return {
        "jsonrpc": "2.0",
        "id": 1,
        "result": {
            "content": [
                {"type": "text", "text": "answer"},
                {"type": "text", "text": json.dumps(data)},
            ],
            "structuredContent": data,
        },
    }


def trust(
    status: str,
    seal: str | None = None,
    agent: dict[str, Any] | None = None,
    **extra: Any,
) -> dict[str, Any]:
    """A get_trust answer. A shown one names the fixture agent by default."""
    if agent is None and status == "shown":
        agent = {"id": FIXTURE_AGENT["id"], "handle": FIXTURE_AGENT["handle"]}
    if agent is None and status in ("checking", "delisted"):
        agent = {
            "handle": FIXTURE_AGENT["handle"],
            "pageUrl": "https://sealkeeper.run/agents/alice/fixture",
        }
    return {
        "skill": "get-trust",
        "status": status,
        "agent": agent,
        "seal": seal,
        **extra,
    }


Reply = httpx.Response | Exception | Callable[[httpx.Request], httpx.Response]


def reply(
    status: int = 200, body: Any = None, headers: dict[str, str] | None = None
) -> httpx.Response:
    content = body if isinstance(body, bytes) else json.dumps(body).encode()
    return httpx.Response(
        status,
        content=content,
        headers={"content-type": "application/json", **(headers or {})},
    )


def answer(data: dict[str, Any]) -> httpx.Response:
    return reply(200, tool_result(data))


def from_record(name: str) -> httpx.Response:
    record = recorded(name)
    return reply(record["status"], record["body"], record["headers"])


@dataclass
class Server:
    """A recorded SealKeeper. Each URL answers its replies in order, the last
    one again once they run out, and every request is kept."""

    mcp: list[Reply] = field(default_factory=list)
    keys: list[Reply] = field(default_factory=lambda: [reply(200, FIXTURE_KEYS)])
    requests: list[httpx.Request] = field(default_factory=list)

    def handle(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        url = str(request.url)
        queue = self.mcp if url == MCP_URL else self.keys if url == KEYS_URL else None
        if not queue:
            raise AssertionError(f"no reply for {request.method} {url}")
        item = queue.pop(0) if len(queue) > 1 else queue[0]
        if isinstance(item, Exception):
            raise item
        response = item(request) if callable(item) else item
        # A fresh copy each time, so one reply serves any number of
        # requests from either kind of client.
        return httpx.Response(
            response.status_code, headers=response.headers, content=response.content
        )

    def of(self, url: str) -> list[httpx.Request]:
        return [r for r in self.requests if str(r.url) == url]

    def calls(self) -> list[dict[str, Any]]:
        return [json.loads(r.content) for r in self.of(MCP_URL)]


class Clock:
    def __init__(self, now: float) -> None:
        self.now = now

    def __call__(self) -> float:
        return self.now


class Sleeps:
    """Records each wait instead of waiting."""

    def __init__(self) -> None:
        self.waits: list[float] = []

    def __call__(self, seconds: float) -> None:
        self.waits.append(seconds)

    async def asleep(self, seconds: float) -> None:
        self.waits.append(seconds)


def sync_client(
    server: Server, clock: Clock, sleeps: Sleeps | None = None, **kw: Any
) -> SealKeeper:
    http = httpx.Client(transport=httpx.MockTransport(server.handle))
    return SealKeeper(http_client=http, clock=clock, sleep=sleeps or Sleeps(), **kw)


def async_client(
    server: Server, clock: Clock, sleeps: Sleeps | None = None, **kw: Any
) -> AsyncSealKeeper:
    http = httpx.AsyncClient(transport=httpx.MockTransport(server.handle))
    return AsyncSealKeeper(
        http_client=http, clock=clock, sleep=(sleeps or Sleeps()).asleep, **kw
    )


async def run(
    mode: str,
    server: Server,
    clock: Clock,
    method: str,
    *args: Any,
    sleeps: Sleeps | None = None,
    **kw: Any,
) -> Any:
    """Calls method on a sync or an async client over server."""
    if mode == "sync":
        return getattr(sync_client(server, clock, sleeps, **kw), method)(*args)
    return await getattr(async_client(server, clock, sleeps, **kw), method)(*args)
