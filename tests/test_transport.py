"""The requests both clients send and how they read every kind of answer."""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

import httpx
import pytest

from sealkeeper import (
    BadTargetError,
    SealKeeper,
    SealKeeperError,
    UnavailableError,
    __version__,
)
from support import (
    FIXTURE_AGENT,
    MCP_URL,
    MODES,
    Clock,
    Server,
    Sleeps,
    answer,
    from_record,
    reply,
    run,
    trust,
)

pytestmark = pytest.mark.anyio
CLOCK = Clock(1_790_856_000)
NOT_FOUND = trust("not_found", agent=None)


async def get_trust(mode: str, server: Server, target: str = "alice/helper", **kw):
    return await run(mode, server, CLOCK, "get_trust", target, **kw)


@pytest.mark.parametrize("mode", MODES)
async def test_sends_one_stateless_tools_call(mode):
    server = Server(mcp=[answer(NOT_FOUND)])
    assert await get_trust(mode, server) == NOT_FOUND
    [request] = server.requests
    assert request.method == "POST"
    assert str(request.url) == MCP_URL
    assert request.url.query == b""
    assert request.headers["content-type"] == "application/json"
    assert request.headers["accept"] == "application/json, text/event-stream"
    assert request.headers["mcp-protocol-version"] == "2025-11-25"
    assert request.headers["user-agent"] == f"sealkeeper-py/{__version__}"
    assert request.extensions["timeout"] == dict.fromkeys(
        ("connect", "read", "write", "pool"), 5.0
    )
    assert json.loads(request.content) == {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {"name": "get_trust", "arguments": {"agent": "alice/helper"}},
    }


@pytest.mark.parametrize("mode", MODES)
async def test_adds_a_wrapper_to_the_user_agent(mode):
    server = Server(mcp=[answer(NOT_FOUND)])
    await get_trust(mode, server, user_agent_suffix="langchain-sealkeeper/0.1.0")
    assert server.requests[0].headers["user-agent"] == (
        f"sealkeeper-py/{__version__} langchain-sealkeeper/0.1.0"
    )


@pytest.mark.parametrize("suffix", ["", "a\r\nX-Evil: 1", "é", "x" * 129, 3])
def test_refuses_a_user_agent_suffix_that_is_not_printable_words(suffix):
    with pytest.raises(ValueError):
        SealKeeper(user_agent_suffix=suffix)


@pytest.mark.parametrize("mode", MODES)
@pytest.mark.parametrize(
    "target",
    [
        "alice/helper",
        "https://sealkeeper.run/agents/alice/helper",
        "https://agents.example.com/.well-known/agent-card.json",
        "https://mcp.example.com/mcp",
        "https://[not-a-host/x",
    ],
)
async def test_sends_a_handle_or_a_url_as_given(mode, target):
    server = Server(mcp=[answer(NOT_FOUND)])
    await get_trust(mode, server, target)
    assert server.calls()[0]["params"]["arguments"] == {"agent": target}


@pytest.mark.parametrize("mode", MODES)
@pytest.mark.parametrize("target", [FIXTURE_AGENT["id"], FIXTURE_AGENT["did"]])
async def test_sends_an_agent_id_or_its_did_key_as_its_page_url(mode, target):
    server = Server(mcp=[answer(NOT_FOUND)])
    await get_trust(mode, server, target)
    page = f"https://sealkeeper.run/agents/{FIXTURE_AGENT['id']}"
    assert server.calls()[0]["params"]["arguments"] == {"agent": page}


@pytest.mark.parametrize("mode", MODES)
@pytest.mark.parametrize("target", ["", "   ", "did:key:z6MkNotAKey", None])
async def test_refuses_a_target_it_cannot_send_without_a_request(mode, target):
    server = Server(mcp=[answer(NOT_FOUND)])
    with pytest.raises(BadTargetError):
        await get_trust(mode, server, target)
    assert server.requests == []


@pytest.mark.parametrize("mode", MODES)
async def test_a_tool_error_is_a_bad_target_with_the_server_line(mode):
    server = Server(mcp=[from_record("get-trust-is-error")])
    with pytest.raises(BadTargetError, match=r"^agent: Too small"):
        await get_trust(mode, server)


@pytest.mark.parametrize("mode", MODES)
@pytest.mark.parametrize(
    ("record", "match"),
    [("unknown-tool", "Unknown tool"), ("query-400", "HTTP 400: Invalid query")],
)
async def test_a_json_rpc_error_or_a_400_is_raised(mode, record, match):
    server = Server(mcp=[from_record(record)])
    with pytest.raises(SealKeeperError, match=match) as raised:
        await get_trust(mode, server)
    assert type(raised.value) is SealKeeperError


@pytest.mark.parametrize("mode", MODES)
async def test_a_413_is_raised(mode):
    too_large = {
        "jsonrpc": "2.0",
        "id": None,
        "error": {"code": -32600, "message": "The request is larger than 17408 bytes"},
    }
    server = Server(mcp=[reply(413, too_large)])
    with pytest.raises(SealKeeperError, match="HTTP 413") as raised:
        await get_trust(mode, server)
    assert type(raised.value) is SealKeeperError


@pytest.mark.parametrize("mode", MODES)
@pytest.mark.parametrize(
    "body",
    [
        b"not json",
        b"[]",
        b'{"jsonrpc":"2.0","id":1}',
        b'{"jsonrpc":"2.0","id":1,"result":{"content":[]}}',
    ],
)
async def test_an_answer_that_is_no_tool_result_is_raised(mode, body):
    server = Server(mcp=[reply(200, body)])
    with pytest.raises(SealKeeperError) as raised:
        await get_trust(mode, server)
    assert type(raised.value) is SealKeeperError


@pytest.mark.parametrize("mode", MODES)
async def test_a_redirect_is_not_followed(mode):
    server = Server(mcp=[reply(302, b"", {"location": "https://elsewhere.example/"})])
    with pytest.raises(SealKeeperError, match="HTTP 302"):
        await get_trust(mode, server)
    assert len(server.requests) == 1


@pytest.mark.parametrize("mode", MODES)
@pytest.mark.parametrize("status", [500, 502, 503])
async def test_a_5xx_is_unavailable(mode, status):
    server = Server(mcp=[reply(status, b"")])
    with pytest.raises(UnavailableError):
        await get_trust(mode, server)


@pytest.mark.parametrize("mode", MODES)
@pytest.mark.parametrize(
    "error",
    [
        httpx.ReadTimeout("slow"),
        httpx.ConnectTimeout("slow"),
        httpx.ConnectError("refused"),
        httpx.RemoteProtocolError("cut"),
    ],
)
async def test_a_timeout_or_a_connection_error_is_unavailable(mode, error):
    server = Server(mcp=[error])
    with pytest.raises(UnavailableError):
        await get_trust(mode, server)


@pytest.mark.parametrize("mode", MODES)
async def test_an_answer_past_64_kb_is_refused(mode):
    server = Server(mcp=[reply(200, b" " * (64 * 1024 + 1))])
    with pytest.raises(SealKeeperError, match="larger than 65536"):
        await get_trust(mode, server)


@pytest.mark.parametrize("mode", MODES)
async def test_a_429_with_retry_after_waits_and_tries_once_more(mode):
    sleeps = Sleeps()
    limited = reply(429, {"error": {"code": "rate_limited"}}, {"retry-after": "2"})
    server = Server(mcp=[limited, answer(NOT_FOUND)])
    assert await get_trust(mode, server, sleeps=sleeps) == NOT_FOUND
    assert sleeps.waits == [2.0]
    assert len(server.requests) == 2


@pytest.mark.parametrize("mode", MODES)
async def test_a_second_429_is_unavailable(mode):
    sleeps = Sleeps()
    limited = reply(429, {"error": {"code": "rate_limited"}}, {"retry-after": "1"})
    server = Server(mcp=[limited, limited, answer(NOT_FOUND)])
    with pytest.raises(UnavailableError):
        await get_trust(mode, server, sleeps=sleeps)
    assert sleeps.waits == [1.0]
    assert len(server.requests) == 2


@pytest.mark.parametrize("mode", MODES)
@pytest.mark.parametrize(
    "headers",
    [{}, {"retry-after": "60"}, {"retry-after": "soon"}, {"retry-after": "-1"}],
)
async def test_a_429_without_a_short_retry_after_is_unavailable_at_once(mode, headers):
    sleeps = Sleeps()
    server = Server(
        mcp=[
            reply(429, {"error": {"code": "rate_limited"}}, headers),
            answer(NOT_FOUND),
        ]
    )
    with pytest.raises(UnavailableError):
        await get_trust(mode, server, sleeps=sleeps)
    assert sleeps.waits == []
    assert len(server.requests) == 1


@pytest.mark.parametrize("mode", MODES)
async def test_verify_seal_sends_the_seal_and_only_the_fields_given(mode):
    valid = {"valid": False, "reason": "malformed"}
    server = Server(mcp=[answer(valid)])
    assert await run(mode, server, CLOCK, "verify_seal", "a.b.c") == valid
    assert server.calls()[0]["params"] == {
        "name": "verify_seal",
        "arguments": {"seal": "a.b.c"},
    }


@pytest.mark.parametrize("mode", MODES)
async def test_verify_seal_writes_a_time_as_utc_with_milliseconds(mode):
    server = Server(mcp=[answer({"valid": False, "reason": "expired"})])
    at = datetime(2026, 10, 1, 14, 0, 0, 123456, tzinfo=timezone(timedelta(hours=2)))
    await run(mode, server, CLOCK, "verify_seal", "a.b.c", FIXTURE_AGENT["id"], at)
    assert server.calls()[0]["params"]["arguments"] == {
        "seal": "a.b.c",
        "agent": FIXTURE_AGENT["id"],
        "at": "2026-10-01T12:00:00.123Z",
    }


def test_verify_seal_refuses_a_time_with_no_time_zone():
    with pytest.raises(ValueError):
        SealKeeper().verify_seal("a.b.c", at=datetime(2026, 10, 1))
