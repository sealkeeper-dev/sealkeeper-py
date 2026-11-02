"""The key copy behind verify. Kept five minutes, fetched again for an
unknown kid, and never used past its age when a fetch fails."""

from __future__ import annotations

import httpx
import pytest

from sealkeeper import SealBroken, UnavailableError, __version__
from support import (
    FIXTURE_AGENT,
    FIXTURE_KEYS,
    KEYS_URL,
    MODES,
    PINNED,
    TEST_KEYS,
    Clock,
    Server,
    async_client,
    key_document,
    reply,
    seal_file,
    sync_client,
)

pytestmark = pytest.mark.anyio
AGENT = FIXTURE_AGENT["id"]
ROTATED = {"keys": [key_document(TEST_KEYS)["keys"][0], *FIXTURE_KEYS["keys"]]}


class Verifier:
    """One client of either kind, kept across calls."""

    def __init__(self, mode: str, server: Server, clock: Clock) -> None:
        self.mode = mode
        maker = sync_client if mode == "sync" else async_client
        self.client = maker(server, clock)

    async def verify(self, seal: str, agent: str = AGENT):
        if self.mode == "sync":
            return self.client.verify(seal, agent)
        return await self.client.verify(seal, agent)


async def reason(verifier: Verifier, seal: str) -> str:
    with pytest.raises(SealBroken) as broken:
        await verifier.verify(seal)
    return broken.value.reason


@pytest.mark.parametrize("mode", MODES)
async def test_fetches_the_keys_from_sealkeeper_run_once_for_five_minutes(mode):
    server, clock = Server(), Clock(PINNED)
    verifier = Verifier(mode, server, clock)
    await verifier.verify(seal_file("v1-valid"))
    clock.now = PINNED + 299
    await verifier.verify(seal_file("v4-valid"))
    [request] = server.of(KEYS_URL)
    assert request.method == "GET"
    assert request.headers["user-agent"] == f"sealkeeper-py/{__version__}"
    clock.now = PINNED + 300
    await verifier.verify(seal_file("v1-valid"))
    assert len(server.of(KEYS_URL)) == 2


@pytest.mark.parametrize("mode", MODES)
async def test_a_copy_dated_after_now_is_fetched_again(mode):
    server, clock = Server(), Clock(PINNED)
    verifier = Verifier(mode, server, clock)
    await verifier.verify(seal_file("v1-valid"))
    clock.now = PINNED - 1
    await verifier.verify(seal_file("v1-valid"))
    assert len(server.of(KEYS_URL)) == 2


@pytest.mark.parametrize("mode", MODES)
async def test_an_unknown_kid_fetches_the_keys_again_once_then_is_unknown_kid(mode):
    server, clock = Server(), Clock(PINNED)
    verifier = Verifier(mode, server, clock)
    await verifier.verify(seal_file("v1-valid"))
    assert await reason(verifier, seal_file("v1-unknown-kid")) == "unknown_kid"
    assert len(server.of(KEYS_URL)) == 2


@pytest.mark.parametrize("mode", MODES)
async def test_a_kid_added_since_the_last_copy_is_found_by_fetching_again(mode):
    from support import payload_of, sign

    server = Server(keys=[reply(200, FIXTURE_KEYS), reply(200, ROTATED)])
    clock = Clock(PINNED)
    verifier = Verifier(mode, server, clock)
    await verifier.verify(seal_file("v1-valid"))
    fresh = sign(payload_of(seal_file("v4-valid")))
    assert (await verifier.verify(fresh)).trust == 412
    assert len(server.of(KEYS_URL)) == 2


@pytest.mark.parametrize("mode", MODES)
async def test_a_malformed_header_fetches_nothing(mode):
    server = Server()
    assert (
        await reason(Verifier(mode, server, Clock(PINNED)), "not a seal") == "malformed"
    )
    assert server.requests == []


@pytest.mark.parametrize("mode", MODES)
@pytest.mark.parametrize(
    "failure",
    [
        httpx.ConnectError("refused"),
        httpx.ReadTimeout("slow"),
        reply(503, b""),
        reply(404, b""),
        reply(200, b"not json"),
        reply(200, {"keys": []}),
    ],
)
async def test_with_no_copy_a_failed_fetch_is_unavailable(mode, failure):
    verifier = Verifier(mode, Server(keys=[failure]), Clock(PINNED))
    with pytest.raises(UnavailableError):
        await verifier.verify(seal_file("v1-valid"))


@pytest.mark.parametrize("mode", MODES)
async def test_an_older_copy_is_never_used_when_the_fetch_fails(mode):
    server = Server(keys=[reply(200, FIXTURE_KEYS), httpx.ConnectError("refused")])
    clock = Clock(PINNED)
    verifier = Verifier(mode, server, clock)
    await verifier.verify(seal_file("v1-valid"))
    clock.now = PINNED + 300
    with pytest.raises(UnavailableError):
        await verifier.verify(seal_file("v1-valid"))


@pytest.mark.parametrize("mode", MODES)
async def test_a_fresh_copy_and_a_failed_fetch_for_an_unknown_kid_is_unavailable(mode):
    server = Server(keys=[reply(200, FIXTURE_KEYS), httpx.ConnectError("refused")])
    verifier = Verifier(mode, server, Clock(PINNED))
    await verifier.verify(seal_file("v1-valid"))
    with pytest.raises(UnavailableError):
        await verifier.verify(seal_file("v1-unknown-kid"))


@pytest.mark.parametrize("mode", MODES)
async def test_the_expected_agent_may_be_a_did_key(mode):
    verifier = Verifier(mode, Server(), Clock(PINNED))
    seal = await verifier.verify(seal_file("v1-valid"), FIXTURE_AGENT["did"])
    assert seal.agent_id == AGENT


@pytest.mark.parametrize("mode", MODES)
@pytest.mark.parametrize("agent", ["alice/fixture", "did:key:z6MkNotAKey", None])
async def test_an_expected_agent_that_is_no_id_is_a_value_error(mode, agent):
    with pytest.raises(ValueError):
        await Verifier(mode, Server(), Clock(PINNED)).verify(
            seal_file("v1-valid"), agent
        )
