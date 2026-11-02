"""Gate, every rule of a pass and a block, sync and async, and its cache."""

from __future__ import annotations

import logging
import re
from pathlib import Path

import httpx
import pytest

from sealkeeper import BLOCK_CODES, PASS_CODES, SEAL_BROKEN_REASONS, Block, Gate, Pass
from sealkeeper import gate as gate_module
from support import (
    FIXTURE_AGENT,
    MODES,
    PINNED,
    PRODUCTION_KEYS,
    TEST_AGENT_CLOCK,
    TEST_KEYS,
    Clock,
    Server,
    answer,
    async_client,
    from_record,
    key_document,
    payload_of,
    reply,
    seal_file,
    sign,
    sync_client,
    trust,
)

pytestmark = pytest.mark.anyio
AGENT_SEAL = seal_file("v7-valid")
SERVICE_SEAL = seal_file("v7-service-valid")
LISTED_SEAL = seal_file("v7-listed-x402-valid")
SERVICE_URL = "https://pay.example.com/.well-known/x402"
CARD_URL = "https://agents.example.com/.well-known/agent-card.json"
README = Path(__file__).parent.parent / "README.md"


class Checker:
    """A gate over server, checked the sync or the async way."""

    def __init__(
        self, mode: str, server: Server, clock: Clock | None = None, **kw
    ) -> None:
        self.mode = mode
        self.clock = clock or Clock(PINNED)
        self.gate = Gate(
            client=sync_client(server, self.clock),
            async_client=async_client(server, self.clock),
            clock=self.clock,
            **kw,
        )

    async def check(self, target: str, kind: str = "agent"):
        if self.mode == "sync":
            return self.gate.check(target, kind)
        return await self.gate.acheck(target, kind)


async def decide(
    mode: str, data: dict, target: str = "alice/fixture", kind: str = "agent", **kw
):
    return await Checker(mode, Server(mcp=[answer(data)]), **kw).check(target, kind)


@pytest.mark.parametrize("mode", MODES)
async def test_a_current_bronze_seal_of_the_kind_passes(mode):
    decision = await decide(mode, trust("shown", AGENT_SEAL))
    assert isinstance(decision, Pass)
    assert (decision.passed, decision.code, decision.seal.level) == (
        True,
        "sealed",
        "bronze",
    )


@pytest.mark.parametrize("mode", MODES)
@pytest.mark.parametrize("name", ["v4-valid", "v6-valid"])
async def test_a_seal_from_before_subject_passes_as_an_agent(mode, name):
    assert (await decide(mode, trust("shown", seal_file(name)))).code == "sealed"
    assert (
        await decide(mode, trust("shown", seal_file(name)), kind="service")
    ).code == "wrong_kind"


@pytest.mark.parametrize("mode", MODES)
async def test_the_other_kind_blocks_as_wrong_kind(mode):
    decision = await decide(mode, trust("shown", SERVICE_SEAL), kind="agent")
    assert isinstance(decision, Block)
    assert (decision.passed, decision.code) == (False, "wrong_kind")
    assert decision.reason == "it holds a Service SEAL, not an Agent SEAL"


@pytest.mark.parametrize("mode", MODES)
async def test_level_none_blocks_as_below_bronze(mode):
    server = Server(
        mcp=[from_record("get-trust-shown")], keys=[reply(200, PRODUCTION_KEYS)]
    )
    checker = Checker(mode, server, Clock(TEST_AGENT_CLOCK))
    assert (await checker.check("sealkeeper/test-agent")).code == "below_bronze"


@pytest.mark.parametrize("mode", MODES)
@pytest.mark.parametrize(
    ("target", "seal", "kind"),
    [
        (SERVICE_URL, SERVICE_SEAL, "service"),
        ("https://PAY.Example.COM/.well-known/x402", SERVICE_SEAL, "service"),
        (CARD_URL, LISTED_SEAL, "agent"),
    ],
)
async def test_a_url_target_passes_when_the_seal_names_that_url(
    mode, target, seal, kind
):
    assert (await decide(mode, trust("shown", seal), target, kind)).code == "sealed"


@pytest.mark.parametrize("mode", MODES)
@pytest.mark.parametrize(
    ("target", "seal"),
    [
        ("https://pay.example.com/.well-known/X402", SERVICE_SEAL),
        ("https://pay.example.com/.well-known/x402/", SERVICE_SEAL),
        ("http://pay.example.com/.well-known/x402", SERVICE_SEAL),
        ("https://other.example.com/.well-known/x402", SERVICE_SEAL),
        (SERVICE_URL, AGENT_SEAL),
    ],
)
async def test_a_url_target_blocks_when_the_seal_names_another_or_none(
    mode, target, seal
):
    assert (
        await decide(mode, trust("shown", seal), target, "service")
    ).code == "wrong_url"


@pytest.mark.parametrize("mode", MODES)
@pytest.mark.parametrize(
    "target", ["https://mcp.example.com", "https://MCP.example.com/"]
)
async def test_an_origin_alone_reads_as_its_root(mode, target):
    service = payload_of(SERVICE_SEAL) | {
        "ver": 8,
        "subject": {"kind": "service", "interfaces": ["mcp"], "paid": False},
        "listing": {
            "handle": "example.com/mcp",
            "domain_key": "example.com",
            "card_url": "https://mcp.example.com/",
        },
    }
    server = Server(
        mcp=[answer(trust("shown", sign(service)))],
        keys=[reply(200, key_document(TEST_KEYS))],
    )
    assert (await Checker(mode, server).check(target, "service")).code == "sealed"


@pytest.mark.parametrize("mode", MODES)
@pytest.mark.parametrize(
    "target",
    [
        "https://sealkeeper.run/agents/alice/fixture",
        f"https://sealkeeper.run/agents/{FIXTURE_AGENT['id']}",
        f"https://api.sealkeeper.run/v1/agents/{FIXTURE_AGENT['id']}/card",
    ],
)
async def test_a_sealkeeper_page_or_card_url_needs_no_listing(mode, target):
    assert (await decide(mode, trust("shown", AGENT_SEAL), target)).code == "sealed"


@pytest.mark.parametrize("mode", MODES)
async def test_a_broken_seal_blocks_with_its_reason(mode):
    decision = await decide(mode, trust("shown", seal_file("v1-bad-signature")))
    assert decision.code == "bad_signature"
    expired = await decide(mode, trust("shown", seal_file("v1-expired")))
    assert expired.code == "expired"


UNSEALED = [
    ("not_found", trust("not_found", agent=None)),
    ("checking", trust("checking")),
    ("checking", trust("shown", None, withheld={"code": "checking"})),
    ("no_seal", trust("shown", None, withheld={"code": "no_seal", "dormant_days": 93})),
]
ALWAYS_BLOCKED = [
    (
        "withheld",
        trust("shown", None, withheld={"code": "withheld", "reason": "fraud"}),
    ),
    (
        "withheld",
        trust(
            "shown",
            None,
            withheld={
                "code": "withheld",
                "reason": "failed_checks",
                "since": "2026-10-30T08:00:00.000Z",
            },
        ),
    ),
    ("delisted", trust("delisted")),
    ("unknown", trust("shown", None)),
    ("unknown", trust("shown", None, withheld={"code": "frozen"})),
    ("unknown", {"skill": "get-trust", "status": "paused"}),
]


@pytest.mark.parametrize("mode", MODES)
@pytest.mark.parametrize(("code", "data"), UNSEALED + ALWAYS_BLOCKED)
async def test_no_seal_blocks_with_its_code(mode, code, data):
    decision = await decide(mode, data)
    assert (decision.passed, decision.code) == (False, code)


@pytest.mark.parametrize("mode", MODES)
@pytest.mark.parametrize(("code", "data"), UNSEALED)
async def test_allow_unsealed_lets_through_not_found_checking_and_no_seal(
    mode, code, data
):
    decision = await decide(mode, data, allow_unsealed=True)
    assert decision == Pass(code)
    assert decision.seal is None


@pytest.mark.parametrize("mode", MODES)
@pytest.mark.parametrize(("code", "data"), ALWAYS_BLOCKED)
async def test_allow_unsealed_still_blocks_the_rest(mode, code, data):
    assert (await decide(mode, data, allow_unsealed=True)).code == code


@pytest.mark.parametrize("mode", MODES)
async def test_allow_unsealed_still_blocks_a_broken_seal(mode):
    data = trust("shown", seal_file("v1-unknown-kid"))
    assert (await decide(mode, data, allow_unsealed=True)).code == "unknown_kid"


@pytest.mark.parametrize("mode", MODES)
@pytest.mark.parametrize(
    ("server", "code"),
    [
        (lambda: Server(mcp=[reply(503, b"")]), "unavailable"),
        (lambda: Server(mcp=[httpx.ConnectError("refused")]), "unavailable"),
        (
            lambda: Server(
                mcp=[answer(trust("shown", AGENT_SEAL))],
                keys=[httpx.ConnectError("refused")],
            ),
            "unavailable",
        ),
        (lambda: Server(mcp=[from_record("get-trust-is-error")]), "bad_target"),
        (lambda: Server(mcp=[from_record("unknown-tool")]), "error"),
        (lambda: Server(mcp=[RuntimeError("boom")]), "error"),
    ],
)
async def test_a_failure_blocks_and_never_raises(mode, server, code):
    decision = await Checker(mode, server()).check("alice/fixture")
    assert decision.code == code


@pytest.mark.parametrize("mode", MODES)
async def test_unavailable_blocks_even_with_allow_unsealed(mode):
    checker = Checker(mode, Server(mcp=[reply(503, b"")]), allow_unsealed=True)
    assert (await checker.check("alice/fixture")).code == "unavailable"


@pytest.mark.parametrize("mode", MODES)
async def test_a_bad_target_blocks_with_the_server_line(mode):
    decision = await Checker(
        mode, Server(mcp=[from_record("get-trust-is-error")])
    ).check(" ")
    assert decision.code == "bad_target"
    decision = await Checker(
        mode, Server(mcp=[from_record("get-trust-is-error")])
    ).check("x")
    assert decision.reason.startswith("agent: Too small")


@pytest.mark.parametrize("mode", MODES)
@pytest.mark.parametrize("kind", ["robot", "", None, "Agent"])
async def test_a_kind_other_than_agent_or_service_is_a_value_error(mode, kind):
    with pytest.raises(ValueError):
        await Checker(mode, Server()).check("alice/fixture", kind)


@pytest.mark.parametrize("ttl", [-1, 86401, True, "300", None])
def test_cache_ttl_must_be_0_to_86400_seconds(ttl):
    with pytest.raises(ValueError):
        Gate(cache_ttl=ttl)


@pytest.mark.parametrize("mode", MODES)
async def test_a_lookup_is_kept_for_cache_ttl_seconds(mode):
    server = Server(mcp=[answer(trust("shown", AGENT_SEAL))])
    checker = Checker(mode, server, cache_ttl=60)
    assert (await checker.check("alice/fixture")).code == "sealed"
    checker.clock.now += 59
    assert (await checker.check("alice/fixture", "service")).code == "wrong_kind"
    assert len(server.calls()) == 1
    checker.clock.now += 1
    await checker.check("alice/fixture")
    assert len(server.calls()) == 2


@pytest.mark.parametrize("mode", MODES)
async def test_the_cache_is_keyed_by_target(mode):
    server = Server(mcp=[answer(trust("shown", AGENT_SEAL))])
    checker = Checker(mode, server)
    await checker.check("alice/fixture")
    await checker.check(f"https://sealkeeper.run/agents/{FIXTURE_AGENT['id']}")
    assert len(server.calls()) == 2


@pytest.mark.parametrize("mode", MODES)
async def test_a_kept_seal_is_checked_against_exp_on_every_use(mode):
    exp = payload_of(AGENT_SEAL)["exp"]
    server = Server(mcp=[answer(trust("shown", AGENT_SEAL))])
    checker = Checker(mode, server, cache_ttl=86400)
    assert (await checker.check("alice/fixture")).code == "sealed"
    checker.clock.now = exp
    assert (await checker.check("alice/fixture")).code == "expired"
    assert len(server.calls()) == 2


@pytest.mark.parametrize("mode", MODES)
@pytest.mark.parametrize(
    "failure",
    [
        reply(503, b""),
        httpx.ReadTimeout("slow"),
        from_record("unknown-tool"),
        from_record("get-trust-is-error"),
    ],
)
async def test_a_failure_is_never_kept(mode, failure):
    server = Server(mcp=[failure, answer(trust("shown", AGENT_SEAL))])
    checker = Checker(mode, server)
    assert not (await checker.check("alice/fixture")).passed
    assert (await checker.check("alice/fixture")).code == "sealed"
    assert len(server.calls()) == 2


@pytest.mark.parametrize("mode", MODES)
async def test_an_answer_with_no_seal_is_kept(mode):
    server = Server(mcp=[answer(trust("not_found", agent=None))])
    checker = Checker(mode, server)
    await checker.check("alice/fixture")
    await checker.check("alice/fixture")
    assert len(server.calls()) == 1


@pytest.mark.parametrize("mode", MODES)
async def test_cache_ttl_0_keeps_nothing(mode):
    server = Server(mcp=[answer(trust("shown", AGENT_SEAL))])
    checker = Checker(mode, server, cache_ttl=0)
    await checker.check("alice/fixture")
    await checker.check("alice/fixture")
    assert len(server.calls()) == 2


@pytest.mark.parametrize("mode", MODES)
async def test_the_oldest_target_goes_once_the_cache_is_full(mode, monkeypatch):
    monkeypatch.setattr(gate_module, "CACHE_MAX_ENTRIES", 2)
    server = Server(mcp=[answer(trust("not_found", agent=None))])
    checker = Checker(mode, server)
    for target in ("a/one", "a/two", "a/three", "a/two", "a/one"):
        await checker.check(target)
    assert [c["params"]["arguments"]["agent"] for c in server.calls()] == [
        "a/one",
        "a/two",
        "a/three",
        "a/one",
    ]


@pytest.mark.parametrize("mode", MODES)
async def test_logs_one_line_per_decision_with_the_handle(mode, caplog):
    caplog.set_level(logging.INFO, logger="sealkeeper")
    checker = Checker(mode, Server(mcp=[answer(trust("shown", AGENT_SEAL))]))
    await checker.check("alice/fixture")
    await checker.check("alice/fixture", "service")
    lines = [(r.name, r.levelname, r.getMessage()) for r in caplog.records]
    assert lines == [
        ("sealkeeper", "INFO", "gate pass sealed kind=agent agent=alice/fixture"),
        (
            "sealkeeper",
            "INFO",
            "gate block wrong_kind kind=service agent=alice/fixture",
        ),
    ]


@pytest.mark.parametrize("mode", MODES)
async def test_the_log_names_a_url_by_its_host_alone_and_never_the_seal(mode, caplog):
    caplog.set_level(logging.DEBUG)
    secret_url = "https://user:pw@mcp.example.com/mcp/token-abc123?key=s3cret"
    for server in (
        Server(mcp=[answer(trust("not_found", agent=None))]),
        Server(
            mcp=[
                answer(trust("shown", SERVICE_SEAL, agent={"id": FIXTURE_AGENT["id"]}))
            ]
        ),
        Server(mcp=[reply(503, b"")]),
    ):
        await Checker(mode, server).check(secret_url, "service")
    text = "\n".join(
        r.getMessage() for r in caplog.records if r.name.startswith("sealkeeper")
    )
    assert text.count("host=mcp.example.com") == 3
    for leak in (
        "token-abc123",
        "s3cret",
        "pw@",
        "/mcp",
        SERVICE_SEAL.split(".")[1][:40],
        SERVICE_SEAL.split(".")[2],
    ):
        assert leak not in text


def test_every_block_and_pass_code_is_in_the_readme():
    readme = README.read_text()
    for code in (
        BLOCK_CODES[: -len(SEAL_BROKEN_REASONS)] + SEAL_BROKEN_REASONS + PASS_CODES
    ):
        assert re.search(rf"`{code}`", readme), code
    assert BLOCK_CODES[-len(SEAL_BROKEN_REASONS) :] == SEAL_BROKEN_REASONS
    assert len(set(BLOCK_CODES)) == len(BLOCK_CODES)
