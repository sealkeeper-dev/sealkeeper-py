"""lookup, every get_trust status and every reason a SEAL is missing."""

from __future__ import annotations

import pytest

from sealkeeper import Lookup, SealKeeperError
from support import (
    FIXTURE_AGENT,
    MODES,
    PINNED,
    PRODUCTION_KEYS,
    TEST_AGENT_CLOCK,
    TEST_AGENT_ID,
    Clock,
    Server,
    answer,
    from_record,
    reply,
    run,
    seal_file,
    trust,
)

pytestmark = pytest.mark.anyio
OTHER = "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"
HOLD_REASONS = [
    "fraud",
    "collusion",
    "safety",
    "operator_ban",
    "key_compromise",
    "failed_checks",
    "no_recent_check",
    "wallet_unproven_change",
    "price_above_declared",
    "mcp_hidden_text",
    "mcp_change_unresolved",
]


async def lookup(mode: str, data: dict, target: str = "alice/fixture") -> Lookup:
    return await run(mode, Server(mcp=[answer(data)]), Clock(PINNED), "lookup", target)


@pytest.mark.parametrize("mode", MODES)
async def test_verifies_the_recorded_test_agent_seal_with_the_production_keys(mode):
    server = Server(
        mcp=[from_record("get-trust-shown")], keys=[reply(200, PRODUCTION_KEYS)]
    )
    found = await run(
        mode, server, Clock(TEST_AGENT_CLOCK), "lookup", "sealkeeper/test-agent"
    )
    assert found.verified
    assert (found.status, found.kind, found.level, found.trust) == (
        "shown",
        "agent",
        "none",
        0,
    )
    assert found.seal.agent_id == TEST_AGENT_ID
    assert found.seal.payload["ver"] == 9
    assert found.handle == "sealkeeper/test-agent"


@pytest.mark.parametrize("mode", MODES)
@pytest.mark.parametrize(
    ("name", "kind"),
    [("v7-valid", "agent"), ("v7-service-valid", "service"), ("v6-valid", "agent")],
)
async def test_reads_kind_level_and_trust_from_the_verified_seal_only(mode, name, kind):
    unsigned = {
        "id": FIXTURE_AGENT["id"],
        "handle": "alice/fixture",
        "level": "gold",
        "trust": 9999,
        "subjectKind": "robot",
    }
    found = await lookup(mode, trust("shown", seal_file(name), agent=unsigned))
    assert (found.kind, found.level) == (kind, "bronze")
    assert found.trust in (412, 0)
    assert found.code is None


@pytest.mark.parametrize("mode", MODES)
async def test_a_broken_seal_is_no_seal_with_its_reason(mode):
    found = await lookup(mode, trust("shown", seal_file("v1-bad-signature")))
    assert not found.verified
    assert (found.code, found.broken) == ("broken", "bad_signature")
    assert (found.kind, found.level, found.trust, found.seal) == (
        None,
        None,
        None,
        None,
    )


@pytest.mark.parametrize("mode", MODES)
async def test_a_seal_for_another_agent_than_the_answer_names_is_wrong_agent(mode):
    found = await lookup(
        mode, trust("shown", seal_file("v7-valid"), agent={"id": OTHER})
    )
    assert found.broken == "wrong_agent"


@pytest.mark.parametrize("mode", MODES)
async def test_an_id_the_target_names_is_the_one_the_seal_must_be_for(mode):
    answered = trust("shown", seal_file("v7-valid"))
    assert (await lookup(mode, answered, FIXTURE_AGENT["did"])).verified
    assert (
        await lookup(
            mode, answered, f"https://sealkeeper.run/agents/{FIXTURE_AGENT['id']}"
        )
    ).verified
    assert (await lookup(mode, answered, OTHER)).broken == "wrong_agent"
    card = f"https://api.sealkeeper.run/v1/agents/{OTHER}/card"
    assert (await lookup(mode, answered, card)).broken == "wrong_agent"


@pytest.mark.parametrize("mode", MODES)
@pytest.mark.parametrize("status", ["checking", "delisted"])
async def test_a_listed_agent_not_shown_says_its_status(mode, status):
    found = await lookup(mode, trust(status))
    assert (found.status, found.code, found.verified) == (status, status, False)
    assert found.handle == "alice/fixture"


@pytest.mark.parametrize("mode", MODES)
async def test_the_recorded_not_found_answer_is_not_found(mode):
    server = Server(mcp=[from_record("get-trust-not-found")])
    found = await run(mode, server, Clock(PINNED), "lookup", "alice/no-such-agent")
    assert (found.status, found.code, found.handle) == ("not_found", "not_found", None)


@pytest.mark.parametrize("mode", MODES)
async def test_a_shown_answer_with_no_seal_and_nothing_more_is_unknown(mode):
    data = trust("shown", None)
    found = await lookup(mode, data)
    assert (found.code, found.raw) == ("unknown", data)


@pytest.mark.parametrize("mode", MODES)
@pytest.mark.parametrize("reason", HOLD_REASONS)
async def test_a_withheld_seal_says_its_reason_and_since(mode, reason):
    since = "2026-10-30T08:00:00.000Z"
    found = await lookup(
        mode,
        trust(
            "shown",
            None,
            withheld={"code": "withheld", "reason": reason, "since": since},
        ),
    )
    assert (found.code, found.reason, found.since, found.raw) == (
        "withheld",
        reason,
        since,
        None,
    )


@pytest.mark.parametrize("mode", MODES)
async def test_a_withheld_seal_with_no_since_or_a_new_reason_is_read_as_sent(mode):
    found = await lookup(
        mode,
        trust("shown", None, withheld={"code": "withheld", "reason": "a_new_reason"}),
    )
    assert (found.code, found.reason, found.since) == ("withheld", "a_new_reason", None)


@pytest.mark.parametrize("mode", MODES)
@pytest.mark.parametrize("days", [93, None, -1, "93"])
async def test_no_seal_says_how_long_the_agent_is_dormant(mode, days):
    found = await lookup(
        mode, trust("shown", None, withheld={"code": "no_seal", "dormant_days": days})
    )
    assert found.code == "no_seal"
    assert found.dormant_days == (93 if days == 93 else None)


@pytest.mark.parametrize("mode", MODES)
async def test_a_withheld_checking_code_is_checking(mode):
    found = await lookup(mode, trust("shown", None, withheld={"code": "checking"}))
    assert (found.status, found.code) == ("shown", "checking")


@pytest.mark.parametrize("mode", MODES)
@pytest.mark.parametrize(
    "withheld", [{"code": "frozen", "until": 1}, {"code": 7}, "withheld"]
)
async def test_a_withheld_code_it_does_not_know_comes_through_with_the_answer(
    mode, withheld
):
    data = trust("shown", None, withheld=withheld)
    found = await lookup(mode, data)
    assert found.code == (
        "frozen" if withheld == {"code": "frozen", "until": 1} else "unknown"
    )
    assert found.raw == data


@pytest.mark.parametrize("mode", MODES)
async def test_a_status_it_does_not_know_is_unknown_with_the_answer(mode):
    data = {"skill": "get-trust", "status": "paused", "agent": None, "seal": None}
    found = await lookup(mode, data)
    assert (found.status, found.code, found.raw) == ("paused", "unknown", data)


@pytest.mark.parametrize("mode", MODES)
@pytest.mark.parametrize(
    "data",
    [
        trust("shown", seal_file("v7-valid"), agent={"handle": "alice/fixture"}),
        trust("shown", 12),
    ],
)
async def test_a_shown_seal_with_no_agent_id_or_no_string_is_raised(mode, data):
    with pytest.raises(SealKeeperError):
        await lookup(mode, data)
