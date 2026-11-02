"""Every SEAL case of the reader fixtures, at the pinned clock and at now."""

from __future__ import annotations

import time

import pytest

from sealkeeper import SealBroken, read_keys, verify_with_keys
from support import FIXTURE_AGENT, FIXTURE_KEYS, INDEX, NOW_FROM, PINNED, seal_file

KEYS = read_keys(FIXTURE_KEYS)
SEAL_CASES = [c for c in INDEX["cases"] if c["kind"] == "seal"]
# The fixtures also hold handshakes and SEAL route answers, which this
# library does not read.
OTHER_KINDS = {"handshake", "read"}


def _verify(name: str, now: float) -> dict:
    try:
        seal = verify_with_keys(seal_file(name), KEYS, now, FIXTURE_AGENT["id"])
    except SealBroken as broken:
        return {"valid": False, "reason": broken.reason}
    return {"valid": True, "seal": seal}


def _check(case: dict, expected: dict, now: float) -> None:
    got = _verify(case["name"], now)
    assert got["valid"] is expected["valid"]
    if not expected["valid"]:
        assert got["reason"] == expected["reason"]
        return
    seal, payload = got["seal"], expected["payload"]
    assert seal.payload == payload
    assert seal.agent_id == payload["sub"]
    assert seal.level == payload["level"]
    assert seal.trust == payload.get("trust")
    assert seal.kind == payload.get("subject", {}).get("kind", "agent")
    assert (seal.issued_at, seal.expires_at) == (payload["iat"], payload["exp"])


def test_every_case_is_a_seal_or_a_kind_this_library_does_not_read():
    kinds = {c["kind"] for c in INDEX["cases"]}
    assert "seal" in kinds
    assert kinds - {"seal"} <= OTHER_KINDS


@pytest.mark.parametrize("case", SEAL_CASES, ids=lambda c: c["name"])
def test_a_seal_case_answers_as_the_index_says_at_the_pinned_clock(case):
    _check(case, case["expected"]["pinned"], PINNED)


@pytest.mark.parametrize("case", SEAL_CASES, ids=lambda c: c["name"])
def test_a_seal_case_answers_as_the_index_says_from_now_on(case):
    _check(case, case["expected"]["now"], NOW_FROM)
    _check(case, case["expected"]["now"], max(time.time(), NOW_FROM))
