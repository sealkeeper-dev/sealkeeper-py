"""agent_id_from_did_key, checked against an independent encoder."""

from __future__ import annotations

import base64

import pytest

from sealkeeper import agent_id_from_did_key
from support import FIXTURE_AGENT, b64url

ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
# The agent ids of the two Ed25519 test vectors of RFC 8032.
VECTOR_IDS = [
    "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo",
    "PUAXw-hDiVqStwqnTRt-vJyYLM8uxJaMwM1V8Sr0Zgw",
]


def base58(raw: bytes) -> str:
    zeros = len(raw) - len(raw.lstrip(b"\x00"))
    n, out = int.from_bytes(raw, "big"), ""
    while n:
        n, digit = divmod(n, 58)
        out = ALPHABET[digit] + out
    return "1" * zeros + out


def key_bytes(agent_id: str) -> bytes:
    return base64.urlsafe_b64decode(agent_id + "=")


def did_of(agent_id: str) -> str:
    return "did:key:z" + base58(b"\xed\x01" + key_bytes(agent_id))


def test_reads_the_fixture_agent_did():
    assert agent_id_from_did_key(FIXTURE_AGENT["did"]) == FIXTURE_AGENT["id"]
    assert did_of(FIXTURE_AGENT["id"]) == FIXTURE_AGENT["did"]


def test_reads_the_example_of_the_seal_format():
    did = "did:key:z6Mkr73sdsBsqzmSrDUQPFHQAu5BewVajoLHyoG92ktE1xyf"
    assert agent_id_from_did_key(did) == "rR7dStS9oIU4l8V4C1OJdW2VzcjgTS3m2qjLLwm2NYI"


@pytest.mark.parametrize("agent_id", VECTOR_IDS)
def test_round_trips_a_test_vector(agent_id):
    did = did_of(agent_id)
    assert did.startswith("did:key:z6Mk")
    assert len(did) == len("did:key:z6Mk") + 44
    assert agent_id_from_did_key(did) == agent_id


@pytest.mark.parametrize("fill", [0x00, 0xFF])
def test_round_trips_the_lowest_and_highest_key(fill):
    agent_id = b64url(bytes([fill]) * 32)
    assert agent_id_from_did_key(did_of(agent_id)) == agent_id


_ID = VECTOR_IDS[0]
_DID = did_of(_ID)
_BODY = b"\xed\x01" + key_bytes(_ID)


@pytest.mark.parametrize(
    "value",
    [
        "did:key:z" + base58(b"\xe7\x01" + _BODY[2:]),
        "did:key:z" + base58(_BODY[:33]),
        "did:key:z" + base58(_BODY + b"\x00"),
        "did:key:z" + base58(b"\x00" + _BODY),
        _DID[:-1] + "0",
        "did:key:f" + _DID[len("did:key:z") :],
        _DID.replace("did:key:", "did:web:"),
        _DID + "\n",
        _ID,
        "",
        "did:key:z6Mk" + "2" * (10_000 - len("did:key:z6Mk")),
        None,
    ],
)
def test_reads_anything_else_as_no_did_key(value):
    assert agent_id_from_did_key(value) is None
