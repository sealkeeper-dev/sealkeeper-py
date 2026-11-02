"""verify_with_keys, each step of verification and the shape it reads."""

from __future__ import annotations

import base64
import json

import pytest

from sealkeeper import SEAL_VERSIONS, SealBroken, read_keys, verify_with_keys
from support import FIXTURE_AGENT, TEST_KEYS, b64url, seal_file, sign

AGENT = FIXTURE_AGENT["id"]
OTHER = "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"
NOW = 1_790_856_000
DROP = object()


def payload(version: int = 9, **fields: object) -> dict:
    """The fields this library reads at version, valid at NOW, with fields
    over them. DROP leaves a field out."""
    p: dict = {
        "iss": "sealkeeper.run",
        "sub": AGENT,
        "ver": version,
        "iat": NOW - 60,
        "exp": NOW - 60 + 86400,
        "level": "bronze",
    }
    if version >= 4:
        p["trust"] = 7
    if version >= 7:
        p["subject"] = {"kind": "agent"}
    p.update(fields)
    return {k: v for k, v in p.items() if v is not DROP}


def reason(
    seal: object, now: float = NOW, agent: str = AGENT, keys=TEST_KEYS
) -> str | None:
    try:
        verify_with_keys(seal, keys, now, agent)
    except SealBroken as broken:
        return broken.reason
    return None


@pytest.mark.parametrize("ver", SEAL_VERSIONS)
def test_reads_every_version_it_knows(ver):
    seal = verify_with_keys(sign(payload(ver)), TEST_KEYS, NOW, AGENT)
    assert seal.level == "bronze"
    assert seal.kind == "agent"
    assert seal.trust == (7 if ver >= 4 else None)


@pytest.mark.parametrize("ver", [0, 10, "9", True, None, 9.5, DROP])
def test_refuses_a_version_it_does_not_know(ver):
    assert reason(sign(payload(ver=ver))) == "unsupported_version"


def test_reads_a_whole_number_written_with_a_point():
    seal = verify_with_keys(
        sign(payload(ver=9.0, iat=NOW - 60.0)), TEST_KEYS, NOW, AGENT
    )
    assert seal.issued_at == NOW - 60


@pytest.mark.parametrize(
    "header",
    [
        {"alg": "none", "kid": "test-1"},
        {"alg": "EdDSA"},
        {"alg": "EdDSA", "kid": ""},
        {"alg": "EdDSA", "kid": "k" * 129},
        {"alg": "EdDSA", "kid": "test-1", "typ": "JWT"},
        {"alg": "EdDSA", "kid": 1},
        ["EdDSA", "test-1"],
    ],
)
def test_a_header_other_than_alg_and_kid_is_malformed(header):
    assert reason(sign(payload(), header=header)) == "malformed"


@pytest.mark.parametrize(
    "seal",
    ["", "a.b", "a.b.c.d", "a..c", "a.b.c=", "a b.c.d", None, 12, "x" * 262145],
)
def test_anything_but_three_base64url_parts_is_malformed(seal):
    assert reason(seal) == "malformed"


def test_surrounding_whitespace_is_dropped():
    assert reason(f"  {sign(payload())}\n") is None


def test_a_kid_not_among_the_keys_is_unknown_kid():
    assert reason(sign(payload(), kid="test-9")) == "unknown_kid"


def test_the_key_is_found_by_kid_not_by_position():
    keys = read_keys(
        {
            "keys": [
                {
                    "kid": "a",
                    "kty": "OKP",
                    "crv": "Ed25519",
                    "alg": "EdDSA",
                    "x": OTHER,
                },
                {
                    "kid": "test-1",
                    "kty": "OKP",
                    "crv": "Ed25519",
                    "alg": "EdDSA",
                    "x": TEST_KEYS["test-1"],
                },
            ]
        }
    )
    assert reason(sign(payload()), keys=keys) is None


def _flip_signature(seal: str) -> str:
    head, body, sig = seal.split(".")
    raw = bytearray(base64.urlsafe_b64decode(sig + "=="))
    raw[0] ^= 1
    return f"{head}.{body}.{b64url(bytes(raw))}"


def test_one_changed_byte_of_the_signature_is_bad_signature():
    assert reason(_flip_signature(sign(payload()))) == "bad_signature"


def test_a_changed_payload_is_bad_signature_before_any_time_check():
    head, _, sig = sign(payload()).split(".")
    other = b64url(json.dumps(payload(level="gold")).encode())
    assert reason(f"{head}.{other}.{sig}", now=0) == "bad_signature"


def test_a_signature_of_the_wrong_length_is_bad_signature():
    head, body, _ = sign(payload()).split(".")
    assert reason(f"{head}.{body}.{b64url(bytes(63))}") == "bad_signature"


def test_a_signed_payload_that_is_not_json_is_malformed():
    assert reason(sign(b"not json")) == "malformed"
    assert reason(sign(b'{"ver": NaN}')) == "malformed"


def test_a_byte_order_mark_before_the_payload_is_read_past():
    assert reason(sign(b"\xef\xbb\xbf" + json.dumps(payload()).encode())) is None


@pytest.mark.parametrize("iss", ["vouched.dev", None, 1, DROP])
def test_another_issuer_is_wrong_issuer(iss):
    assert reason(sign(payload(iss=iss))) == "wrong_issuer"


def test_a_payload_that_is_not_an_object_is_wrong_issuer():
    assert reason(sign([1, 2])) == "wrong_issuer"


def test_the_issuer_comes_before_the_version_and_the_shape():
    assert reason(sign(payload(iss="x", ver=99, level="platinum"))) == "wrong_issuer"


def test_the_old_issuer_counts_only_before_2_october_2026():
    old = sign(payload(iss="vouched.run", iat=1790890000, exp=1790900000))
    assert reason(old, now=1790899199) is None
    assert reason(old, now=1790899200) == "wrong_issuer"


@pytest.mark.parametrize(
    "fields",
    [
        {"sub": "not-an-id"},
        {"sub": DROP},
        {"level": "platinum"},
        {"level": DROP},
        {"iat": -1},
        {"iat": "now"},
        {"exp": NOW - 60},
        {"exp": NOW - 60 + 86401},
        {"exp": 2**53},
        {"trust": -1},
        {"trust": DROP},
        {"trust": 1.5},
        {"subject": DROP},
        {"subject": {"kind": "robot"}},
        {"subject": "agent"},
        {"listing": {"handle": "a/b"}},
        {"listing": {"card_url": "ftp://example.com/card"}},
    ],
)
def test_a_field_this_library_reads_with_the_wrong_shape_is_malformed(fields):
    assert reason(sign(payload(**fields))) == "malformed"


@pytest.mark.parametrize(
    ("ver", "field", "value"),
    [
        (3, "trust", 1),
        (6, "subject", {"kind": "agent"}),
        (4, "listing", {"card_url": "https://x.example/"}),
    ],
)
def test_a_field_from_before_its_version_is_malformed(ver, field, value):
    assert reason(sign(payload(ver, **{field: value}))) == "malformed"


def test_a_seal_before_version_7_is_an_agents():
    assert verify_with_keys(sign(payload(6)), TEST_KEYS, NOW, AGENT).kind == "agent"


def test_a_service_seal_reads_its_kind():
    seal = sign(
        payload(subject={"kind": "service", "interfaces": ["mcp"], "paid": False})
    )
    assert verify_with_keys(seal, TEST_KEYS, NOW, AGENT).kind == "service"


def test_a_field_this_library_does_not_read_is_not_checked():
    assert reason(sign(payload(counts="anything"))) is None


def test_exp_must_be_a_whole_second_ahead():
    seal = sign(payload(iat=NOW - 100, exp=NOW + 1))
    assert reason(seal, now=NOW) is None
    assert reason(seal, now=NOW + 0.5) == "expired"
    assert reason(seal, now=NOW + 1) == "expired"


def test_iat_may_be_at_most_300_seconds_ahead():
    assert reason(sign(payload(iat=NOW + 300, exp=NOW + 1000))) is None
    assert reason(sign(payload(iat=NOW + 301, exp=NOW + 1000))) == "not_yet_valid"


def test_expiry_comes_before_iat_and_sub():
    assert reason(sign(payload(iat=NOW - 1000, exp=NOW - 10)), agent=OTHER) == "expired"


def test_a_valid_seal_for_another_agent_is_wrong_agent():
    assert reason(sign(payload()), agent=OTHER) == "wrong_agent"


def test_the_payload_is_kept_out_of_the_repr():
    seal = verify_with_keys(sign(payload()), TEST_KEYS, NOW, AGENT)
    assert "sealkeeper.run" not in repr(seal)


def test_is_current_reads_exp_against_the_clock():
    seal = verify_with_keys(sign(payload(exp=NOW + 10)), TEST_KEYS, NOW, AGENT)
    assert seal.is_current(NOW + 9)
    assert not seal.is_current(NOW + 9.5)


def test_read_keys_keeps_only_ed25519_keys_and_the_first_of_a_kid():
    good = {"kid": "k1", "kty": "OKP", "crv": "Ed25519", "alg": "EdDSA", "x": AGENT}
    keys = read_keys(
        {
            "keys": [
                good,
                {**good, "x": OTHER},
                {**good, "kid": "k2", "crv": "X25519"},
                {**good, "kid": "k3", "x": "short"},
                "not a key",
            ]
        }
    )
    assert keys == {"k1": AGENT}


@pytest.mark.parametrize(
    "doc", [None, [], {"keys": []}, {"keys": "k1"}, {"keys": [{"kid": "k1"}]}]
)
def test_read_keys_refuses_a_document_with_no_usable_key(doc):
    with pytest.raises(ValueError):
        read_keys(doc)


def test_the_fixture_seal_checks_out_with_the_fixture_keys_only():
    assert reason(seal_file("v1-valid"), now=1790856000) == "unknown_kid"
