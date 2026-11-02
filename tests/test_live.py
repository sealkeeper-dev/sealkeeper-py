"""Against production, only with SEALKEEPER_LIVE=1. Read only."""

from __future__ import annotations

import base64
import os

import pytest

from sealkeeper import SealBroken, SealKeeper
from support import b64url

pytestmark = [
    pytest.mark.live,
    pytest.mark.skipif(
        os.environ.get("SEALKEEPER_LIVE") != "1", reason="set SEALKEEPER_LIVE=1"
    ),
]


def _flip_one_signature_byte(seal: str) -> str:
    head, body, sig = seal.split(".")
    raw = bytearray(base64.urlsafe_b64decode(sig + "=="))
    raw[0] ^= 1
    return f"{head}.{body}.{b64url(bytes(raw))}"


def test_the_test_agent_seal_verifies_and_one_changed_byte_breaks_it():
    with SealKeeper() as sk:
        found = sk.lookup("sealkeeper/test-agent")
        assert found.verified
        assert (found.kind, found.level) == ("agent", "none")
        seal = sk.get_trust("sealkeeper/test-agent")["seal"]
        assert sk.verify(seal, found.seal.agent_id).agent_id == found.seal.agent_id
        with pytest.raises(SealBroken) as broken:
            sk.verify(_flip_one_signature_byte(seal), found.seal.agent_id)
        assert broken.value.reason == "bad_signature"
