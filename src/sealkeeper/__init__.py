"""Look up and verify SealKeeper SEALs, and gate calls on them."""

from ._version import __version__
from .client import AsyncSealKeeper, SealKeeper
from .errors import BadTargetError, SealBroken, SealKeeperError, UnavailableError
from .gate import BLOCK_CODES, PASS_CODES, Block, Gate, Pass
from .lookup import Lookup
from .seal import (
    SEAL_BROKEN_REASONS,
    SEAL_VERSIONS,
    VerifiedSeal,
    agent_id_from_did_key,
    read_keys,
    verify_with_keys,
)

__all__ = [
    "BLOCK_CODES",
    "PASS_CODES",
    "SEAL_BROKEN_REASONS",
    "SEAL_VERSIONS",
    "AsyncSealKeeper",
    "BadTargetError",
    "Block",
    "Gate",
    "Lookup",
    "Pass",
    "SealBroken",
    "SealKeeper",
    "SealKeeperError",
    "UnavailableError",
    "VerifiedSeal",
    "__version__",
    "agent_id_from_did_key",
    "read_keys",
    "verify_with_keys",
]
