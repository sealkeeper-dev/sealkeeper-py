"""The exceptions the library raises. Every one is a SealKeeperError."""

from __future__ import annotations


class SealKeeperError(Exception):
    """SealKeeper answered something this library cannot use."""


class BadTargetError(SealKeeperError):
    """SealKeeper refused the target or the input, with its line saying why."""


class UnavailableError(SealKeeperError):
    """SealKeeper could not be reached, timed out or asked to slow down."""


class SealBroken(SealKeeperError):
    """A SEAL that did not verify. reason is one of SEAL_BROKEN_REASONS."""

    def __init__(self, reason: str) -> None:
        super().__init__(f"broken SEAL: {reason}")
        self.reason = reason
