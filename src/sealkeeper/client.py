"""SealKeeper and AsyncSealKeeper, the two clients. They only do I/O.

Every request and every answer goes through _protocol, and every SEAL
through seal.verify_with_keys, so both clients behave the same.
"""

from __future__ import annotations

import asyncio
import time
from collections.abc import AsyncIterator, Awaitable, Callable, Iterator, Mapping
from datetime import datetime
from typing import Any

import httpx

from . import _protocol as p
from .errors import SealBroken, SealKeeperError, UnavailableError
from .lookup import Lookup, lookup_of, seal_to_check
from .seal import (
    DID_KEY_PREFIX,
    VerifiedSeal,
    agent_id_from_did_key,
    is_agent_id,
    read_keys,
    seal_kid,
    verify_with_keys,
)

Clock = Callable[[], float]
_Answer = tuple[int, Mapping[str, str], bytes]


def _expected_id(expected_agent_id: str) -> str:
    """The raw agent id, from an agent id or its did:key."""
    agent_id: object = expected_agent_id
    if isinstance(agent_id, str) and agent_id.startswith(DID_KEY_PREFIX):
        agent_id = agent_id_from_did_key(agent_id)
    if not is_agent_id(agent_id):
        raise ValueError("expected_agent_id must be an agent id or its did:key")
    return agent_id


def _keys_of(status: int, body: bytes) -> dict[str, str]:
    try:
        return read_keys(p.read_keys_answer(status, body))
    except ValueError as error:
        raise UnavailableError(f"could not use the SealKeeper keys, {error}") from None


def _too_large() -> SealKeeperError:
    return SealKeeperError(
        f"SealKeeper's answer is larger than {p.ANSWER_MAX_BYTES} bytes"
    )


def _timed_out() -> UnavailableError:
    return UnavailableError(
        f"SealKeeper did not answer within {p.TIMEOUT_SECONDS} seconds"
    )


def _unreachable(error: Exception) -> UnavailableError:
    return UnavailableError(f"could not reach SealKeeper, {type(error).__name__}")


def _read_capped(chunks: Iterator[bytes], deadline: float) -> bytes:
    body = bytearray()
    for chunk in chunks:
        body += chunk
        if len(body) > p.ANSWER_MAX_BYTES:
            raise _too_large()
        if time.monotonic() > deadline:
            raise _timed_out()
    return bytes(body)


async def _aread_capped(chunks: AsyncIterator[bytes], deadline: float) -> bytes:
    body = bytearray()
    async for chunk in chunks:
        body += chunk
        if len(body) > p.ANSWER_MAX_BYTES:
            raise _too_large()
        if time.monotonic() > deadline:
            raise _timed_out()
    return bytes(body)


class SealKeeper:
    """Reads trust from SealKeeper and verifies SEALs, one blocking call each.

    http_client is an httpx.Client to send through, for a caller's own
    transport or a test. One is made and closed with the client when none
    is given. clock answers Unix seconds and decides whether a SEAL is
    current. user_agent_suffix is added to the User-Agent, such as
    "langchain-sealkeeper/0.1.0". sleep waits before the one retry of a 429.
    """

    def __init__(
        self,
        *,
        http_client: httpx.Client | None = None,
        clock: Clock | None = None,
        user_agent_suffix: str | None = None,
        sleep: Callable[[float], None] | None = None,
    ) -> None:
        agent = p.user_agent(user_agent_suffix)
        self._mcp_headers = p.mcp_headers(agent)
        self._keys_headers = p.keys_headers(agent)
        self._owns_http = http_client is None
        self._http = http_client if http_client is not None else httpx.Client()
        self.clock: Clock = clock if clock is not None else time.time
        self._sleep = sleep if sleep is not None else time.sleep
        self._keys = p.KeyCache()

    def close(self) -> None:
        if self._owns_http:
            self._http.close()

    def __enter__(self) -> SealKeeper:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    def get_trust(self, target: str) -> dict[str, Any]:
        """get_trust's answer for a handle, a URL, an agent id or a did:key.

        The answer as SealKeeper sends it. Its agent fields are unsigned,
        so a decision reads lookup instead.
        """
        return self._call("get_trust", {"agent": p.trust_target(target)[0]})

    def verify_seal(
        self, seal: str, agent: str | None = None, at: datetime | str | None = None
    ) -> dict[str, Any]:
        """SealKeeper's own check of a SEAL, with its record of holds.

        agent is the agent id expected, at a time to check at in place of
        now. The answer as SealKeeper sends it.
        """
        return self._call("verify_seal", p.verify_arguments(seal, agent, at))

    def verify(self, seal: str, expected_agent_id: str) -> VerifiedSeal:
        """Verifies a SEAL here, against SealKeeper's published keys.

        Raises SealBroken with the reason, or UnavailableError when the keys
        cannot be had and no copy younger than five minutes knows the kid.
        """
        expected = _expected_id(expected_agent_id)
        now = self.clock()
        kid = seal_kid(seal)
        keys = self._keys.usable(kid, now)
        if keys is None:
            status, _, body = self._send("GET", p.KEYS_URL, None, self._keys_headers)
            keys = _keys_of(status, body)
            self._keys.store(keys, now)
        return verify_with_keys(seal, keys, now, expected)

    def lookup(self, target: str) -> Lookup:
        """get_trust for target, with the SEAL in its answer verified here."""
        argument, named_id = p.trust_target(target)
        answer = self._call("get_trust", {"agent": argument})
        check = seal_to_check(answer, named_id)
        if check is None:
            return lookup_of(answer, None, None)
        try:
            return lookup_of(answer, self.verify(*check), None)
        except SealBroken as error:
            return lookup_of(answer, None, error.reason)

    def _call(self, name: str, arguments: Mapping[str, Any]) -> dict[str, Any]:
        body = p.tool_call(name, arguments)
        attempt = 0
        while True:
            status, headers, answer = self._send(
                "POST", p.MCP_URL, body, self._mcp_headers
            )
            wait = p.retry_wait(status, headers, attempt)
            if wait is None:
                return p.read_answer(status, answer)
            self._sleep(wait)
            attempt += 1

    def _send(
        self, method: str, url: str, body: bytes | None, headers: dict[str, str]
    ) -> _Answer:
        deadline = time.monotonic() + p.TIMEOUT_SECONDS
        try:
            with self._http.stream(
                method,
                url,
                content=body,
                headers=headers,
                timeout=p.TIMEOUT_SECONDS,
                follow_redirects=False,
            ) as response:
                data = _read_capped(response.iter_bytes(), deadline)
                return response.status_code, response.headers, data
        except httpx.TimeoutException:
            raise _timed_out() from None
        except httpx.TransportError as error:
            raise _unreachable(error) from None


class AsyncSealKeeper:
    """SealKeeper with every call awaited, the same methods and answers.

    http_client is an httpx.AsyncClient. sleep is awaited before the one
    retry of a 429, asyncio.sleep unless another is given.
    """

    def __init__(
        self,
        *,
        http_client: httpx.AsyncClient | None = None,
        clock: Clock | None = None,
        user_agent_suffix: str | None = None,
        sleep: Callable[[float], Awaitable[None]] | None = None,
    ) -> None:
        agent = p.user_agent(user_agent_suffix)
        self._mcp_headers = p.mcp_headers(agent)
        self._keys_headers = p.keys_headers(agent)
        self._owns_http = http_client is None
        self._http = http_client if http_client is not None else httpx.AsyncClient()
        self.clock: Clock = clock if clock is not None else time.time
        self._sleep = sleep if sleep is not None else asyncio.sleep
        self._keys = p.KeyCache()

    async def aclose(self) -> None:
        if self._owns_http:
            await self._http.aclose()

    async def __aenter__(self) -> AsyncSealKeeper:
        return self

    async def __aexit__(self, *_: object) -> None:
        await self.aclose()

    async def get_trust(self, target: str) -> dict[str, Any]:
        return await self._call("get_trust", {"agent": p.trust_target(target)[0]})

    async def verify_seal(
        self, seal: str, agent: str | None = None, at: datetime | str | None = None
    ) -> dict[str, Any]:
        return await self._call("verify_seal", p.verify_arguments(seal, agent, at))

    async def verify(self, seal: str, expected_agent_id: str) -> VerifiedSeal:
        expected = _expected_id(expected_agent_id)
        now = self.clock()
        kid = seal_kid(seal)
        keys = self._keys.usable(kid, now)
        if keys is None:
            status, _, body = await self._send(
                "GET", p.KEYS_URL, None, self._keys_headers
            )
            keys = _keys_of(status, body)
            self._keys.store(keys, now)
        return verify_with_keys(seal, keys, now, expected)

    async def lookup(self, target: str) -> Lookup:
        argument, named_id = p.trust_target(target)
        answer = await self._call("get_trust", {"agent": argument})
        check = seal_to_check(answer, named_id)
        if check is None:
            return lookup_of(answer, None, None)
        try:
            return lookup_of(answer, await self.verify(*check), None)
        except SealBroken as error:
            return lookup_of(answer, None, error.reason)

    async def _call(self, name: str, arguments: Mapping[str, Any]) -> dict[str, Any]:
        body = p.tool_call(name, arguments)
        attempt = 0
        while True:
            status, headers, answer = await self._send(
                "POST", p.MCP_URL, body, self._mcp_headers
            )
            wait = p.retry_wait(status, headers, attempt)
            if wait is None:
                return p.read_answer(status, answer)
            await self._sleep(wait)
            attempt += 1

    async def _send(
        self, method: str, url: str, body: bytes | None, headers: dict[str, str]
    ) -> _Answer:
        deadline = time.monotonic() + p.TIMEOUT_SECONDS
        try:
            async with self._http.stream(
                method,
                url,
                content=body,
                headers=headers,
                timeout=p.TIMEOUT_SECONDS,
                follow_redirects=False,
            ) as response:
                data = await _aread_capped(response.aiter_bytes(), deadline)
                return response.status_code, response.headers, data
        except httpx.TimeoutException:
            raise _timed_out() from None
        except httpx.TransportError as error:
            raise _unreachable(error) from None
