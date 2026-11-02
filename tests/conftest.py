import pytest


# Async tests run on asyncio, the loop httpx and the clients use by default.
@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"
