"""Async scan engine base class."""

from __future__ import annotations

import asyncio
import logging
from abc import ABC, abstractmethod

import aiohttp

from scanme.core.models import ScanResult, ScanTarget

log = logging.getLogger("scanme")


class AsyncScanEngine(ABC):
    """Base class for all scan modules.

    Provides shared async infrastructure: concurrency limiter,
    configurable timeout, retry logic, proxy support, and an
    optional aiohttp session.
    """

    name: str = "base"

    def __init__(
        self,
        concurrency: int = 200,
        timeout: float = 10.0,
        retries: int = 2,
        proxy: str | None = None,
    ):
        self.concurrency = concurrency
        self.timeout = timeout
        self.retries = retries
        self.proxy = proxy
        self._semaphore = asyncio.Semaphore(concurrency)
        self._session: aiohttp.ClientSession | None = None

    async def get_session(self) -> aiohttp.ClientSession:
        """Lazy-create a shared aiohttp session."""
        if self._session is None or self._session.closed:
            self._session = aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=self.timeout),
                connector=aiohttp.TCPConnector(ssl=False, limit=self.concurrency),
                headers={"User-Agent": "Mozilla/5.0 (compatible; ScanMe/2.0)"},
            )
        return self._session

    async def fetch(self, url: str, **kwargs) -> aiohttp.ClientResponse:
        """HTTP GET with retry logic and optional proxy."""
        session = await self.get_session()
        last_exc: Exception | None = None

        for attempt in range(1, self.retries + 1):
            try:
                resp = await session.get(url, proxy=self.proxy, **kwargs)
                return resp
            except (aiohttp.ClientError, asyncio.TimeoutError) as exc:
                last_exc = exc
                if attempt < self.retries:
                    wait = 0.5 * attempt
                    log.debug("Retry %d/%d for %s (%.1fs): %s", attempt, self.retries, url, wait, exc)
                    await asyncio.sleep(wait)

        raise last_exc  # type: ignore[misc]

    async def close(self):
        if self._session and not self._session.closed:
            await self._session.close()

    @abstractmethod
    async def run(self, target: ScanTarget) -> ScanResult:
        """Execute the scan against the given target."""
        ...

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        await self.close()
