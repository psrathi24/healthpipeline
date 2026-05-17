"""
FHIR HTTP client: paginated search with retries and per-page logging.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Iterator

import requests
from dotenv import load_dotenv
from loguru import logger
from tenacity import retry, retry_if_exception, stop_after_attempt, wait_exponential


def _retryable(exc: BaseException) -> bool:
    if isinstance(exc, (requests.ConnectionError, requests.Timeout)):
        return True
    if isinstance(exc, requests.HTTPError) and exc.response is not None:
        code = exc.response.status_code
        return code >= 500 or code == 429
    return False


class FHIRClient:
    """FHIR REST client with Bundle pagination and resilient GETs."""

    def __init__(self, base_url: str | None = None) -> None:
        env_path = Path(__file__).resolve().parent.parent / ".env"
        load_dotenv(env_path, override=True)
        raw = base_url or os.getenv("FHIR_BASE_URL", "")
        self.base_url = raw.rstrip("/")
        if not self.base_url:
            raise ValueError("FHIR_BASE_URL must be set in .env or passed to FHIRClient()")

    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=1, max=10),
        retry=retry_if_exception(_retryable),
        reraise=True,
    )
    def _fetch_json(self, url: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        response = requests.get(url, params=params, timeout=120)
        response.raise_for_status()
        return response.json()

    def get_resources(
        self,
        resource_type: str,
        params: dict[str, Any] | None = None,
    ) -> Iterator[dict[str, Any]]:
        """
        GET {base}/{resource_type}?params..., follow Bundle.link relation \"next\",
        yield each entry.resource (skips entries without a resource).
        """
        rt = (resource_type or "").strip().strip("/")
        if not rt:
            raise ValueError("resource_type must be non-empty")

        params = dict(params or {})
        initial_url = f"{self.base_url}/{rt}"
        next_url: str | None = None
        page = 0

        while True:
            page += 1
            if next_url:
                bundle = self._fetch_json(next_url, params=None)
                logger.info(
                    "Fetched FHIR page {} for {} (next link)",
                    page,
                    rt,
                )
            else:
                bundle = self._fetch_json(
                    initial_url,
                    params=params if params else None,
                )
                logger.info(
                    "Fetched FHIR page {} for {} ({})",
                    page,
                    rt,
                    initial_url,
                )

            if bundle.get("resourceType") != "Bundle":
                logger.warning(
                    "Expected Bundle, got {}; stopping pagination",
                    bundle.get("resourceType"),
                )
                return

            for entry in bundle.get("entry") or []:
                resource = entry.get("resource")
                if resource is not None:
                    yield resource

            following: str | None = None
            for link in bundle.get("link") or []:
                if link.get("relation") == "next" and link.get("url"):
                    following = link["url"]
                    break

            if not following:
                break
            next_url = following