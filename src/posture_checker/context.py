"""Shared state for one scan: the boto3 session, cached clients and cached lookups."""

from __future__ import annotations

import threading
from typing import Any, Callable

import boto3


class Context:
    def __init__(self, session: boto3.Session, regions: list[str] | None = None):
        self.session = session
        self._regions = regions
        self._clients: dict[tuple[str, str], Any] = {}
        self._cache: dict[str, Any] = {}
        self._lock = threading.Lock()

    @property
    def home_region(self) -> str:
        return self.session.region_name or "us-east-1"

    def client(self, service: str, region: str | None = None):
        """Return a cached client. boto3 sessions are not thread-safe, so creation is locked."""
        key = (service, region or self.home_region)
        with self._lock:
            if key not in self._clients:
                self._clients[key] = self.session.client(service, region_name=key[1])
            return self._clients[key]

    def cached(self, key: str, fn: Callable[[], Any]) -> Any:
        """Run fn once per scan and reuse the result (e.g. the CloudTrail trail list)."""
        with self._lock:
            if key in self._cache:
                return self._cache[key]
        value = fn()
        with self._lock:
            self._cache.setdefault(key, value)
            return self._cache[key]

    @property
    def regions(self) -> list[str]:
        if self._regions is None:
            # describe_regions returns only regions enabled for this account.
            resp = self.client("ec2").describe_regions()
            self._regions = sorted(r["RegionName"] for r in resp["Regions"])
        return self._regions

    @property
    def account_id(self) -> str:
        return self.cached(
            "account_id", lambda: self.client("sts").get_caller_identity()["Account"]
        )
