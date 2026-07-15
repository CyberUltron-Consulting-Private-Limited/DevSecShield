"""
DevSecShield heavy production load profile.

Design notes adapted from proven open-source Locust patterns:
- weighted mixed users for realistic traffic composition
- constant_throughput stress user for deterministic pressure
- explicit allowed status handling to avoid false negatives under load
"""

from __future__ import annotations

import os
import random
import string
import threading
from collections import defaultdict
from typing import Any

from locust import HttpUser, between, constant_throughput, events, tag, task

SCAN_TYPES = ["sast", "dast", "iac", "llm", "sbom_sca", "mcp", "leakage", "agent_discovery"]

ACCESS_TOKEN = os.getenv("DEVSEC_ACCESS_TOKEN", "")
REFRESH_TOKEN = os.getenv("DEVSEC_REFRESH_TOKEN", "")
CONFIG_TEAM_IDS = [int(x) for x in os.getenv("DEVSEC_TEAM_IDS", "").split(",") if x.strip().isdigit()]

STATE_LOCK = threading.Lock()
TEAM_IDS: list[int] = CONFIG_TEAM_IDS.copy()
SCAN_IDS: dict[int, dict[str, list[int]]] = defaultdict(lambda: defaultdict(list))


def _hdr() -> dict[str, str]:
    return {
        "Authorization": f"Bearer {ACCESS_TOKEN}",
        "Content-Type": "application/json",
    }


def _random_word(n: int = 10) -> str:
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=n))


def _safe_json(resp: Any) -> dict[str, Any]:
    try:
        data = resp.json()
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


@events.test_start.add_listener
def _test_start(environment, **_kwargs):
    print("\n[load] DevSecShield heavy profile starting")
    print(f"[load] Preconfigured team ids: {TEAM_IDS}")


class PublicProbeUser(HttpUser):
    weight = 1
    wait_time = between(0.4, 1.5)

    @tag("public")
    @task(7)
    def docs(self):
        with self.client.get("/docs", name="GET /docs", catch_response=True) as r:
            if r.status_code == 200:
                r.success()
            elif r.status_code == 429:
                r.success()
            else:
                r.failure(f"unexpected {r.status_code}")

    @tag("public")
    @task(3)
    def openapi(self):
        with self.client.get("/openapi.json", name="GET /openapi.json", catch_response=True) as r:
            if r.status_code == 200:
                r.success()
            elif r.status_code == 429:
                r.success()
            else:
                r.failure(f"unexpected {r.status_code}")


class AuthReadHeavyUser(HttpUser):
    weight = 7
    wait_time = between(0.2, 1.2)

    def on_start(self):
        if not ACCESS_TOKEN:
            raise RuntimeError("Missing DEVSEC_ACCESS_TOKEN environment variable")
        self.headers = _hdr()
        self.team_id = self._resolve_team_id()

    def _resolve_team_id(self) -> int | None:
        with STATE_LOCK:
            if TEAM_IDS:
                return random.choice(TEAM_IDS)

        with self.client.get("/teams", headers=self.headers, name="GET /teams [bootstrap]", catch_response=True) as r:
            if r.status_code == 200:
                try:
                    rows = r.json()
                    ids = [int(t["team_id"]) for t in rows if isinstance(t, dict) and "team_id" in t]
                    if ids:
                        with STATE_LOCK:
                            for tid in ids:
                                if tid not in TEAM_IDS:
                                    TEAM_IDS.append(tid)
                        return random.choice(ids)
                except Exception:
                    pass
            if r.status_code in (401, 403):
                r.failure("auth failed during bootstrap")
            else:
                r.success()
        return None

    @tag("auth")
    @task(8)
    def get_user(self):
        with self.client.get("/get_user", headers=self.headers, name="GET /get_user", catch_response=True) as r:
            if r.status_code in (200, 429):
                r.success()
            else:
                r.failure(f"unexpected {r.status_code}")

    @tag("teams")
    @task(10)
    def list_teams(self):
        with self.client.get("/teams", headers=self.headers, name="GET /teams", catch_response=True) as r:
            if r.status_code in (200, 429):
                if r.status_code == 200:
                    try:
                        rows = r.json()
                        ids = [int(t["team_id"]) for t in rows if isinstance(t, dict) and "team_id" in t]
                        with STATE_LOCK:
                            for tid in ids:
                                if tid not in TEAM_IDS:
                                    TEAM_IDS.append(tid)
                    except Exception:
                        pass
                r.success()
            else:
                r.failure(f"unexpected {r.status_code}")

    @tag("teams")
    @task(7)
    def team_details(self):
        if not self.team_id:
            return
        with self.client.get(
            f"/team/{self.team_id}",
            headers=self.headers,
            name="GET /team/{team_id}",
            catch_response=True,
        ) as r:
            if r.status_code in (200, 403, 404, 429):
                r.success()
            else:
                r.failure(f"unexpected {r.status_code}")

    @tag("dashboard")
    @task(5)
    def team_dashboard(self):
        if not self.team_id:
            return
        with self.client.get(
            f"/team/{self.team_id}/dashboard",
            headers=self.headers,
            name="GET /team/{team_id}/dashboard",
            catch_response=True,
        ) as r:
            if r.status_code in (200, 403, 404, 429):
                r.success()
            else:
                r.failure(f"unexpected {r.status_code}")

    @tag("dashboard")
    @task(3)
    def teams_dashboard(self):
        with self.client.get("/teams/dashboard", headers=self.headers, name="GET /teams/dashboard", catch_response=True) as r:
            if r.status_code in (200, 429):
                r.success()
            else:
                r.failure(f"unexpected {r.status_code}")

    @tag("scans")
    @task(16)
    def list_scans(self):
        if not self.team_id:
            return
        scan_type = random.choice(SCAN_TYPES)
        with self.client.get(
            f"/{self.team_id}/{scan_type}/scans",
            headers=self.headers,
            name="GET /{team_id}/{type}/scans",
            catch_response=True,
        ) as r:
            if r.status_code in (200, 403, 404, 429):
                if r.status_code == 200:
                    payload = _safe_json(r)
                    scans = payload.get("scans_list_data", [])
                    with STATE_LOCK:
                        for item in scans:
                            sid = item.get("scan_id") if isinstance(item, dict) else None
                            if isinstance(sid, int) and sid not in SCAN_IDS[self.team_id][scan_type]:
                                SCAN_IDS[self.team_id][scan_type].append(sid)
                r.success()
            else:
                r.failure(f"unexpected {r.status_code}")

    @tag("auth")
    @task(2)
    def refresh_token(self):
        if not REFRESH_TOKEN:
            return
        body = {"refresh_token": REFRESH_TOKEN}
        with self.client.post(
            "/refresh", json=body, headers=self.headers, name="POST /refresh", catch_response=True
        ) as r:
            if r.status_code in (200, 401, 403, 429):
                r.success()
            else:
                r.failure(f"unexpected {r.status_code}")


class ScanLifecycleNoStartUser(HttpUser):
    weight = 2
    wait_time = between(0.5, 2.0)

    def on_start(self):
        if not ACCESS_TOKEN:
            raise RuntimeError("Missing DEVSEC_ACCESS_TOKEN environment variable")
        self.headers = _hdr()
        self.team_id = random.choice(TEAM_IDS) if TEAM_IDS else None

    @tag("scan-lifecycle")
    @task(4)
    def create_scan(self):
        if not self.team_id:
            return
        scan_type = random.choice(SCAN_TYPES)
        body = {"title": f"lt-{scan_type}-{_random_word(8)}"}
        with self.client.post(
            f"/{self.team_id}/{scan_type}/scan",
            json=body,
            headers=self.headers,
            name="POST /{team_id}/{type}/scan",
            catch_response=True,
        ) as r:
            if r.status_code in (200, 201):
                payload = _safe_json(r)
                sid = payload.get("scan_id")
                if isinstance(sid, int):
                    with STATE_LOCK:
                        SCAN_IDS[self.team_id][scan_type].append(sid)
                r.success()
            elif r.status_code in (400, 403, 404, 429):
                # 400/403 can happen with ownership/team checks under race conditions
                r.success()
            else:
                r.failure(f"unexpected {r.status_code}")

    @tag("scan-lifecycle")
    @task(8)
    def poll_scan(self):
        if not self.team_id:
            return

        scan_type = random.choice(SCAN_TYPES)
        with STATE_LOCK:
            existing = list(SCAN_IDS[self.team_id][scan_type])
        if not existing:
            return

        sid = random.choice(existing)
        with self.client.get(
            f"/{self.team_id}/{scan_type}/scan/{sid}",
            headers=self.headers,
            name="GET /{team_id}/{type}/scan/{scan_id}",
            catch_response=True,
        ) as r:
            if r.status_code in (200, 403, 404, 429):
                r.success()
            else:
                r.failure(f"unexpected {r.status_code}")

    @tag("scan-lifecycle")
    @task(3)
    def rename_scan(self):
        if not self.team_id:
            return

        scan_type = random.choice(SCAN_TYPES)
        with STATE_LOCK:
            existing = list(SCAN_IDS[self.team_id][scan_type])
        if not existing:
            return
        sid = random.choice(existing)

        with self.client.put(
            f"/{self.team_id}/{scan_type}/scan/{sid}",
            json={"title": f"renamed-{_random_word(8)}"},
            headers=self.headers,
            name="PUT /{team_id}/{type}/scan/{scan_id}",
            catch_response=True,
        ) as r:
            if r.status_code in (200, 400, 403, 404, 429):
                r.success()
            else:
                r.failure(f"unexpected {r.status_code}")


class PeakStressUser(HttpUser):
    """Deterministic pressure user based on constant throughput pattern."""

    weight = 1
    wait_time = constant_throughput(1.2)

    def on_start(self):
        if not ACCESS_TOKEN:
            raise RuntimeError("Missing DEVSEC_ACCESS_TOKEN environment variable")
        self.headers = _hdr()
        self.team_id = random.choice(TEAM_IDS) if TEAM_IDS else None

    @tag("stress")
    @task(7)
    def rapid_scan_list(self):
        if not self.team_id:
            return
        scan_type = random.choice(SCAN_TYPES)
        self.client.get(
            f"/{self.team_id}/{scan_type}/scans",
            headers=self.headers,
            name="GET /{team_id}/{type}/scans [stress]",
        )

    @tag("stress")
    @task(4)
    def rapid_team_lookup(self):
        if not self.team_id:
            return
        self.client.get(
            f"/team/{self.team_id}",
            headers=self.headers,
            name="GET /team/{team_id} [stress]",
        )

    @tag("stress")
    @task(2)
    def rapid_user_lookup(self):
        self.client.get("/get_user", headers=self.headers, name="GET /get_user [stress]")
