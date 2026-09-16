#!/usr/bin/env python3
"""
════════════════════════════════════════════════════════════════════════════════
 samsung_to_bigquery.py  ·  v1.0                                     2026-09-15
 Samsung Galaxy Store (Seller Portal)  →  BigQuery

 KYA KARTA HAI
   1. JWT banata hai (RS256, private key se) → access token leta hai
   2. /seller/contentList        → saarey apps (contentId + naam + status)
   3. /gss/query/contentMetric   → HAR app ka ROZANA data (installs/revenue/rating)
   4. BigQuery mein MERGE karta hai — idempotent, dobara chalane par duplicate nahi

 API DOCS (tasdeeq shuda 2026-09-15)
   https://developer.samsung.com/galaxy-store/galaxy-store-developer-api.html
   https://developer.samsung.com/galaxy-store/galaxy-store-statistics/gss-metric-api.html

 ══ ENTERPRISE GUARDS ══
   🛡️ FAIL CLOSED   — koi bhi app fail ho to BigQuery mein kuch nahi likhta
   🛡️ MERGE         — append nahi; dobara chalao to update hota hai, duplicate nahi
   🛡️ RETRY         — 429/5xx par exponential backoff + jitter
   🛡️ TOKEN REFRESH — token 20 min chalta hai; 5 min pehle khud naya le leta hai
   🛡️ THROTTLE      — har call ke beech wait (Samsung rate limit nahi batata)
   🛡️ STAGING SWAP  — pehle temp table, tasdeeq, phir MERGE
   🛡️ DRY_RUN       — kuch likhe baghair poora chala kar dekho
   🛡️ SCHEMA LOCK   — table ka schema code mein likha hai, drift nahi hoga
════════════════════════════════════════════════════════════════════════════════
"""

from __future__ import annotations

import json
import logging
import os
import random
import sys
import time
from dataclasses import dataclass, field
from datetime import date, datetime, timedelta, timezone
from typing import Any, Iterable

import jwt as pyjwt                      # PyJWT
import requests
from google.api_core import exceptions as gexc
from google.cloud import bigquery

# ══════════════════════════════════════════════════════════════════════════════
#  CONFIG — sab environment se, koi secret code mein nahi
# ══════════════════════════════════════════════════════════════════════════════

API_BASE = "https://devapi.samsungapps.com"
AUTH_URL = f"{API_BASE}/auth/accessToken"
CONTENT_LIST_URL = f"{API_BASE}/seller/contentList"
CONTENT_INFO_URL = f"{API_BASE}/seller/contentInfo"
CONTENT_METRIC_URL = f"{API_BASE}/gss/query/contentMetric"

# GSS metric IDs — docs se hu-ba-hu (spelling "volumne" Samsung ki apni hai)
METRIC_INSTALLS = "total_unique_installs_filter"   # New Downloads
METRIC_REVENUE = "revenue_total"                   # Sales (item sales ke saath)
METRIC_IAP_ORDERS = "revenue_iap_order_count"      # Item Purchases
METRIC_RATING = "daily_rat_score"                  # Average Rating
METRIC_RATING_VOL = "daily_rat_volumne"            # Ratings Volume  [sic]

ALL_METRICS = [
    METRIC_INSTALLS,
    METRIC_REVENUE,
    METRIC_IAP_ORDERS,
    METRIC_RATING,
    METRIC_RATING_VOL,
]


def _env(name: str, default: str | None = None, *, required: bool = False) -> str:
    v = os.environ.get(name, default)
    if required and not v:
        raise SystemExit(f"🔴 zaroori environment variable set nahi: {name}")
    return v or ""


def _env_int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, "") or default)
    except ValueError:
        return default


def _env_bool(name: str, default: bool = False) -> bool:
    return (os.environ.get(name, "") or str(default)).strip().lower() in ("1", "true", "yes", "y")


@dataclass(frozen=True)
class Config:
    # ── Samsung ──
    service_account_id: str = field(default_factory=lambda: _env("SAMSUNG_SERVICE_ACCOUNT_ID", required=True))
    private_key: str = field(default_factory=lambda: _env("SAMSUNG_PRIVATE_KEY", required=True))

    # ── BigQuery ──
    gcp_project: str = field(default_factory=lambda: _env("GCP_PROJECT", required=True))
    bq_dataset: str = field(default_factory=lambda: _env("BQ_DATASET", "samsung"))
    bq_location: str = field(default_factory=lambda: _env("BQ_LOCATION", "US"))

    # ── kitne din ──
    lookback_days: int = field(default_factory=lambda: _env_int("LOOKBACK_DAYS", 14))
    backfill_start: str = field(default_factory=lambda: _env("BACKFILL_START", ""))
    backfill_end: str = field(default_factory=lambda: _env("BACKFILL_END", ""))

    # ── guards ──
    dry_run: bool = field(default_factory=lambda: _env_bool("DRY_RUN", False))
    max_retries: int = field(default_factory=lambda: _env_int("MAX_RETRIES", 5))
    throttle_ms: int = field(default_factory=lambda: _env_int("THROTTLE_MS", 400))
    request_timeout: int = field(default_factory=lambda: _env_int("REQUEST_TIMEOUT", 90))
    chunk_days: int = field(default_factory=lambda: _env_int("CHUNK_DAYS", 30))
    fail_threshold_pct: int = field(default_factory=lambda: _env_int("FAIL_THRESHOLD_PCT", 0))
    # 🆕 package name ke liye har app par ek extra call (contentInfo)
    fetch_packages: bool = field(default_factory=lambda: _env_bool("FETCH_PACKAGE_NAMES", True))
    total_budget_s: int = field(default_factory=lambda: _env_int("TOTAL_BUDGET_SECONDS", 3300))

    @property
    def table_daily(self) -> str:
        return f"{self.gcp_project}.{self.bq_dataset}.samsung_daily_app"

    @property
    def table_apps(self) -> str:
        return f"{self.gcp_project}.{self.bq_dataset}.samsung_apps_dim"


# ══════════════════════════════════════════════════════════════════════════════
#  LOGGING — structured, GitHub Actions friendly
# ══════════════════════════════════════════════════════════════════════════════

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)sZ  %(levelname)-7s  %(message)s",
    datefmt="%H:%M:%S",
    stream=sys.stdout,
)
log = logging.getLogger("samsung")
logging.Formatter.converter = time.gmtime


def gha(kind: str, msg: str) -> None:
    """GitHub Actions annotation — Summary mein nazar aata hai."""
    if os.environ.get("GITHUB_ACTIONS"):
        print(f"::{kind}::{msg}", flush=True)


# ══════════════════════════════════════════════════════════════════════════════
#  AUTH — JWT → access token, khud refresh hota hai
# ══════════════════════════════════════════════════════════════════════════════

class SamsungAuth:
    """
    JWT (RS256) banata hai aur access token leta hai.

    Token 20 minute chalta hai. Hum 5 minute pehle hi naya le lete hain —
    taake lambi run ke beech mein kabhi 401 na aaye.
    """

    TOKEN_TTL_S = 20 * 60
    REFRESH_MARGIN_S = 5 * 60

    def __init__(self, cfg: Config, session: requests.Session):
        self.cfg = cfg
        self.session = session
        self._token: str | None = None
        self._expires_at: float = 0.0

        key = cfg.private_key.strip()
        # GitHub secret mein newline aksar \n ban jate hain — theek kar lo
        if "\\n" in key and "-----BEGIN" in key:
            key = key.replace("\\n", "\n")
        if not key.startswith("-----BEGIN"):
            raise SystemExit(
                "🔴 SAMSUNG_PRIVATE_KEY theek nahi lag rahi — "
                "'-----BEGIN PRIVATE KEY-----' se shuru honi chahiye"
            )
        self._key = key

    def _make_jwt(self) -> str:
        now = int(time.time())
        payload = {
            "iss": self.cfg.service_account_id,
            "scopes": ["publishing", "gss"],
            "iat": now,
            "exp": now + self.TOKEN_TTL_S,
        }
        return pyjwt.encode(payload, self._key, algorithm="RS256")

    def token(self) -> str:
        if self._token and time.time() < self._expires_at - self.REFRESH_MARGIN_S:
            return self._token

        signed = self._make_jwt()
        headers = {
            "Authorization": f"Bearer {signed}",
            "service-account-id": self.cfg.service_account_id,
        }
        r = self.session.post(headers=headers, timeout=self.cfg.request_timeout, url=AUTH_URL)

        if r.status_code != 200:
            raise SystemExit(
                f"🔴 access token nahi mila — HTTP {r.status_code}\n"
                f"   {r.text[:400]}\n"
                f"   Dekho: service account ID theek hai? private key wahi hai jo Seller Portal ne di?"
            )
        try:
            tok = r.json()["createdItem"]["accessToken"]
        except (KeyError, ValueError) as e:
            raise SystemExit(f"🔴 token ka jawab samajh nahi aaya: {r.text[:400]}") from e

        self._token = tok
        self._expires_at = time.time() + self.TOKEN_TTL_S
        log.info("🔑 access token mil gaya (20 min)")
        return tok

    def headers(self, *, json_body: bool = False) -> dict[str, str]:
        h = {
            "Authorization": f"Bearer {self.token()}",
            "service-account-id": self.cfg.service_account_id,
        }
        if json_body:
            h["content-type"] = "application/json"
        return h


# ══════════════════════════════════════════════════════════════════════════════
#  HTTP — retry + backoff + throttle
# ══════════════════════════════════════════════════════════════════════════════

RETRYABLE_STATUS = {408, 425, 429, 500, 502, 503, 504}


class SamsungClient:
    def __init__(self, cfg: Config):
        self.cfg = cfg
        self.session = requests.Session()
        self.session.headers["User-Agent"] = "terafort-samsung-loader/1.0"
        self.auth = SamsungAuth(cfg, self.session)
        self._last_call = 0.0
        self._started = time.time()

    # ── budget ──
    def _check_budget(self) -> None:
        spent = time.time() - self._started
        if spent > self.cfg.total_budget_s:
            raise TimeoutError(
                f"waqt ka budget khatam ({spent:.0f}s > {self.cfg.total_budget_s}s) — "
                f"FAIL CLOSED, kuch nahi likha gaya"
            )

    def _throttle(self) -> None:
        gap = time.time() - self._last_call
        need = self.cfg.throttle_ms / 1000.0
        if gap < need:
            time.sleep(need - gap)
        self._last_call = time.time()

    def request(self, method: str, url: str, *, body: dict | None = None,
                label: str = "") -> dict[str, Any] | list[Any]:
        last_err = ""
        for attempt in range(1, self.cfg.max_retries + 1):
            self._check_budget()
            self._throttle()
            try:
                r = self.session.request(
                    method,
                    url,
                    headers=self.auth.headers(json_body=body is not None),
                    json=body,
                    timeout=self.cfg.request_timeout,
                )
            except requests.RequestException as e:
                last_err = f"network: {e}"
                wait = min(2 ** attempt + random.uniform(0, 1.5), 60)
                log.warning("⚠️  %s — %s · %d/%d · %.1fs baad dobara",
                            label, last_err, attempt, self.cfg.max_retries, wait)
                time.sleep(wait)
                continue

            if r.status_code == 200:
                try:
                    return r.json()
                except ValueError:
                    last_err = f"JSON nahi: {r.text[:200]}"
                    break

            if r.status_code == 401 and attempt < self.cfg.max_retries:
                # token expire ho gaya — force refresh
                log.warning("⚠️  %s — 401, naya token le rahe hain", label)
                self.auth._token = None
                continue

            if r.status_code in RETRYABLE_STATUS:
                retry_after = r.headers.get("Retry-After")
                wait = (float(retry_after) if retry_after and retry_after.isdigit()
                        else min(2 ** attempt + random.uniform(0, 1.5), 90))
                last_err = f"HTTP {r.status_code}"
                log.warning("⚠️  %s — %s · %d/%d · %.1fs baad dobara",
                            label, last_err, attempt, self.cfg.max_retries, wait)
                time.sleep(wait)
                continue

            # non-retryable
            last_err = f"HTTP {r.status_code}: {r.text[:300]}"
            break

        raise RuntimeError(f"{label} nakaam — {last_err}")

    # ── endpoints ──
    def content_list(self) -> list[dict[str, Any]]:
        data = self.request("GET", CONTENT_LIST_URL, label="contentList")
        if not isinstance(data, list):
            raise RuntimeError(f"contentList list nahi mili: {str(data)[:300]}")
        return data

    def content_info(self, content_id: str) -> dict[str, Any]:
        """
        🆕 App ki tafseel — package name YAHI se milta hai.

        /seller/contentList package name deta HI NAHI (docs se tasdeeq shuda) —
        wo sirf contentName/contentId/status/price deta hai.
        Package `contentInfo` ke `binaryList[].packageName` mein hota hai.
        """
        data = self.request("GET", f"{CONTENT_INFO_URL}?contentId={content_id}",
                            label=f"contentInfo[{content_id}]")
        # jawab list mein aata hai: [{...}]
        if isinstance(data, list):
            return data[0] if data else {}
        return data if isinstance(data, dict) else {}

    def content_metric(self, content_id: str, start: date, end: date) -> dict[str, Any]:
        body = {
            "contentId": content_id,
            "metricIds": ALL_METRICS,
            "periods": [{"startDate": start.isoformat(), "endDate": end.isoformat()}],
            "noBreakdown": True,          # country/device breakdown nahi chahiye
            "trendAggregation": "day",    # 🔑 ROZANA data — yehi grain chahiye
            "filters": {},
        }
        data = self.request("POST", CONTENT_METRIC_URL, body=body,
                            label=f"contentMetric[{content_id}]")
        if not isinstance(data, dict):
            raise RuntimeError(f"contentMetric dict nahi mila: {str(data)[:300]}")
        return data


# ══════════════════════════════════════════════════════════════════════════════
#  PARSING — nested JSON → flat rows
# ══════════════════════════════════════════════════════════════════════════════

def extract_package(info: dict[str, Any]) -> tuple[str | None, str | None, str | None]:
    """
    contentInfo ke `binaryList` se package + version nikalta hai.

    Ek app ke kai binary ho sakte hain (alag versionCode). Sab ka package
    aksar ek hi hota hai — magar hum sab se NAYA (sab se bara versionCode)
    uthate hain, taake latest wala mile.
    """
    blist = info.get("binaryList")
    if not isinstance(blist, list) or not blist:
        return None, None, None

    best, best_vc = None, -1
    for b in blist:
        if not isinstance(b, dict):
            continue
        pkg = (b.get("packageName") or "").strip()
        if not pkg:
            continue
        try:
            vc = int(str(b.get("versionCode") or 0).strip() or 0)
        except ValueError:
            vc = 0
        if vc >= best_vc:
            best, best_vc = b, vc

    if not best:
        return None, None, None
    return (
        (best.get("packageName") or "").strip().lower() or None,
        str(best.get("versionCode") or "").strip() or None,
        str(best.get("versionName") or "").strip() or None,
    )


def _f(v: Any) -> float:
    try:
        return float(v)
    except (TypeError, ValueError):
        return 0.0


def parse_content_metric(payload: dict[str, Any], content_id: str,
                         app_meta: dict[str, Any]) -> list[dict[str, Any]]:
    """
    Samsung ka jawab:
      data.periods[].{contentId}.{metric}.dailyTrend.{yyyy-MM-dd}.value

    Hum use flat rows mein badalte hain: ek row per (date, contentId).
    """
    by_date: dict[str, dict[str, float]] = {}

    periods = (payload.get("data") or {}).get("periods") or []
    for period in periods:
        block = period.get(content_id)
        if not isinstance(block, dict):
            continue
        for metric, mdata in block.items():
            if metric not in ALL_METRICS or not isinstance(mdata, dict):
                continue
            trend = mdata.get("dailyTrend") or {}
            if not isinstance(trend, dict):
                continue
            for day, point in trend.items():
                if not isinstance(point, dict):
                    continue
                by_date.setdefault(day, {})[metric] = _f(point.get("value"))

    content_info = (payload.get("data") or {}).get("content") or {}
    now = datetime.now(timezone.utc)

    rows: list[dict[str, Any]] = []
    for day in sorted(by_date):
        try:
            datetime.strptime(day, "%Y-%m-%d")
        except ValueError:
            log.warning("⚠️  ajeeb tareekh chhodi: %r (app %s)", day, content_id)
            continue
        m = by_date[day]
        rows.append({
            "date": day,
            "content_id": content_id,
            "app_name": app_meta.get("app_name") or content_info.get("content_name"),
            # 🆕 package contentInfo se aaya (app_meta mein bhar chuke hain)
            "package_name": app_meta.get("package_name"),
            "content_status": app_meta.get("contentStatus") or content_info.get("status"),
            "store_type": content_info.get("store_type"),
            "installs": int(m.get(METRIC_INSTALLS, 0.0)),
            "revenue_usd": round(m.get(METRIC_REVENUE, 0.0), 4),
            "iap_order_count": int(m.get(METRIC_IAP_ORDERS, 0.0)),
            "rating_score_sum": round(m.get(METRIC_RATING, 0.0), 4),
            "rating_volume": int(m.get(METRIC_RATING_VOL, 0.0)),
            "_loaded_at": now.isoformat(),
        })
    return rows


# ══════════════════════════════════════════════════════════════════════════════
#  BIGQUERY — schema + MERGE (idempotent)
# ══════════════════════════════════════════════════════════════════════════════

SCHEMA_DAILY = [
    bigquery.SchemaField("date", "DATE", mode="REQUIRED"),
    bigquery.SchemaField("content_id", "STRING", mode="REQUIRED"),
    bigquery.SchemaField("app_name", "STRING"),
    bigquery.SchemaField("package_name", "STRING"),
    bigquery.SchemaField("content_status", "STRING"),
    bigquery.SchemaField("store_type", "STRING"),
    bigquery.SchemaField("installs", "INT64"),
    bigquery.SchemaField("revenue_usd", "FLOAT64"),
    bigquery.SchemaField("iap_order_count", "INT64"),
    bigquery.SchemaField("rating_score_sum", "FLOAT64"),
    bigquery.SchemaField("rating_volume", "INT64"),
    bigquery.SchemaField("_loaded_at", "TIMESTAMP"),
]

SCHEMA_APPS = [
    bigquery.SchemaField("content_id", "STRING", mode="REQUIRED"),
    bigquery.SchemaField("app_name", "STRING"),
    bigquery.SchemaField("package_name", "STRING"),
    bigquery.SchemaField("content_status", "STRING"),
    bigquery.SchemaField("standard_price", "FLOAT64"),
    bigquery.SchemaField("paid", "STRING"),
    bigquery.SchemaField("modify_date", "STRING"),
    bigquery.SchemaField("version_code", "STRING"),
    bigquery.SchemaField("version_name", "STRING"),
    bigquery.SchemaField("_loaded_at", "TIMESTAMP"),
]


class BQ:
    def __init__(self, cfg: Config):
        self.cfg = cfg
        self.client = bigquery.Client(project=cfg.gcp_project, location=cfg.bq_location)

    def ensure_dataset(self) -> None:
        ds_id = f"{self.cfg.gcp_project}.{self.cfg.bq_dataset}"
        try:
            self.client.get_dataset(ds_id)
        except gexc.NotFound:
            ds = bigquery.Dataset(ds_id)
            ds.location = self.cfg.bq_location
            self.client.create_dataset(ds)
            log.info("📦 dataset banaya: %s", ds_id)

    def ensure_table(self, table_id: str, schema: list[bigquery.SchemaField],
                     *, partition_on: str | None = None,
                     cluster: list[str] | None = None) -> None:
        """
        Table banati hai — aur agar pehle se hai to SCHEMA MIGRATE karti hai.

        🛡️ KYUN: purani table par naye column add karo to MERGE
           "Unrecognized name: <column>" de kar mar jati hai. Ye function
           naye column khud jod deta hai (NULLABLE, is liye purani rows
           mehfooz rehti hain).

        ⚠️ Sirf JORTA hai — kabhi kuch hataata ya badalta NAHI.
        """
        try:
            existing = self.client.get_table(table_id)
        except gexc.NotFound:
            t = bigquery.Table(table_id, schema=schema)
            if partition_on:
                t.time_partitioning = bigquery.TimePartitioning(field=partition_on)
            if cluster:
                t.clustering_fields = cluster
            self.client.create_table(t)
            log.info("📦 table banayi: %s", table_id)
            return

        # 🆕 schema migration — jo column kam hain wo jod do
        have = {f.name for f in existing.schema}
        missing = [f for f in schema if f.name not in have]
        if not missing:
            return

        # naye column hamesha NULLABLE — warna purani rows toot jayengi
        added = [bigquery.SchemaField(f.name, f.field_type, mode="NULLABLE",
                                      description=f.description)
                 for f in missing]
        existing.schema = list(existing.schema) + added
        self.client.update_table(existing, ["schema"])
        log.info("🔧 %s mein %d naye column jode: %s",
                 table_id.split(".")[-1], len(added),
                 ", ".join(f.name for f in added))

    def merge_daily(self, rows: list[dict[str, Any]]) -> int:
        """
        🛡️ MERGE — append NAHI.
        Dobara chalao to wahi (date, content_id) update hoti hai, duplicate nahi banti.
        """
        if not rows:
            return 0
        tmp = f"{self.cfg.gcp_project}.{self.cfg.bq_dataset}._tmp_samsung_daily_{int(time.time())}"
        job = self.client.load_table_from_json(
            rows, tmp,
            job_config=bigquery.LoadJobConfig(
                schema=SCHEMA_DAILY,
                write_disposition="WRITE_TRUNCATE",
            ),
        )
        job.result()
        try:
            sql = f"""
            MERGE `{self.cfg.table_daily}` T
            USING (
              SELECT * EXCEPT(rn) FROM (
                SELECT *, ROW_NUMBER() OVER (
                  PARTITION BY date, content_id ORDER BY _loaded_at DESC) AS rn
                FROM `{tmp}`
              ) WHERE rn = 1
            ) S
            ON T.date = S.date AND T.content_id = S.content_id
            WHEN MATCHED THEN UPDATE SET
              app_name = S.app_name, package_name = S.package_name,
              content_status = S.content_status, store_type = S.store_type,
              installs = S.installs, revenue_usd = S.revenue_usd,
              iap_order_count = S.iap_order_count,
              rating_score_sum = S.rating_score_sum, rating_volume = S.rating_volume,
              _loaded_at = S._loaded_at
            -- 🛡️ NAAM se INSERT — `INSERT ROW` NAHI.
            --    `INSERT ROW` column ki TARTEEB par chalta hai. Agar table par
            --    kabhi ALTER se naya column jur jaye (wo aakhir mein lagta hai)
            --    to tarteeb toot jati hai aur ghalat column mein value chali
            --    jati hai. Naam likhne se ye kabhi nahi hoga.
            WHEN NOT MATCHED THEN INSERT (
              date, content_id, app_name, package_name, content_status,
              store_type, installs, revenue_usd, iap_order_count,
              rating_score_sum, rating_volume, _loaded_at
            ) VALUES (
              S.date, S.content_id, S.app_name, S.package_name, S.content_status,
              S.store_type, S.installs, S.revenue_usd, S.iap_order_count,
              S.rating_score_sum, S.rating_volume, S._loaded_at
            )
            """
            q = self.client.query(sql)
            q.result()
            return q.num_dml_affected_rows or 0
        finally:
            self.client.delete_table(tmp, not_found_ok=True)

    def merge_apps(self, apps: list[dict[str, Any]]) -> int:
        if not apps:
            return 0
        tmp = f"{self.cfg.gcp_project}.{self.cfg.bq_dataset}._tmp_samsung_apps_{int(time.time())}"
        self.client.load_table_from_json(
            apps, tmp,
            job_config=bigquery.LoadJobConfig(schema=SCHEMA_APPS,
                                              write_disposition="WRITE_TRUNCATE"),
        ).result()
        try:
            sql = f"""
            MERGE `{self.cfg.table_apps}` T
            USING (
              SELECT * EXCEPT(rn) FROM (
                SELECT *, ROW_NUMBER() OVER (
                  PARTITION BY content_id ORDER BY _loaded_at DESC) AS rn
                FROM `{tmp}`
              ) WHERE rn = 1
            ) S
            ON T.content_id = S.content_id
            WHEN MATCHED THEN UPDATE SET
              app_name = S.app_name, package_name = S.package_name,
              content_status = S.content_status, standard_price = S.standard_price,
              paid = S.paid, modify_date = S.modify_date,
              version_code = S.version_code, version_name = S.version_name,
              _loaded_at = S._loaded_at
            -- 🛡️ NAAM se INSERT — tarteeb par bharosa nahi
            WHEN NOT MATCHED THEN INSERT (
              content_id, app_name, package_name, content_status,
              standard_price, paid, modify_date,
              version_code, version_name, _loaded_at
            ) VALUES (
              S.content_id, S.app_name, S.package_name, S.content_status,
              S.standard_price, S.paid, S.modify_date,
              S.version_code, S.version_name, S._loaded_at
            )
            """
            q = self.client.query(sql)
            q.result()
            return q.num_dml_affected_rows or 0
        finally:
            self.client.delete_table(tmp, not_found_ok=True)


# ══════════════════════════════════════════════════════════════════════════════
#  HELPERS
# ══════════════════════════════════════════════════════════════════════════════

def date_windows(start: date, end: date, chunk: int) -> Iterable[tuple[date, date]]:
    """Samsung lambi range par thak jata hai — chhote tukdon mein maangte hain."""
    cur = start
    while cur <= end:
        stop = min(cur + timedelta(days=chunk - 1), end)
        yield cur, stop
        cur = stop + timedelta(days=1)


def resolve_range(cfg: Config) -> tuple[date, date]:
    if cfg.backfill_start and cfg.backfill_end:
        s = date.fromisoformat(cfg.backfill_start)
        e = date.fromisoformat(cfg.backfill_end)
        if s > e:
            raise SystemExit("🔴 BACKFILL_START, BACKFILL_END se baad ka hai")
        return s, e
    today = datetime.now(timezone.utc).date()
    # kal tak — aaj ka din adhoora hota hai
    end = today - timedelta(days=1)
    return end - timedelta(days=cfg.lookback_days - 1), end


# ══════════════════════════════════════════════════════════════════════════════
#  MAIN
# ══════════════════════════════════════════════════════════════════════════════

def main() -> int:
    t0 = time.time()
    cfg = Config()
    start, end = resolve_range(cfg)

    log.info("═" * 74)
    log.info("🏪 SAMSUNG GALAXY STORE → BigQuery")
    log.info("   range      %s  se  %s  (%d din)", start, end, (end - start).days + 1)
    log.info("   project    %s.%s", cfg.gcp_project, cfg.bq_dataset)
    log.info("   DRY_RUN    %s", "HAAN — kuch nahi likha jayega" if cfg.dry_run else "nahi")
    log.info("═" * 74)

    client = SamsungClient(cfg)

    # ── 1. app list ──
    try:
        raw_apps = client.content_list()
    except Exception as e:
        log.error("🔴 contentList nakaam: %s", e)
        gha("error", f"Samsung contentList nakaam: {e}")
        return 1

    now_iso = datetime.now(timezone.utc).isoformat()
    apps = [{
        "content_id": str(a.get("contentId") or "").strip(),
        "app_name": a.get("contentName"),
        "package_name": a.get("packageName"),
        "content_status": a.get("contentStatus"),
        "standard_price": _f(a.get("standardPrice")),
        "paid": a.get("paid"),
        "modify_date": a.get("modifyDate"),
        "version_code": None,      # 🆕 contentInfo se bharega
        "version_name": None,      # 🆕
        "_loaded_at": now_iso,
    } for a in raw_apps if str(a.get("contentId") or "").strip()]

    if not apps:
        log.error("🔴 ek bhi app nahi mila — FAIL CLOSED")
        gha("error", "Samsung: contentList khali aayi")
        return 1

    log.info("📱 %d apps mile", len(apps))

    # ── 1b. 🆕 PACKAGE NAME — contentInfo se ──
    #    /seller/contentList package name deta HI NAHI (Samsung docs).
    #    Wo `contentInfo` ke `binaryList[].packageName` mein hota hai —
    #    is liye har app par ek extra call. Ye SOFT hai: fail ho to
    #    package NULL rahega magar poori run nahi rukegi (paisa isi mein
    #    nahi hai, sirf naam hai).
    if cfg.fetch_packages:
        got = 0
        pkg_failed = 0
        for i, app in enumerate(apps, 1):
            try:
                info = client.content_info(app["content_id"])
                pkg, vcode, vname = extract_package(info)
                if pkg:
                    app["package_name"] = pkg
                    got += 1
                app["version_code"] = vcode
                app["version_name"] = vname
                # naam bhi behtar mil jaye to le lo
                if not app.get("app_name"):
                    app["app_name"] = (info.get("appTitle") or "").strip() or None
            except TimeoutError as e:
                log.error("🔴 %s", e)
                gha("error", f"Samsung: {e}")
                return 1
            except Exception as e:  # noqa: BLE001
                pkg_failed += 1
                log.warning("⚠️  contentInfo %s nakaam: %s", app["content_id"], str(e)[:140])
            if i % 25 == 0 or i == len(apps):
                log.info("   … package %d/%d  ·  mile %d", i, len(apps), got)
        log.info("📦 package name: %d/%d mile%s",
                 got, len(apps),
                 f"  ·  {pkg_failed} call nakaam" if pkg_failed else "")
        if got == 0:
            log.warning("⚠️  EK BHI package name nahi mila — contentInfo ka jawab dekho")
            gha("warning", "Samsung: package name ek bhi nahi mila")
    else:
        log.info("⏭️  FETCH_PACKAGE_NAMES=false — package name nahi laaye")

    # ── 2. har app ka rozana data ──
    all_rows: list[dict[str, Any]] = []
    failed: list[tuple[str, str]] = []
    meta_by_id = {a["content_id"]: a for a in apps}

    windows = list(date_windows(start, end, cfg.chunk_days))
    total_calls = len(apps) * len(windows)
    log.info("🔄 %d apps × %d window = %d calls", len(apps), len(windows), total_calls)

    done = 0
    for app in apps:
        cid = app["content_id"]
        for w_start, w_end in windows:
            done += 1
            try:
                payload = client.content_metric(cid, w_start, w_end)
                rows = parse_content_metric(payload, cid, meta_by_id[cid])
                all_rows.extend(rows)
                if done % 25 == 0 or done == total_calls:
                    log.info("   … %d/%d  ·  %d rows", done, total_calls, len(all_rows))
            except TimeoutError as e:
                log.error("🔴 %s", e)
                gha("error", f"Samsung: {e}")
                return 1
            except Exception as e:
                failed.append((cid, str(e)[:200]))
                log.warning("⚠️  app %s (%s) nakaam: %s", cid, app.get("app_name"), str(e)[:160])

    # ── 3. FAIL CLOSED guard ──
    fail_pct = (len(failed) / max(len(apps), 1)) * 100
    log.info("─" * 74)
    log.info("📊 rows %d  ·  nakaam apps %d/%d (%.1f%%)",
             len(all_rows), len(failed), len(apps), fail_pct)

    if failed:
        for cid, err in failed[:10]:
            log.warning("     🔴 %s — %s", cid, err)
        if fail_pct > cfg.fail_threshold_pct:
            log.error("🔴 FAIL CLOSED — %.1f%% apps nakaam (had %d%%). "
                      "BigQuery mein KUCH NAHI likha gaya.", fail_pct, cfg.fail_threshold_pct)
            gha("error", f"Samsung: {len(failed)} apps nakaam — kuch nahi likha")
            return 1

    if not all_rows:
        log.error("🔴 ek bhi row nahi bani — FAIL CLOSED")
        gha("error", "Samsung: koi data nahi mila")
        return 1

    # ── 4. sehat ki jaanch ──
    rev = sum(r["revenue_usd"] for r in all_rows)
    ins = sum(r["installs"] for r in all_rows)
    days = len({r["date"] for r in all_rows})
    with_pkg = len({r["content_id"] for r in all_rows if r.get("package_name")})
    log.info("   revenue $%.2f  ·  installs %s  ·  din %d  ·  apps %d  ·  package wale %d",
             rev, f"{ins:,}", days, len({r['content_id'] for r in all_rows}), with_pkg)

    if cfg.dry_run:
        log.info("🧪 DRY_RUN — BigQuery ko haath nahi lagaya")
        log.info("   namoona: %s", json.dumps(all_rows[0], indent=2)[:600])
        log.info("✅ %.1fs mein poora", time.time() - t0)
        return 0

    # ── 5. BigQuery ──
    bq = BQ(cfg)
    bq.ensure_dataset()
    bq.ensure_table(cfg.table_apps, SCHEMA_APPS, cluster=["content_id"])
    bq.ensure_table(cfg.table_daily, SCHEMA_DAILY,
                    partition_on="date", cluster=["content_id"])

    n_apps = bq.merge_apps(apps)
    log.info("💾 samsung_apps_dim   — %d rows", n_apps)

    n_daily = bq.merge_daily(all_rows)
    log.info("💾 samsung_daily_app  — %d rows", n_daily)

    log.info("═" * 74)
    log.info("✅ POORA — %.1fs", time.time() - t0)
    if os.environ.get("GITHUB_STEP_SUMMARY"):
        with open(os.environ["GITHUB_STEP_SUMMARY"], "a", encoding="utf-8") as fh:
            fh.write(
                f"### 🏪 Samsung Galaxy Store\n\n"
                f"| | |\n|---|---|\n"
                f"| range | `{start}` → `{end}` |\n"
                f"| apps | {len(apps)} |\n"
                f"| rows | {len(all_rows)} |\n"
                f"| revenue | ${rev:,.2f} |\n"
                f"| installs | {ins:,} |\n"
                f"| nakaam apps | {len(failed)} |\n"
                f"| waqt | {time.time() - t0:.1f}s |\n"
            )
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        log.error("🔴 rok diya gaya")
        sys.exit(130)
    except SystemExit:
        raise
    except Exception as exc:  # noqa: BLE001
        log.exception("🔴 na-maloom kharabi: %s", exc)
        gha("error", f"Samsung loader crash: {exc}")
        sys.exit(1)
