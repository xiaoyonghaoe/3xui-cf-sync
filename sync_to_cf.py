#!/usr/bin/env python3
"""Sync 3x-ui client subscriptions & traffic snapshots to Cloudflare KV with local diff verification."""

from __future__ import annotations

import argparse
import base64
import dataclasses
import hashlib
import http.cookiejar
import json
import os
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


DEFAULT_RAW_UA = "v2rayN/6.60"
DEFAULT_CLASH_UA = "Clash-Verge/2.0"
DEFAULT_JSON_UA = "xray"
KV_BULK_CHUNK_SIZE = 1000


@dataclasses.dataclass
class SyncConfig:
    xui_panel_url: str
    xui_api_token: str
    xui_username: str
    xui_password: str
    xui_insecure_tls: bool
    xui_sub_url: str
    xui_sub_clash_url: str
    xui_sub_json_url: str
    cf_public_domain: str
    cf_sub_prefix: str
    cf_account_id: str
    cf_api_token: str
    cf_kv_namespace_id: str
    state_file: Path
    traffic_diff_threshold_bytes: int
    max_stale_seconds: int
    delete_removed_from_kv: bool
    request_timeout: int


def load_env_file(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    if not path.is_file():
        return values
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, val = line.split("=", 1)
        key = key.strip()
        val = val.strip()
        if len(val) >= 2 and ((val[0] == val[-1] == '"') or (val[0] == val[-1] == "'")):
            val = val[1:-1]
        values[key] = val
    return values


def _bool_env(raw: str | None, default: bool = False) -> bool:
    if raw is None or raw == "":
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _int_env(raw: str | None, default: int) -> int:
    if raw is None or raw.strip() == "":
        return default
    return int(raw.strip())


def normalize_public_domain(raw: str) -> str:
    domain = (raw or "").strip().rstrip("/")
    if not domain:
        return ""
    if not domain.startswith(("http://", "https://")):
        domain = "https://" + domain
    return domain


def normalize_sub_prefix(raw: str) -> str:
    return (raw or "").strip().strip("/")


def build_public_sub_url(public_domain: str, sub_prefix: str, sub_id: str) -> str:
    domain = normalize_public_domain(public_domain)
    prefix = normalize_sub_prefix(sub_prefix)
    path = f"/{prefix}/{sub_id}" if prefix else f"/{sub_id}"
    return f"{domain}{path}" if domain else path


def load_config(env_path: Path | None = None, require_cf: bool = True) -> SyncConfig:
    file_vars = load_env_file(env_path) if env_path else {}

    def get(key: str, default: str = "") -> str:
        val = os.environ.get(key)
        if val is not None and val != "":
            return val
        return file_vars.get(key, default)

    cf_public_domain = normalize_public_domain(get("CF_PUBLIC_DOMAIN"))
    if require_cf and not cf_public_domain:
        raise ValueError("CF_PUBLIC_DOMAIN is required")

    cf_account_id = get("CF_ACCOUNT_ID").strip()
    cf_api_token = get("CF_API_TOKEN").strip()
    cf_kv_namespace_id = get("CF_KV_NAMESPACE_ID").strip()
    if require_cf and (not cf_account_id or not cf_api_token or not cf_kv_namespace_id):
        raise ValueError("CF_ACCOUNT_ID, CF_API_TOKEN, and CF_KV_NAMESPACE_ID are required")

    threshold_mb = max(0, _int_env(get("TRAFFIC_DIFF_THRESHOLD_MB", "10"), 10))
    stale_min = max(0, _int_env(get("MAX_STALE_MINUTES", "60"), 60))

    return SyncConfig(
        xui_panel_url=get("XUI_PANEL_URL", "http://127.0.0.1:2053").rstrip("/"),
        xui_api_token=get("XUI_API_TOKEN").strip(),
        xui_username=get("XUI_USERNAME").strip(),
        xui_password=get("XUI_PASSWORD").strip(),
        xui_insecure_tls=_bool_env(get("XUI_INSECURE_TLS"), False),
        xui_sub_url=get("XUI_SUB_URL", "http://127.0.0.1:2096/sub").rstrip("/"),
        xui_sub_clash_url=get("XUI_SUB_CLASH_URL").rstrip("/"),
        xui_sub_json_url=get("XUI_SUB_JSON_URL").rstrip("/"),
        cf_public_domain=cf_public_domain,
        cf_sub_prefix=normalize_sub_prefix(get("CF_SUB_PREFIX")),
        cf_account_id=cf_account_id,
        cf_api_token=cf_api_token,
        cf_kv_namespace_id=cf_kv_namespace_id,
        state_file=Path(get("STATE_FILE", ".sync_state.json")),
        traffic_diff_threshold_bytes=threshold_mb * 1024 * 1024,
        max_stale_seconds=stale_min * 60,
        delete_removed_from_kv=_bool_env(get("DELETE_REMOVED_FROM_KV", "true"), True),
        request_timeout=max(3, _int_env(get("REQUEST_TIMEOUT", "15"), 15)),
    )


def _ssl_context(insecure: bool) -> ssl.SSLContext | None:
    if not insecure:
        return None
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


class XuiClient:
    def __init__(self, cfg: SyncConfig):
        self.cfg = cfg
        self.cookie_jar = http.cookiejar.CookieJar()
        handlers: list[urllib.request.BaseHandler] = [urllib.request.HTTPCookieProcessor(self.cookie_jar)]
        ctx = _ssl_context(cfg.xui_insecure_tls)
        if ctx is not None:
            handlers.append(urllib.request.HTTPSHandler(context=ctx))
        self.opener = urllib.request.build_opener(*handlers)
        self._logged_in = False

    def _request(
        self,
        url: str,
        method: str = "GET",
        headers: dict[str, str] | None = None,
        data: bytes | None = None,
    ) -> tuple[int, dict[str, str], bytes]:
        req = urllib.request.Request(url, data=data, method=method)
        for k, v in (headers or {}).items():
            req.add_header(k, v)
        try:
            with self.opener.open(req, timeout=self.cfg.request_timeout) as resp:
                resp_headers = {k.lower(): v for k, v in resp.headers.items()}
                return resp.status, resp_headers, resp.read()
        except urllib.error.HTTPError as err:
            resp_headers = {k.lower(): v for k, v in (err.headers.items() if err.headers else [])}
            return err.code, resp_headers, err.read()

    def ensure_auth(self) -> dict[str, str]:
        if self.cfg.xui_api_token:
            return {"Authorization": f"Bearer {self.cfg.xui_api_token}"}
        if not self._logged_in:
            if not self.cfg.xui_username or not self.cfg.xui_password:
                raise RuntimeError("Either XUI_API_TOKEN or XUI_USERNAME/XUI_PASSWORD is required")
            payload = urllib.parse.urlencode(
                {"username": self.cfg.xui_username, "password": self.cfg.xui_password}
            ).encode("utf-8")
            status, _, body = self._request(
                f"{self.cfg.xui_panel_url}/login",
                method="POST",
                headers={"Content-Type": "application/x-www-form-urlencoded", "X-Requested-With": "XMLHttpRequest"},
                data=payload,
            )
            if status != 200:
                raise RuntimeError(f"3x-ui login failed with HTTP {status}: {body.decode('utf-8', 'replace')}")
            parsed = json.loads(body.decode("utf-8"))
            if not parsed.get("success"):
                raise RuntimeError(f"3x-ui login rejected: {parsed.get('msg')}")
            self._logged_in = True
        return {}

    def list_inbounds(self) -> list[dict[str, Any]]:
        auth_headers = self.ensure_auth()
        auth_headers["X-Requested-With"] = "XMLHttpRequest"
        status, _, body = self._request(f"{self.cfg.xui_panel_url}/panel/api/inbounds/list", headers=auth_headers)
        if status != 200:
            raise RuntimeError(f"Failed to fetch inbounds/list: HTTP {status}")
        parsed = json.loads(body.decode("utf-8"))
        if not parsed.get("success"):
            raise RuntimeError(f"3x-ui inbounds/list error: {parsed.get('msg')}")
        obj = parsed.get("obj")
        return obj if isinstance(obj, list) else []

    def fetch_subscription(self, sub_id: str, url_base: str, user_agent: str) -> tuple[int, dict[str, str], str]:
        target = f"{url_base.rstrip('/')}/{urllib.parse.quote(sub_id)}"
        status, headers, body = self._request(
            target,
            headers={"User-Agent": user_agent, "Accept": "*/*"},
        )
        return status, headers, body.decode("utf-8", errors="replace")


def decode_nodes_from_raw(raw_payload: str) -> list[str]:
    text = (raw_payload or "").strip()
    if not text:
        return []
    # 3x-ui returns base64-encoded newline-separated URIs when subEncrypt=true
    if "://" not in text:
        padded = text + "=" * (-len(text) % 4)
        try:
            decoded = base64.b64decode(padded.encode("ascii"), validate=False).decode("utf-8", errors="replace")
            if "://" in decoded:
                text = decoded
        except Exception:
            pass
    return [line.strip() for line in text.splitlines() if line.strip() and "://" in line]


def parse_userinfo_header(header_val: str) -> dict[str, int]:
    out: dict[str, int] = {}
    for part in (header_val or "").split(";"):
        part = part.strip()
        if "=" not in part:
            continue
        k, v = part.split("=", 1)
        try:
            out[k.strip().lower()] = int(v.strip())
        except ValueError:
            continue
    return out


def aggregate_clients_by_subid(inbounds: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    users: dict[str, dict[str, Any]] = {}

    for inbound in inbounds:
        inbound_enabled = bool(inbound.get("enable", True))
        settings_raw = inbound.get("settings") or "{}"
        try:
            settings_obj = json.loads(settings_raw) if isinstance(settings_raw, str) else settings_raw
        except json.JSONDecodeError:
            settings_obj = {}

        stats_by_email: dict[str, dict[str, Any]] = {}
        for stat in inbound.get("clientStats") or []:
            email = str(stat.get("email") or "").strip()
            if email:
                stats_by_email[email] = stat

        for client in (settings_obj or {}).get("clients") or []:
            sub_id = str(client.get("subId") or "").strip()
            if not sub_id:
                continue
            email = str(client.get("email") or "").strip()
            stat = stats_by_email.get(email, {})

            client_enabled = inbound_enabled and bool(client.get("enable", True)) and bool(stat.get("enable", True))
            up = int(stat.get("up") or 0)
            down = int(stat.get("down") or 0)
            total = int(stat.get("total") or client.get("totalGB") or 0)
            expiry = int(stat.get("expiryTime") or client.get("expiryTime") or 0)

            entry = users.get(sub_id)
            if entry is None:
                users[sub_id] = {
                    "subId": sub_id,
                    "email": email,
                    "enable": client_enabled,
                    "up": up,
                    "down": down,
                    "total": total,
                    "expiryTime": expiry,
                }
            else:
                if email and email not in entry["email"].split(","):
                    entry["email"] = f"{entry['email']},{email}" if entry["email"] else email
                entry["enable"] = entry["enable"] or client_enabled
                entry["up"] += up
                entry["down"] += down
                if total > 0 and (entry["total"] == 0 or total < entry["total"]):
                    entry["total"] = total
                if expiry > entry["expiryTime"]:
                    entry["expiryTime"] = expiry

    return users


def build_user_snapshot(client_meta: dict[str, Any], xui: XuiClient, cfg: SyncConfig) -> dict[str, Any]:
    sub_id = client_meta["subId"]
    raw_status, raw_headers, raw_body = xui.fetch_subscription(sub_id, cfg.xui_sub_url, DEFAULT_RAW_UA)
    if raw_status != 200:
        raw_body = ""
        raw_headers = {}

    clash_base = cfg.xui_sub_clash_url or cfg.xui_sub_url
    clash_status, _, clash_body = xui.fetch_subscription(sub_id, clash_base, DEFAULT_CLASH_UA)
    if clash_status != 200:
        clash_body = ""

    json_base = cfg.xui_sub_json_url or cfg.xui_sub_url
    json_status, _, json_body = xui.fetch_subscription(sub_id, json_base, DEFAULT_JSON_UA)
    if json_status != 200 or not json_body.lstrip().startswith(("{", "[")):
        json_body = ""

    header_info = parse_userinfo_header(raw_headers.get("subscription-userinfo", ""))
    up = header_info.get("upload", client_meta["up"])
    down = header_info.get("download", client_meta["down"])
    total = header_info.get("total", client_meta["total"])
    expiry_ms = header_info["expire"] * 1000 if "expire" in header_info else client_meta["expiryTime"]

    title = client_meta["email"] or sub_id
    profile_title_hdr = raw_headers.get("profile-title", "")
    if profile_title_hdr.startswith("base64:"):
        try:
            title = base64.b64decode(profile_title_hdr[7:].encode("ascii")).decode("utf-8")
        except Exception:
            pass

    return {
        "subId": sub_id,
        "email": client_meta["email"],
        "title": title,
        "enable": bool(client_meta["enable"]),
        "up": max(0, int(up)),
        "down": max(0, int(down)),
        "total": max(0, int(total)),
        "expiryTime": max(0, int(expiry_ms)),
        "nodes": decode_nodes_from_raw(raw_body),
        "raw": raw_body.strip(),
        "clash": clash_body.strip(),
        "json": json_body.strip(),
        "publicDomain": cfg.cf_public_domain,
        "subPrefix": cfg.cf_sub_prefix,
    }


def _canonical_json(obj: Any) -> str:
    return json.dumps(obj, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def compute_content_hash(snapshot: dict[str, Any]) -> str:
    """Hash everything except mutable usage counters (up/down) and syncedAt."""
    stable = {k: v for k, v in snapshot.items() if k not in {"up", "down", "syncedAt"}}
    return hashlib.sha256(_canonical_json(stable).encode("utf-8")).hexdigest()


def compute_full_hash(snapshot: dict[str, Any]) -> str:
    """Hash complete snapshot excluding syncedAt."""
    stable = {k: v for k, v in snapshot.items() if k != "syncedAt"}
    return hashlib.sha256(_canonical_json(stable).encode("utf-8")).hexdigest()


def should_push_snapshot(
    snapshot: dict[str, Any],
    prev_entry: dict[str, Any] | None,
    threshold_bytes: int,
    max_stale_seconds: int,
    now_ts: float,
    force: bool = False,
) -> tuple[bool, str]:
    if force or prev_entry is None:
        return True, "new_or_forced"

    full_hash = compute_full_hash(snapshot)
    if prev_entry.get("full_hash") == full_hash:
        return False, "unchanged"

    content_hash = compute_content_hash(snapshot)
    if prev_entry.get("content_hash") != content_hash:
        return True, "config_or_status_changed"

    # Only traffic (up/down) changed
    prev_used = int(prev_entry.get("used_bytes") or 0)
    curr_used = int(snapshot.get("up", 0)) + int(snapshot.get("down", 0))
    if abs(curr_used - prev_used) >= threshold_bytes:
        return True, "traffic_threshold_reached"

    last_pushed = float(prev_entry.get("pushed_at") or 0)
    if max_stale_seconds > 0 and (now_ts - last_pushed) >= max_stale_seconds:
        return True, "stale_refresh"

    return False, "below_traffic_threshold"


class CloudflareKVClient:
    def __init__(self, account_id: str, namespace_id: str, api_token: str, timeout: int = 15):
        self.base_url = (
            f"https://api.cloudflare.com/client/v4/accounts/{account_id}"
            f"/storage/kv/namespaces/{namespace_id}"
        )
        self.api_token = api_token
        self.timeout = timeout

    def _call(self, method: str, suffix: str, body_obj: Any) -> dict[str, Any]:
        data = json.dumps(body_obj, ensure_ascii=False).encode("utf-8")
        req = urllib.request.Request(
            f"{self.base_url}{suffix}",
            data=data,
            method=method,
            headers={
                "Authorization": f"Bearer {self.api_token}",
                "Content-Type": "application/json",
            },
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                parsed = json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as err:
            detail = err.read().decode("utf-8", "replace")
            raise RuntimeError(f"Cloudflare KV API HTTP {err.code}: {detail}") from err

        if not parsed.get("success"):
            raise RuntimeError(f"Cloudflare KV API error: {parsed.get('errors')}")
        return parsed

    def bulk_put(self, items: list[dict[str, str]]) -> None:
        for i in range(0, len(items), KV_BULK_CHUNK_SIZE):
            chunk = items[i : i + KV_BULK_CHUNK_SIZE]
            self._call("PUT", "/bulk", chunk)

    def bulk_delete(self, keys: list[str]) -> None:
        for i in range(0, len(keys), KV_BULK_CHUNK_SIZE):
            chunk = keys[i : i + KV_BULK_CHUNK_SIZE]
            self._call("DELETE", "/bulk", chunk)


def load_state(path: Path) -> dict[str, Any]:
    if not path.is_file():
        return {"users": {}}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(data, dict) and isinstance(data.get("users"), dict):
            return data
    except Exception:
        pass
    return {"users": {}}


def save_state(path: Path, state: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(state, ensure_ascii=False, indent=2), encoding="utf-8")
    tmp.replace(path)


def run_sync(
    cfg: SyncConfig,
    xui: XuiClient,
    kv: CloudflareKVClient | None,
    dry_run: bool = False,
    force: bool = False,
    print_urls: bool = False,
    now_ts: float | None = None,
) -> dict[str, Any]:
    ts = now_ts if now_ts is not None else time.time()
    synced_iso = datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    inbounds = xui.list_inbounds()
    users_meta = aggregate_clients_by_subid(inbounds)
    state = load_state(cfg.state_file)
    prev_users: dict[str, dict[str, Any]] = state.get("users", {})

    to_put: list[dict[str, str]] = []
    next_state_users: dict[str, dict[str, Any]] = {}
    stats = {"total": len(users_meta), "pushed": 0, "skipped": 0, "deleted": 0}
    urls: dict[str, str] = {}

    for sub_id, meta in sorted(users_meta.items()):
        snapshot = build_user_snapshot(meta, xui, cfg)
        prev_entry = prev_users.get(sub_id)
        push, reason = should_push_snapshot(
            snapshot,
            prev_entry,
            cfg.traffic_diff_threshold_bytes,
            cfg.max_stale_seconds,
            ts,
            force=force,
        )
        urls[sub_id] = build_public_sub_url(cfg.cf_public_domain, cfg.cf_sub_prefix, sub_id)

        if push:
            payload = {**snapshot, "syncedAt": synced_iso}
            to_put.append({"key": f"sub:{sub_id}", "value": json.dumps(payload, ensure_ascii=False)})
            next_state_users[sub_id] = {
                "full_hash": compute_full_hash(snapshot),
                "content_hash": compute_content_hash(snapshot),
                "used_bytes": snapshot["up"] + snapshot["down"],
                "pushed_at": ts,
                "reason": reason,
            }
            stats["pushed"] += 1
        else:
            assert prev_entry is not None
            next_state_users[sub_id] = prev_entry
            stats["skipped"] += 1

    removed_sub_ids = [sid for sid in prev_users if sid not in users_meta]
    keys_to_delete = [f"sub:{sid}" for sid in removed_sub_ids] if cfg.delete_removed_from_kv else []
    stats["deleted"] = len(keys_to_delete)

    if not dry_run:
        if kv is None:
            raise ValueError("Cloudflare KV client is required when dry_run=False")
        if to_put:
            kv.bulk_put(to_put)
        if keys_to_delete:
            kv.bulk_delete(keys_to_delete)
        save_state(cfg.state_file, {"users": next_state_users, "updated_at": synced_iso})

    if print_urls:
        stats["urls"] = urls
    return stats


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Sync 3x-ui subscriptions to Cloudflare KV")
    parser.add_argument("--env-file", type=Path, default=Path(".env"), help="Path to .env config file")
    parser.add_argument("--dry-run", action="store_true", help="Verify diff locally without writing to Cloudflare KV")
    parser.add_argument("--force", action="store_true", help="Force push all users regardless of local diff cache")
    parser.add_argument("--print-urls", action="store_true", help="Print public Cloudflare subscription URLs")
    args = parser.parse_args(argv)

    cfg = load_config(args.env_file, require_cf=not args.dry_run)
    xui = XuiClient(cfg)
    kv = None if args.dry_run else CloudflareKVClient(cfg.cf_account_id, cfg.cf_kv_namespace_id, cfg.cf_api_token, cfg.request_timeout)

    result = run_sync(cfg, xui, kv, dry_run=args.dry_run, force=args.force, print_urls=args.print_urls)
    print(
        f"[3xui-cf-sync] total={result['total']} pushed={result['pushed']} "
        f"skipped={result['skipped']} deleted={result['deleted']} dry_run={args.dry_run}"
    )
    if args.print_urls and "urls" in result:
        for sid, url in result["urls"].items():
            print(f"  {sid} -> {url}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
