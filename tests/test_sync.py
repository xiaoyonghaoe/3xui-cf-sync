import base64
import json
import tempfile
import unittest
from pathlib import Path

from sync_to_cf import (
    DEFAULT_CLASH_UA,
    DEFAULT_JSON_UA,
    DEFAULT_RAW_UA,
    SyncConfig,
    aggregate_clients_by_subid,
    build_public_sub_url,
    run_sync,
)


class FakeXuiClient:
    def __init__(self, inbounds, subs_by_id):
        self.inbounds = inbounds
        self.subs_by_id = subs_by_id

    def list_inbounds(self):
        return self.inbounds

    def fetch_subscription(self, sub_id, url_base, user_agent):
        entry = self.subs_by_id.get(sub_id)
        if not entry:
            return 404, {}, ""
        if user_agent == DEFAULT_CLASH_UA:
            return 200, {}, entry.get("clash", "")
        if user_agent == DEFAULT_JSON_UA:
            return 200, {}, entry.get("json", "")
        if user_agent == DEFAULT_RAW_UA:
            return 200, entry.get("headers", {}), entry.get("raw", "")
        return 404, {}, ""


class FakeKVClient:
    def __init__(self):
        self.puts = []
        self.deletes = []

    def bulk_put(self, items):
        self.puts.append(items)

    def bulk_delete(self, keys):
        self.deletes.append(keys)


def make_config(state_file: Path, domain: str = "https://cf.example.com", prefix: str = "") -> SyncConfig:
    return SyncConfig(
        xui_panel_url="http://127.0.0.1:2053",
        xui_api_token="token",
        xui_username="",
        xui_password="",
        xui_insecure_tls=False,
        xui_sub_url="http://127.0.0.1:2096/sub",
        xui_sub_clash_url="",
        xui_sub_json_url="",
        cf_public_domain=domain,
        cf_sub_prefix=prefix,
        cf_account_id="acc",
        cf_api_token="tok",
        cf_kv_namespace_id="ns",
        state_file=state_file,
        traffic_diff_threshold_bytes=10 * 1024 * 1024,
        max_stale_seconds=3600,
        delete_removed_from_kv=True,
        request_timeout=10,
    )


def sample_inbounds():
    return [
        {
            "enable": True,
            "settings": json.dumps(
                {
                    "clients": [
                        {"email": "alice-vless", "subId": "sub_alice_01", "enable": True, "expiryTime": 1893456000000},
                        {"email": "bob-vless", "subId": "sub_bob_02", "enable": True, "expiryTime": 0},
                    ]
                }
            ),
            "clientStats": [
                {"email": "alice-vless", "up": 1000, "down": 2000, "total": 10737418240, "enable": True},
                {"email": "bob-vless", "up": 500, "down": 500, "total": 0, "enable": True},
            ],
        },
        {
            "enable": True,
            "settings": json.dumps(
                {
                    "clients": [
                        {"email": "alice-hy2", "subId": "sub_alice_01", "enable": True, "expiryTime": 1893456000000},
                    ]
                }
            ),
            "clientStats": [
                {"email": "alice-hy2", "up": 300, "down": 700, "total": 10737418240, "enable": True},
            ],
        },
    ]


class SyncTests(unittest.TestCase):
    def test_build_public_sub_url_supports_configurable_domain_and_prefix(self):
        self.assertEqual(build_public_sub_url("sub.example.com", "", "u123"), "https://sub.example.com/u123")
        self.assertEqual(build_public_sub_url("https://sub.example.com/", "/s/", "u123"), "https://sub.example.com/s/u123")

    def test_aggregate_combines_multi_inbound_traffic_by_subid(self):
        agg = aggregate_clients_by_subid(sample_inbounds())
        self.assertEqual(agg["sub_alice_01"]["up"], 1300)
        self.assertEqual(agg["sub_alice_01"]["down"], 2700)
        self.assertEqual(agg["sub_bob_02"]["up"], 500)

    def test_local_diff_skips_unchanged_and_pushes_on_change_or_domain_update(self):
        raw_alice = base64.b64encode(b"vless://uuid@1.1.1.1:443#Alice-A\nhysteria2://pw@1.1.1.1:8443#Alice-B").decode()
        raw_bob = base64.b64encode(b"vless://uuid@1.1.1.1:443#Bob-A").decode()
        subs = {
            "sub_alice_01": {
                "raw": raw_alice,
                "clash": "proxies:\n  - name: Alice-A",
                "json": '{"routing":{"rules":[]}}',
                "headers": {"profile-title": "base64:" + base64.b64encode("Alice套餐".encode()).decode()},
            },
            "sub_bob_02": {"raw": raw_bob, "clash": "proxies:\n  - name: Bob-A", "json": ""},
        }

        with tempfile.TemporaryDirectory() as tmp:
            state_path = Path(tmp) / "state.json"
            inbounds = sample_inbounds()
            xui = FakeXuiClient(inbounds, subs)
            kv = FakeKVClient()
            cfg = make_config(state_path)

            # 1. Initial sync pushes both users
            r1 = run_sync(cfg, xui, kv, now_ts=1000.0, print_urls=True)
            self.assertEqual(r1["pushed"], 2)
            self.assertEqual(r1["skipped"], 0)
            self.assertEqual(len(kv.puts[0]), 2)
            alice_payload = json.loads(kv.puts[0][0]["value"])
            self.assertEqual(alice_payload["title"], "Alice套餐")
            self.assertEqual(len(alice_payload["nodes"]), 2)
            self.assertEqual(r1["urls"]["sub_alice_01"], "https://cf.example.com/sub_alice_01")

            # 2. Repeat with identical data -> 0 KV writes
            r2 = run_sync(cfg, xui, kv, now_ts=1100.0)
            self.assertEqual(r2["pushed"], 0)
            self.assertEqual(r2["skipped"], 2)
            self.assertEqual(len(kv.puts), 1)

            # 3. Small traffic bump below 10MB threshold within max_stale -> skipped
            inbounds[1]["clientStats"][0]["down"] += 1024 * 1024
            r3 = run_sync(cfg, xui, kv, now_ts=1200.0)
            self.assertEqual(r3["pushed"], 0)
            self.assertEqual(r3["skipped"], 2)

            # 4. Large traffic jump >= 10MB -> pushes only alice
            inbounds[1]["clientStats"][0]["down"] += 12 * 1024 * 1024
            r4 = run_sync(cfg, xui, kv, now_ts=1300.0)
            self.assertEqual(r4["pushed"], 1)
            self.assertEqual(r4["skipped"], 1)
            self.assertEqual(kv.puts[-1][0]["key"], "sub:sub_alice_01")

            # 5. Changing CF_PUBLIC_DOMAIN pushes both immediately
            cfg2 = make_config(state_path, domain="https://new-cf.example.com", prefix="v2")
            r5 = run_sync(cfg2, xui, kv, now_ts=1350.0, print_urls=True)
            self.assertEqual(r5["pushed"], 2)
            self.assertEqual(r5["urls"]["sub_bob_02"], "https://new-cf.example.com/v2/sub_bob_02")

            # 6. Deleting bob from 3x-ui triggers KV delete
            inbounds[0]["settings"] = json.dumps(
                {"clients": [{"email": "alice-vless", "subId": "sub_alice_01", "enable": True, "expiryTime": 1893456000000}]}
            )
            r6 = run_sync(cfg2, xui, kv, now_ts=1400.0)
            self.assertEqual(r6["deleted"], 1)
            self.assertEqual(kv.deletes[-1], ["sub:sub_bob_02"])

    def test_ignores_random_reality_sid_rotation(self):
        inbounds = [
            {
                "enable": True,
                "settings": json.dumps(
                    {"clients": [{"email": "alice", "subId": "sub_alice_01", "enable": True, "expiryTime": 0}]}
                ),
                "clientStats": [{"email": "alice", "up": 100, "down": 200, "total": 0, "enable": True}],
            }
        ]
        subs = {
            "sub_alice_01": {
                "raw": base64.b64encode(b"vless://uuid@1.1.1.1:443?security=reality&sid=aaaa1111#Alice").decode(),
                "clash": "proxies:\n  - name: Alice",
                "json": "",
            }
        }
        with tempfile.TemporaryDirectory() as tmp:
            cfg = make_config(Path(tmp) / "state.json")
            xui = FakeXuiClient(inbounds, subs)
            kv = FakeKVClient()

            r1 = run_sync(cfg, xui, kv, now_ts=1000.0)
            self.assertEqual(r1["pushed"], 1)

            # Rotate Reality sid as 3x-ui does per /sub/ request
            subs["sub_alice_01"]["raw"] = base64.b64encode(
                b"vless://uuid@1.1.1.1:443?security=reality&sid=bbbb2222#Alice"
            ).decode()
            r2 = run_sync(cfg, xui, kv, now_ts=1100.0)
            self.assertEqual(r2["pushed"], 0)
            self.assertEqual(r2["skipped"], 1)


if __name__ == "__main__":
    unittest.main()
