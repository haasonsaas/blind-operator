from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path

from blindop.errors import PolicyDenied
from blindop.gateway import Gateway
from blindop.policy import Label
from blindop.safe_output import SafeOutputBudget, sanitize


class TestSafeOutput(unittest.TestCase):
    def test_redacts_bytes(self) -> None:
        out = sanitize(b"abc")
        self.assertIsInstance(out, dict)
        self.assertEqual(out.get("$redacted"), "bytes")
        self.assertEqual(out.get("len"), 3)

    def test_redacts_long_string(self) -> None:
        out = sanitize("a" * 50, SafeOutputBudget(max_str_len=10))
        self.assertIsInstance(out, dict)
        self.assertEqual(out.get("$redacted"), "string")
        self.assertEqual(out.get("len"), 50)


class TestGatewayWorkflow(unittest.TestCase):
    def test_basic_workflow(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            state_dir = Path(td)
            gw = Gateway(state_dir=state_dir)
            try:
                case = gw.call("case.create", name="unit")
                case_id = case["result"]["case_id"]

                p1 = state_dir / "a.txt"
                p1.write_text("visit https://example.com and email a@b.com 1.2.3.4", encoding="utf-8")
                ing1 = gw.call(
                    "artifact.ingest",
                    case_id=case_id,
                    src_path=p1,
                    label=Label.restricted,
                )
                self.assertEqual(ing1["output_label"], Label.restricted.value)
                a1 = ing1["result"]["handle"]

                p2 = state_dir / "b.txt"
                p2.write_text("visit https://example.com and email a@b.com 1.2.3.4", encoding="utf-8")
                ing2 = gw.call(
                    "artifact.ingest",
                    case_id=case_id,
                    src_path=p2,
                    label=Label.restricted,
                )
                self.assertEqual(ing2["output_label"], Label.restricted.value)
                a2 = ing2["result"]["handle"]

                dd = gw.call("artifact.dedupe", case_id=case_id, include_unique=False)["result"]
                self.assertEqual(dd["group_count"], 1)
                self.assertEqual(dd["groups"][0]["count"], 2)

                gw.call("tag.add", handle=a1, tag="possible_exfil")
                art = gw.call("artifact.show", handle=a1)["result"]
                self.assertIn("possible_exfil", art["tags"])

                iocs_resp = gw.call("iocs.extract", handle=a1, include_hashes=True, top=5)
                self.assertEqual(iocs_resp["output_label"], Label.restricted.value)
                iocs = iocs_resp["result"]
                self.assertIn("counts", iocs)
                self.assertIn("hmac_sha256_top", iocs)

                iocs_kmin = gw.call("iocs.extract", handle=a1, include_hashes=True, top=5, k_min=2)["result"]
                self.assertEqual(iocs_kmin["hash_k_min"], 2)
                self.assertEqual(iocs_kmin["hmac_sha256_top"]["email"], [])

                rules = state_dir / "rules.json"
                rules.write_text(
                    json.dumps({"rules": [{"id": "has_example", "regex": "example\\.com"}]}),
                    encoding="utf-8",
                )
                rp = gw.call("rulepack.scan", handle=a1, rules_path=rules)["result"]
                self.assertEqual(rp["matched_count"], 1)
                self.assertIn("has_example", rp["matched_rule_ids"])

                tl = gw.call("timeline.build", case_id=case_id, limit=50)["result"]
                self.assertGreaterEqual(tl["event_count"], 1)

                df = gw.call("artifact.diff", handle_a=a1, handle_b=a2)["result"]
                self.assertTrue(df["same_blob"])
            finally:
                gw.close()


class TestBudgets(unittest.TestCase):
    def test_iocs_hashed_budget_per_case(self) -> None:
        env_name = "BLINDOP_BUDGET_IOCS_HASHED_PER_CASE"
        prev = os.environ.get(env_name)
        os.environ[env_name] = "1"
        try:
            with tempfile.TemporaryDirectory() as td:
                state_dir = Path(td)
                gw = Gateway(state_dir=state_dir)
                try:
                    case_id = gw.call("case.create", name="b")["result"]["case_id"]
                    p = state_dir / "a.txt"
                    p.write_text("email a@b.com", encoding="utf-8")
                    h = gw.call(
                        "artifact.ingest",
                        case_id=case_id,
                        src_path=p,
                        label=Label.restricted,
                    )["result"]["handle"]

                    gw.call("iocs.extract", handle=h, include_hashes=True, top=5)
                    with self.assertRaises(PolicyDenied):
                        gw.call("iocs.extract", handle=h, include_hashes=True, top=5)
                finally:
                    gw.close()
        finally:
            if prev is None:
                os.environ.pop(env_name, None)
            else:
                os.environ[env_name] = prev

    def test_rulepack_scan_budget_per_case(self) -> None:
        env_name = "BLINDOP_BUDGET_RULEPACK_SCANS_PER_CASE"
        prev = os.environ.get(env_name)
        os.environ[env_name] = "1"
        try:
            with tempfile.TemporaryDirectory() as td:
                state_dir = Path(td)
                gw = Gateway(state_dir=state_dir)
                try:
                    case_id = gw.call("case.create", name="b")["result"]["case_id"]
                    p = state_dir / "a.txt"
                    p.write_text("hello example.com", encoding="utf-8")
                    h = gw.call(
                        "artifact.ingest",
                        case_id=case_id,
                        src_path=p,
                        label=Label.restricted,
                    )["result"]["handle"]

                    rules = state_dir / "rules.json"
                    rules.write_text(json.dumps({"rules": [{"id": "has_example", "regex": "example\\.com"}]}))

                    gw.call("rulepack.scan", handle=h, rules_path=rules)
                    with self.assertRaises(PolicyDenied):
                        gw.call("rulepack.scan", handle=h, rules_path=rules)
                finally:
                    gw.close()
        finally:
            if prev is None:
                os.environ.pop(env_name, None)
            else:
                os.environ[env_name] = prev
