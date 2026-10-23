import copy
import json
import subprocess
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch
from vulntriage.advisory import normalize_osv, template
from vulntriage.assessment import assess
from vulntriage.common import component, coverage, now
from vulntriage.inventory import collect_repositories, merge_windows
from vulntriage.report import build_plan, render_report
from vulntriage.versions import match_version, version_key
from vulntriage.verification import verify

ROOT = Path(__file__).resolve().parents[1]
TEST_TEMP = ROOT / ".vulnerability-runs" / "test-temp"
TEST_TEMP.mkdir(parents=True, exist_ok=True)


def advisory():
    return dict(schema_version=1, id="DEMO-001", aliases=["CVE-DEMO"], title="Synthetic test",
                sources=[{"url": "https://vendor.example/DEMO-001", "retrieved_at": now()}],
                source_status="verified", provider="manual", targets=[dict(
                    ecosystem="npm", name="demo-widget", version_scheme="semver",
                    affected_ranges=[{"introduced": "1.0.0", "fixed": "1.2.3"}],
                    fixed_versions=["1.2.3"], prerequisites=["Attacker-controlled input reaches parse()"])])


def inventory(version="1.2.2", kind="resolved"):
    stamp = (datetime.now(timezone.utc) - timedelta(seconds=2)).isoformat()
    return dict(schema_version=1, collected_at=stamp, scopes=["repo"],
                components=[component("npm", "demo-widget", version, "repo/package-lock.json", kind, scope="repo")],
                coverage=[coverage("repo", "lock", "complete", "fixture")])


class MatchingTests(unittest.TestCase):
    def test_semver_release_prerelease_and_build(self):
        self.assertLess(version_key("1.0.0-alpha.2", "semver"), version_key("1.0.0-alpha.10", "semver"))
        self.assertLess(version_key("1.0.0-rc.1", "semver"), version_key("1.0.0", "semver"))
        self.assertEqual(version_key("1.0.0+one", "semver"), version_key("1.0.0+two", "semver"))
        for invalid in ("01.0.0", "1.0", "1.0.0-01", "1.0.0-a..b"):
            with self.assertRaises(ValueError):
                version_key(invalid, "semver")

    def test_numeric_windows_build(self):
        target = {"version_scheme": "numeric", "affected_ranges": [
            {"introduced": "10.0.22631.0", "fixed": "10.0.22631.4000"}]}
        self.assertEqual(match_version("10.0.22631.3999", target)[0], "affected")
        self.assertEqual(match_version("10.0.22631.4000", target)[0], "not_affected")

    def test_range_boundaries_and_malformed_ranges(self):
        target = advisory()["targets"][0]
        self.assertEqual(match_version("1.0.0", target)[0], "affected")
        self.assertEqual(match_version("1.2.3", target)[0], "not_affected")
        target["affected_ranges"] = [{"introduced": "9.0.0", "fixed": "1.0.0"}]
        self.assertEqual(match_version("0.5.0", target)[0], "unknown")
        target["affected_ranges"] = [{"last_affected": "1.2.3"}]
        self.assertEqual(match_version("1.2.3", target)[0], "affected")

    def test_nonexhaustive_list_not_negative_proof(self):
        target = {"version_scheme": "exact", "affected_versions": ["1.0"]}
        self.assertEqual(match_version("1.0", target)[0], "affected")
        self.assertEqual(match_version("1.1", target)[0], "unknown")

    def test_osv_multi_intervals_and_unsupported_ecosystem(self):
        record = {"id": "DEMO", "affected": [{"package": {"name": "demo-widget", "ecosystem": "npm"},
            "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "1.0.0"},
                       {"introduced": "2.0.0"}, {"last_affected": "2.1.0"}]}]}]}
        target = normalize_osv(record)["targets"][0]
        self.assertEqual(match_version("1.5.0", target)[0], "not_affected")
        self.assertEqual(match_version("2.1.0", target)[0], "affected")
        target["osv_ranges"][0]["type"] = "ECOSYSTEM"
        self.assertEqual(match_version("2.1.0", target)[0], "unknown")

    def test_declared_and_stale_are_unknown(self):
        self.assertEqual(assess(advisory(), inventory(kind="declared"))["findings"][0]["applicability"], "unknown")
        inv = inventory()
        inv["collected_at"] = "2000-01-01T00:00:00+00:00"
        self.assertEqual(assess(advisory(), inv)["findings"][0]["applicability"], "unknown")

    def test_unverified_withdrawn_missing_identity(self):
        a = advisory()
        a["source_status"] = "unverified"
        self.assertEqual(assess(a, inventory())["findings"][0]["applicability"], "unknown")
        a["source_status"] = "verified"
        a["withdrawn"] = now()
        self.assertEqual(assess(a, inventory())["findings"][0]["applicability"], "unknown")
        a = advisory()
        inv = inventory()
        inv["components"][0]["name"] = "different-widget"
        result = assess(a, inv)
        self.assertFalse(result["findings"])
        self.assertEqual(result["missing_targets"][0]["status"], "unknown")

    def test_private_registry_does_not_become_public_advisory_match(self):
        inv = inventory()
        inv["components"][0]["provenance"] = "unconfirmed"
        self.assertEqual(assess(advisory(), inv)["findings"][0]["applicability"], "unknown")

    def test_online_alias_and_failure(self):
        a = advisory()
        a["provider"] = "OSV"
        with patch("vulntriage.assessment.query_osv", return_value=[{"id": "GHSA-demo", "aliases": ["CVE-DEMO"]}]):
            self.assertEqual(assess(a, inventory(), True)["findings"][0]["applicability"], "affected")
        with patch("vulntriage.assessment.query_osv", side_effect=TimeoutError):
            self.assertEqual(assess(a, inventory(), True)["findings"][0]["applicability"], "unknown")
        with patch("vulntriage.assessment.query_osv", return_value=[]):
            self.assertEqual(assess(a, inventory(), True)["findings"][0]["applicability"], "not_affected")

    def test_unsupported_versions_remain_unknown(self):
        inv = inventory("vendor-special-build")
        self.assertEqual(assess(advisory(), inv)["findings"][0]["applicability"], "unknown")

    def test_runtime_is_not_inferred_from_affected_version(self):
        result = assess(advisory(), inventory())
        self.assertEqual(result["findings"][0]["applicability"], "affected")
        self.assertEqual(result["findings"][0]["exposure"], "unknown")


class InventoryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=TEST_TEMP)
        self.root = Path(self.temp.name)

    def tearDown(self):
        self.temp.cleanup()

    def put(self, path, value):
        target = self.root / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(value if isinstance(value, str) else json.dumps(value), encoding="utf-8")
        return target

    def test_npm_nested_versions_and_manifest_are_distinct(self):
        self.put("package.json", {"dependencies": {"demo-widget": "^1.0.0"}})
        self.put("package-lock.json", {"lockfileVersion": 3, "packages": {
            "": {"dependencies": {"demo-widget": "^1.0.0"}},
            "node_modules/demo-widget": {"version": "1.2.2", "resolved": "https://registry.npmjs.org/demo-widget/-/x.tgz"},
            "node_modules/parent/node_modules/demo-widget": {"version": "1.2.3"}}})
        result = collect_repositories([self.root])
        records = result["components"]
        self.assertEqual({r["version"] for r in records}, {None, "1.2.2", "1.2.3"})
        self.assertEqual(len({r["asset_key"] for r in records}), 3)
        self.assertEqual(next(r for r in records if r["version"] == "1.2.2")["provenance"], "public_registry")

    def test_npm_v1_chain(self):
        self.put("package-lock.json", {"lockfileVersion": 1, "dependencies": {
            "parent": {"version": "2.0.0", "dependencies": {"child": {"version": "1.0.0"}}}}})
        records = collect_repositories([self.root])["components"]
        self.assertEqual(records[1]["dependency_path"], ["parent", "child"])
        self.assertFalse(records[1]["direct"])

    def test_uv_private_sources_not_public_matches(self):
        self.put("uv.lock", 'version=1\n[[package]]\nname="good"\nversion="1.0"\nsource={registry="https://pypi.org/simple"}\n'
                 '[[package]]\nname="private"\nversion="1.0"\nsource={registry="https://private.example/simple"}\n')
        inv = collect_repositories([self.root])
        self.assertEqual([r["name"] for r in inv["components"]], ["good"])
        self.assertTrue(any(c["status"] == "partial" for c in inv["coverage"]))

    def test_nuget_frameworks_preserved(self):
        self.put("packages.lock.json", {"dependencies": {
            "net8.0": {"Demo": {"type": "Direct", "resolved": "1.0.0"}},
            "net9.0": {"Demo": {"type": "Transitive", "resolved": "2.0.0"}}}})
        records = collect_repositories([self.root])["components"]
        self.assertEqual(len(records), 2)
        self.assertNotEqual(records[0]["asset_key"], records[1]["asset_key"])

    def test_unknown_format_invalid_json_and_scan_cap(self):
        self.put("package-lock.json", "{broken")
        self.put("pnpm-lock.yaml", "packages: {}")
        inv = collect_repositories([self.root])
        self.assertEqual({c["status"] for c in inv["coverage"]}, {"error", "unsupported", "complete"})
        capped = collect_repositories([self.root], max_files=1)
        self.assertEqual(capped["coverage"][-1]["status"], "partial")

    def test_missing_root(self):
        inv = collect_repositories([self.root / "missing"])
        self.assertEqual(inv["coverage"][0]["status"], "error")

    def test_python_environment_reads_metadata_without_execution(self):
        self.put("env/Lib/site-packages/demo_widget-1.0.dist-info/METADATA", "Name: demo-widget\nVersion: 1.0\n\n")
        inv = collect_repositories([], python_envs=[self.root / "env"])
        self.assertEqual(inv["components"][0]["evidence_kind"], "installed")
        self.assertEqual(inv["components"][0]["version"], "1.0")

    def test_go_replacement_is_not_original_version(self):
        self.put("go.mod", "module demo\nrequire example.com/foo v1.2.3\nreplace example.com/foo => ../foo\n")
        inv = collect_repositories([self.root])
        self.assertIsNone(inv["components"][0]["version"])

    def test_windows_timestamp_preserved_on_merge(self):
        old = "2000-01-01T00:00:00+00:00"
        windows = dict(schema_version=1, collected_at=old, scopes=["windows-host"], coverage=[],
                       components=[dict(ecosystem="Windows", name="App", version="1.0",
                                        source="registry", evidence_kind="installed")])
        inv = merge_windows(collect_repositories([]), windows)
        self.assertEqual(inv["components"][0]["observed_at"], old)

    def test_symlink_escape_not_followed(self):
        outside = self.root / "outside"
        outside.mkdir()
        self.put("outside/package.json", {"dependencies": {"secret": "1.0.0"}})
        selected = self.root / "selected"
        selected.mkdir()
        try:
            (selected / "escape").symlink_to(outside, target_is_directory=True)
        except OSError:
            self.skipTest("Symlink creation privilege unavailable")
        inv = collect_repositories([selected])
        self.assertFalse(inv["components"])
        self.assertTrue(any(c["status"] == "unsupported" for c in inv["coverage"]))


class VerificationTests(unittest.TestCase):
    def setUp(self):
        self.a = advisory()
        self.before = assess(self.a, inventory())

    def after(self, version="1.2.3"):
        inv = inventory(version)
        inv["collected_at"] = now()
        return assess(self.a, inv)

    def test_fresh_fixed_component_is_not_full_runtime_verification(self):
        result = verify(self.before, self.after())
        self.assertEqual(result["results"][0]["state"], "component_fix_verified")
        self.assertEqual(result["overall"], "component_fixes_verified_runtime_unverified")

    def test_disappeared_scope_stale_unchanged_advisory(self):
        after = self.after()
        after["findings"] = []
        self.assertEqual(verify(self.before, after)["results"][0]["state"], "unknown")
        after = self.after()
        after["scopes"] = ["other"]
        self.assertEqual(verify(self.before, after)["results"][0]["state"], "unknown")
        self.assertEqual(verify(self.before, self.before)["results"][0]["state"], "unknown")
        after = self.after()
        after["advisory_digest"] = "changed"
        with self.assertRaises(ValueError):
            verify(self.before, after)

    def test_new_affected_copy_blocks_overall_resolution(self):
        after = self.after()
        extra = copy.deepcopy(self.before["findings"][0])
        extra["asset_key"] = "new-copy"
        after["findings"].append(extra)
        self.assertEqual(verify(self.before, after)["overall"], "needs_follow_up")

    def test_remains_affected(self):
        self.assertEqual(verify(self.before, self.after("1.2.2"))["results"][0]["state"], "still_affected")

    def test_no_fixed_release_never_says_upgrade_latest(self):
        assessment = self.before
        assessment["findings"][0]["fixed_versions"] = []
        plan = build_plan(assessment)
        self.assertIn("no fixed version", " ".join(plan["actions"][0]["steps"]).lower())
        self.assertNotIn("latest", render_report(assessment, plan).lower())

    def test_cli_runs_from_other_directory_end_to_end(self):
        with tempfile.TemporaryDirectory(dir=TEST_TEMP) as tmp:
            base = Path(tmp)
            (base / "advisory.json").write_text(json.dumps(self.a))
            (base / "inventory.json").write_text(json.dumps(inventory()))
            def run(*args):
                return subprocess.run([sys.executable, str(ROOT / "scripts/vuln.py"), *map(str, args)],
                                      cwd=tmp, text=True, capture_output=True, check=True)
            run("assess", "--advisory", base / "advisory.json", "--inventory", base / "inventory.json",
                "--out", base / "assessment.json")
            run("report", "--assessment", base / "assessment.json", "--plan-out", base / "plan.json",
                "--out", base / "report.md")
            self.assertIn("demo-widget", (base / "report.md").read_text())
            self.assertEqual(json.loads((base / "plan.json").read_text())["state"], "proposed")

    def test_unresolved_template_produces_no_clean_verdict(self):
        result = assess(template("a vendor says it is vulnerable"), inventory())
        self.assertEqual(result["summary"]["scope_conclusion"], "needs_follow_up")


if __name__ == "__main__":
    unittest.main()
