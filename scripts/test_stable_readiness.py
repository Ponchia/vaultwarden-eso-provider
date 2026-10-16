"""Stable admission cannot be satisfied by old or unrelated backend smoke tests."""
import copy
from datetime import datetime, timedelta, timezone
import unittest
import json
from pathlib import Path
import subprocess
import sys
from stable_readiness import CHECKS, validate


class StableReadinessTests(unittest.TestCase):
    def baseline(self):
        return {"schemaVersion":1, "targetVersion":"0.5.0", "cloud":{
            "status":"passed", "checkedAt":datetime.now(timezone.utc).isoformat(),
            "backend":"Bitwarden Cloud EU", "sourceRevision":"a" * 40,
            "runtimeInputsSha256":"b" * 64, "artifactSha256":"c" * 64, "architecture":"arm64",
            "checks":{"pbkdf2":sorted(CHECKS), "argon2":sorted(CHECKS)}}}

    def test_complete_evidence(self):
        validate(self.baseline(), "0.5.0", "b" * 64)

    def test_pending_is_not_pass(self):
        report = self.baseline()
        report["cloud"] = {"status":"pending"}
        with self.assertRaisesRegex(ValueError, "still pending"):
            validate(report, "0.5.0", "b" * 64)

    def test_source_changes_and_wrong_version(self):
        for version, fingerprint in (("0.5.1", "b" * 64), ("0.5.0", "d" * 64)):
            with self.assertRaises(ValueError):
                validate(self.baseline(), version, fingerprint)

    def test_unexpected_private_fields(self):
        report = self.baseline()
        report["cloud"]["accountEmail"] = "fixture@example.invalid"
        with self.assertRaises(ValueError):
            validate(report, "0.5.0", "b" * 64)

    def test_no_reuse_of_old_or_future_run(self):
        for days in (-31, 2):
            report = self.baseline()
            report["cloud"]["checkedAt"] = (datetime.now(timezone.utc) + timedelta(days=days)).isoformat()
            with self.assertRaises(ValueError):
                validate(report, "0.5.0", "b" * 64)

    def test_each_required_behavior(self):
        for kdf in ("pbkdf2", "argon2"):
            for missing in CHECKS:
                report = self.baseline()
                report["cloud"]["checks"][kdf].remove(missing)
                with self.assertRaises(ValueError):
                    validate(report, "0.5.0", "b" * 64)

    def test_disposable_backend_is_not_cloud(self):
        report = self.baseline()
        report["cloud"]["backend"] = "Vaultwarden"
        with self.assertRaises(ValueError):
            validate(report, "0.5.0", "b" * 64)

    def test_no_missing_artifact_identity(self):
        report = self.baseline()
        report["cloud"]["artifactSha256"] = "latest"
        with self.assertRaises(ValueError):
            validate(report, "0.5.0", "b" * 64)


    def scoped(self):
        return {"schemaVersion":2, "targetVersion":"0.5.0", "releaseScope":"vaultwarden-only",
                "cloud":{"status":"deferred", "issue":75}}

    def test_explicit_vaultwarden_scope_is_not_a_cloud_pass(self):
        report = self.scoped()
        original = copy.deepcopy(report)
        self.assertEqual(validate(report, "0.5.0", "b" * 64), "vaultwarden-only")
        self.assertEqual(report, original)
        self.assertEqual(report["cloud"]["status"], "deferred")

    def test_deferred_does_not_pass_the_old_cloud_claim(self):
        report = self.baseline()
        report["cloud"] = self.scoped()["cloud"]
        with self.assertRaisesRegex(ValueError, "still pending"):
            validate(report, "0.5.0", "b" * 64)

    def test_scoped_gate_rejects_wrong_version(self):
        with self.assertRaises(ValueError): validate(self.scoped(), "0.5.1", "b" * 64)

    def test_unknown_or_broadened_scope_requires_a_new_review(self):
        for scope in (None, "", "all", "vaultwarden-and-bitwarden-cloud", ["vaultwarden-only"]):
            with self.subTest(scope=scope):
                report = self.scoped()
                report["releaseScope"] = scope
                with self.assertRaises(ValueError): validate(report, "0.5.0", "b" * 64)

    def test_deferral_needs_exact_explicit_record(self):
        for cloud in ({"status":"pending", "issue":75}, {"status":"passed", "issue":75},
                      {"status":"deferred"}, {"status":"deferred", "issue":"75"},
                      {"status":"deferred", "issue":76}, {"status":"deferred", "issue":True},
                      {"status":"deferred", "issue":75, "accountEmail":"fixture@example.invalid"}, None):
            with self.subTest(cloud=cloud):
                report = self.scoped()
                report["cloud"] = cloud
                with self.assertRaises(ValueError): validate(report, "0.5.0", "b" * 64)

    def test_unknown_shape_and_schema_do_not_disable_admission(self):
        for extra in ({"schemaVersion":3}, {"schemaVersion":True}, {"schemaVersion":"2"},
                      {"skipCloud":True}, {"accountEmail":"fixture@example.invalid"}):
            with self.subTest(extra=extra):
                report = self.scoped() | extra
                with self.assertRaises(ValueError): validate(report, "0.5.0", "b" * 64)
        report = self.scoped()
        del report["releaseScope"]
        with self.assertRaises(ValueError): validate(report, "0.5.0", "b" * 64)

    def test_checked_in_scope_and_cli_agree_without_fabricating_cloud_evidence(self):
        root = Path(__file__).resolve().parents[1]
        report = json.loads((root / "docs/release-readiness.json").read_text())
        self.assertEqual(report, self.scoped() | {"targetVersion":report["targetVersion"]})
        result = subprocess.run([sys.executable, str(root / "scripts/stable_readiness.py"),
                                 "--tag", "v" + report["targetVersion"]],
                                check=True, capture_output=True, text=True, timeout=15)
        status = json.loads(result.stdout)
        self.assertTrue(status["ready"])
        self.assertEqual(status["gate"], "backend-release-scope")
        self.assertEqual(status["releaseScope"], "vaultwarden-only")
        self.assertEqual(status["cloud"], "deferred")
        self.assertTrue(status["otherReleaseGatesRequired"])

    def test_release_keeps_source_and_both_native_vaultwarden_gates(self):
        from release_gates import REQUIRED, validate as validate_checks
        expected = {"Rust", "Minimum Rust", "License notices", "Helm", "Security", "Docker",
                    "CodeQL Rust", "CodeQL Actions", "Vaultwarden and ESO",
                    "Packaged provider (amd64)", "Packaged provider (arm64)"}
        self.assertEqual(set(REQUIRED), expected)
        root = Path(__file__).resolve().parents[1]
        workflow = (root / ".github/workflows/release.yml").read_text()
        self.assertIn("python3 scripts/release_gates.py", workflow)
        self.assertIn('python3 scripts/stable_readiness.py --tag "${GITHUB_REF_NAME}"', workflow)
        self.assertIn('python3 scripts/release_bundle.py verify --directory dist', workflow)
        checks = [{"id":i, "name":name, "head_sha":"a" * 40, "app":{"id":15368},
                   "status":"completed", "conclusion":"success"} for i, name in enumerate(REQUIRED)]
        for missing in REQUIRED:
            with self.subTest(missing=missing):
                remaining = [c for c in checks if c["name"] != missing]
                with self.assertRaises(ValueError):
                    validate_checks({"check_runs":remaining, "total_count":len(remaining)}, "a" * 40)


if __name__ == "__main__":
    unittest.main()
