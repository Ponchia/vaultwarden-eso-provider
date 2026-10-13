"""Stable admission cannot be satisfied by old or unrelated backend smoke tests."""
import copy
from datetime import datetime, timedelta, timezone
import unittest
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


if __name__ == "__main__":
    unittest.main()
