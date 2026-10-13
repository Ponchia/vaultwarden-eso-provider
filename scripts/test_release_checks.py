"""Pure regression tests for public release metadata and check admission."""
import copy
import re
import unittest

from release_artifacts import TAG, DIGEST, evidence
from release_gates import REQUIRED, validate


class ReleaseChecks(unittest.TestCase):
    def test_version_boundary(self):
        for tag in ("v0.5.0", "v0.5.0-rc.1"):
            self.assertIsNotNone(TAG.fullmatch(tag))
        for tag in ("main", "--help", "v01.2.3", "v1.2.3\n", "v1.2.3;exit"):
            self.assertIsNone(TAG.fullmatch(tag))

    def test_release_evidence(self):
        value = "sha256:" + "a" * 64
        self.assertEqual(evidence(f"- Image index digest: `{value}`\n", "Image index digest", DIGEST), value)
        for body in ("", f"- Image index digest: `{value}`\n" * 2, "- Image index digest: `latest`"):
            with self.assertRaises(ValueError):
                evidence(body, "Image index digest", DIGEST)

    def baseline(self):
        checks = [{"id":i, "name":name, "head_sha":"a" * 40, "app":{"id":15368},
                   "status":"completed", "conclusion":"success"} for i, name in enumerate(REQUIRED)]
        return {"check_runs":checks, "total_count":len(checks)}

    def test_complete_evidence(self):
        validate(self.baseline(), "a" * 40)

    def test_incomplete_response(self):
        data = self.baseline()
        data["total_count"] += 1
        with self.assertRaises(ValueError):
            validate(data, "a" * 40)

    def test_wrong_actor_revision_missing_or_failed(self):
        for field, value in (("app", {"id":1}), ("head_sha", "b" * 40),
                             ("status", "in_progress"), ("conclusion", "failure"), ("name", "Other")):
            data = self.baseline()
            data["check_runs"][0][field] = value
            with self.assertRaises(ValueError):
                validate(data, "a" * 40)

    def test_new_failure_does_not_reuse_old_success(self):
        data = self.baseline()
        newer = copy.deepcopy(data["check_runs"][0])
        newer.update(id=100, conclusion="failure")
        data["check_runs"].append(newer)
        data["total_count"] += 1
        with self.assertRaises(ValueError):
            validate(data, "a" * 40)


if __name__ == "__main__":
    unittest.main()
