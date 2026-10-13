"""Fast qualification regressions: no account, Docker, cluster, or crypto dependencies."""
import hashlib
import json
import unittest

from qualification_checks import IdentityError, canonical_digest, verify_native_image


class ImageIdentityTests(unittest.TestCase):
    def setUp(self):
        self.expected = "sha256:" + "a" * 64
        self.objects = {}

    def store(self, value):
        raw = json.dumps(value).encode()
        digest = "sha256:" + hashlib.sha256(raw).hexdigest()
        self.objects[digest] = raw
        return digest

    def test_normalizes_imported_repository_and_runtime_scheme(self):
        self.assertEqual(canonical_digest("docker-pullable://docker.io/library/import-2026@" + self.expected), self.expected)

    def test_rejects_tags_and_invalid_digests(self):
        for value in ("latest", "repo:version", "sha256:short", "sha256:" + "A" * 64):
            with self.subTest(value=value), self.assertRaises(IdentityError):
                canonical_digest(value)

    def test_accepts_exact_config_without_lookup(self):
        verify_native_image(self.expected, self.expected, lambda _: self.fail("unexpected lookup"), "arm64")

    def test_follows_manifest_and_checks_config(self):
        digest = self.store({"config": {"digest": self.expected}})
        verify_native_image("repo@" + digest, self.expected, self.objects.__getitem__, "arm64")
        with self.assertRaises(IdentityError):
            verify_native_image(digest, "sha256:" + "b" * 64, self.objects.__getitem__, "arm64")

    def test_rejects_content_that_does_not_match_its_digest(self):
        digest = self.store({"config": {"digest": self.expected}})
        with self.assertRaises(IdentityError):
            verify_native_image(digest, self.expected, lambda _: b"{}", "arm64")

    def test_selects_only_the_native_linux_manifest(self):
        child = self.store({"config": {"digest": self.expected}})
        index = self.store({"manifests": [
            {"platform": {"os": "linux", "architecture": "arm64"}, "digest": child},
            {"platform": {"os": "linux", "architecture": "amd64"}, "digest": "sha256:" + "c" * 64}]})
        verify_native_image(index, self.expected, self.objects.__getitem__, "arm64")
        with self.assertRaises(IdentityError):
            verify_native_image(index, self.expected, self.objects.__getitem__, "ppc64le")

    def test_duplicate_matching_platforms_are_ambiguous(self):
        entry = {"platform": {"os": "linux", "architecture": "arm64"}, "digest": self.expected}
        index = self.store({"manifests": [entry, entry]})
        with self.assertRaises(IdentityError):
            verify_native_image(index, self.expected, self.objects.__getitem__, "arm64")

    def test_invalid_structures_fail_with_safe_diagnostics(self):
        for value in ([], {"config": None}, {"manifests": ["invalid"]}, {"config": {}}):
            digest = self.store(value)
            with self.subTest(value=value), self.assertRaises(IdentityError):
                verify_native_image(digest, self.expected, self.objects.__getitem__, "arm64")

    def test_manifest_indirection_is_bounded(self):
        digest = self.store({"config": {"digest": self.expected}})
        for _ in range(3):
            digest = self.store({"manifests": [{"platform": {"os": "linux", "architecture": "arm64"}, "digest": digest}]})
        with self.assertRaises(IdentityError):
            verify_native_image(digest, self.expected, self.objects.__getitem__, "arm64")


if __name__ == "__main__":
    unittest.main()
