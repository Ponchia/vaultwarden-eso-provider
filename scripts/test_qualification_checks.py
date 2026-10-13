"""Fast qualification regressions: no account, Docker, cluster, or crypto dependencies."""
import hashlib
import json
import unittest

from qualification_checks import IdentityError, canonical_digest, verify_native_image


class ImageIdentityTests(unittest.TestCase):
    def setUp(self):
        self.objects = {}
        self.expected = self.store({"architecture": "arm64", "os": "linux", "rootfs": {"diff_ids": []}})
        self.manifest = self.store({"config": {"digest": self.expected}})

    def store(self, value):
        raw = json.dumps(value).encode()
        digest = "sha256:" + hashlib.sha256(raw).hexdigest()
        self.objects[digest] = raw
        return digest

    def verify(self, observed, expected=None, arch="arm64"):
        verify_native_image(observed, expected or self.expected, self.objects.__getitem__, arch)

    def test_normalizes_imported_repository_and_runtime_scheme(self):
        self.assertEqual(canonical_digest("docker-pullable://docker.io/library/import-2026@" + self.expected), self.expected)

    def test_rejects_tags_and_invalid_digests(self):
        for value in ("latest", "repo:version", "sha256:short", "sha256:" + "A" * 64):
            with self.subTest(value=value), self.assertRaises(IdentityError):
                canonical_digest(value)

    def test_accepts_exact_config_and_still_verifies_platform(self):
        self.verify(self.expected)
        with self.assertRaises(IdentityError):
            self.verify(self.expected, arch="amd64")

    def test_follows_manifest_and_checks_config(self):
        self.verify("repo@" + self.manifest)
        other = self.store({"architecture": "arm64", "os": "linux", "rootfs": {"diff_ids": ["different"]}})
        with self.assertRaises(IdentityError):
            self.verify(self.manifest, expected=other)

    def test_rejects_content_that_does_not_match_its_digest(self):
        with self.assertRaises(IdentityError):
            verify_native_image(self.manifest, self.expected, lambda _: b"{}", "arm64")

    def test_selects_only_the_native_linux_manifest(self):
        index = self.store({"manifests": [
            {"platform": {"os": "linux", "architecture": "arm64"}, "digest": self.manifest},
            {"platform": {"os": "linux", "architecture": "amd64"}, "digest": "sha256:" + "c" * 64}]})
        self.verify(index)
        with self.assertRaises(IdentityError):
            self.verify(index, arch="ppc64le")

    def test_accepts_platformless_import_wrapper_without_skipping_config_check(self):
        index = self.store({"manifests": [{"digest": self.manifest}]})
        self.verify("repo@" + index)
        self.verify(index, expected=self.manifest)
        with self.assertRaises(IdentityError):
            self.verify(index, arch="amd64")

    def test_multiple_unknown_platforms_are_ambiguous(self):
        entry = {"digest": self.manifest}
        index = self.store({"manifests": [entry, entry]})
        with self.assertRaises(IdentityError):
            self.verify(index)

    def test_duplicate_matching_platforms_are_ambiguous(self):
        entry = {"platform": {"os": "linux", "architecture": "arm64"}, "digest": self.manifest}
        index = self.store({"manifests": [entry, entry]})
        with self.assertRaises(IdentityError):
            self.verify(index)

    def test_invalid_structures_fail_with_safe_diagnostics(self):
        for value in ([], {"config": None}, {"manifests": ["invalid"]}, {"config": {}}):
            with self.subTest(value=value), self.assertRaises(IdentityError):
                self.verify(self.store(value))

    def test_manifest_indirection_is_bounded(self):
        digest = self.manifest
        for _ in range(5):
            digest = self.store({"manifests": [{"platform": {"os": "linux", "architecture": "arm64"}, "digest": digest}]})
        with self.assertRaises(IdentityError):
            self.verify(digest)


if __name__ == "__main__":
    unittest.main()
