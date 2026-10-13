"""Adversarial public artifact checks, requiring no network or credentials."""
import hashlib
import io
import json
from pathlib import Path
import struct
import tarfile
import tempfile
import unittest

from release_bundle import asset_names, binary_name, check_archive, check_elf, package, verify, write_bundle


class ReleaseBundleTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.version = "0.5.0"
        self.license = self.root / "LICENSE"
        self.notices = self.root / "THIRD-PARTY-LICENSES.txt"
        self.license.write_text("Project license fixture")
        self.notices.write_text("Runtime license notices fixture")

    @staticmethod
    def elf(machine=62):
        data = bytearray(64)
        data[:6] = b"\x7fELF\x02\x01"
        struct.pack_into("<H", data, 18, machine)
        return bytes(data)

    def populate(self):
        (self.root / f"vaultwarden-eso-provider-{self.version}.tgz").write_bytes(b"chart fixture")
        for arch, machine in (("amd64", 62), ("arm64", 183)):
            binary = self.root / ("binary-" + arch)
            binary.write_bytes(self.elf(machine))
            package(binary, self.license, self.notices, self.root / binary_name(self.version, arch), arch)
            (self.root / f"sbom-linux-{arch}.spdx.json").write_text(json.dumps({
                "spdxVersion":"SPDX-2.3", "SPDXID":"SPDXRef-DOCUMENT", "name":"provider-linux-" + arch,
                "packages":[{"SPDXID":"SPDXRef-ProviderBinary", "versionInfo":self.version,
                             "checksums":[{"algorithm":"SHA256", "checksumValue":hashlib.sha256(binary.read_bytes()).hexdigest()}]},
                            {"SPDXID":"SPDXRef-Source"}]}))
        (self.root / "release-readiness.json").write_text(json.dumps({"schemaVersion":1, "targetVersion":self.version, "cloud":{"status":"passed"}}))
        write_bundle(self.root, self.version, "a" * 40, "sha256:" + "b" * 64, "sha256:" + "c" * 64)

    def test_roundtrip_and_explicit_allowlist(self):
        (self.root / "sensitive-scratch.env").write_text("Never publish this fixture")
        self.populate()
        verify(self.root)
        record = json.loads((self.root / "release-manifest.json").read_text())
        self.assertEqual({x["name"] for x in record["artifacts"]}, set(asset_names(self.version)))
        self.assertNotIn("sensitive-scratch", (self.root / "SHA256SUMS").read_text())

    def test_modified_payload(self):
        self.populate()
        self.notices.write_text("modified fixture")
        with self.assertRaises(ValueError):
            verify(self.root)

    def test_missing_platform(self):
        self.populate()
        (self.root / binary_name(self.version, "arm64")).unlink()
        with self.assertRaises(ValueError):
            verify(self.root)

    def test_unexpected_checksum_entry(self):
        self.populate()
        sums = self.root / "SHA256SUMS"
        sums.write_text(sums.read_text() + "0" * 64 + "  ../outside\n")
        with self.assertRaises(ValueError):
            verify(self.root)

    def test_rejects_symlink(self):
        self.populate()
        sbom = self.root / "sbom-linux-amd64.spdx.json"
        other = self.root / "other.json"
        sbom.rename(other)
        sbom.symlink_to(other)
        with self.assertRaises(ValueError):
            verify(self.root)

    def test_rejects_wrong_elf(self):
        for data in (b"hello", self.elf(183), b"\x7fELF\x01\x01" + b"\0" * 58):
            with self.assertRaises(ValueError):
                check_elf(data, "amd64")

    def test_deterministic_archive_and_no_overwrite(self):
        source = self.root / "provider"
        source.write_bytes(self.elf())
        one, two = self.root / "one.tar.gz", self.root / "two.tar.gz"
        package(source, self.license, self.notices, one, "amd64")
        package(source, self.license, self.notices, two, "amd64")
        self.assertEqual(hashlib.sha256(one.read_bytes()).digest(), hashlib.sha256(two.read_bytes()).digest())
        with self.assertRaises(FileExistsError):
            package(source, self.license, self.notices, one, "amd64")

    def test_unsafe_archive_member(self):
        for name, kind in (("../outside", tarfile.REGTYPE), ("LICENSE", tarfile.SYMTYPE)):
            output = self.root / "bad.tar.gz"
            with tarfile.open(output, "w:gz") as archive:
                entry = tarfile.TarInfo(name)
                entry.type = kind
                entry.size = 1 if kind == tarfile.REGTYPE else 0
                entry.linkname = "/etc/passwd" if kind == tarfile.SYMTYPE else ""
                archive.addfile(entry, io.BytesIO(b"x") if entry.size else None)
            with self.assertRaises(ValueError):
                check_archive(output, "amd64")

    def test_invalid_version(self):
        for value in ("../0.5.0", "0.5.0\n", "v0.5.0", "00.5.0", "0.5.0;whoami"):
            with self.assertRaises(ValueError):
                asset_names(value)

    def test_spdx_must_contain_dependencies_and_matching_binary(self):
        self.populate()
        path = self.root / "sbom-linux-amd64.spdx.json"
        baseline = json.loads(path.read_text())
        for mode in ("empty", "wrong-binary", "wrong-version", "wrong-platform"):
            obj = json.loads(json.dumps(baseline))
            if mode == "empty": obj["packages"] = obj["packages"][:1]
            elif mode == "wrong-binary": obj["packages"][0]["checksums"][0]["checksumValue"] = "f" * 64
            elif mode == "wrong-version": obj["packages"][0]["versionInfo"] = "0.4.0"
            else: obj["name"] = "provider-linux-arm64"
            path.write_text(json.dumps(obj))
            with self.assertRaises(ValueError):
                verify(self.root)

    def test_stable_distribution_rejects_pending_readiness(self):
        self.populate()
        path = self.root / "release-readiness.json"
        path.write_text(json.dumps({"schemaVersion":1, "targetVersion":self.version, "cloud":{"status":"pending"}}))
        with self.assertRaises(ValueError): verify(self.root)

    def test_invalid_manifest_digest(self):
        with self.assertRaises(ValueError):
            write_bundle(self.root, "0.5.0", "a" * 40, "latest", "sha256:" + "c" * 64)


if __name__ == "__main__":
    unittest.main()
