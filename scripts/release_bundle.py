#!/usr/bin/env python3
"""Build and verify an explicit public release allowlist; never include scratch."""
from __future__ import annotations

import argparse
import gzip
import hashlib
import io
import json
from pathlib import Path
import re
import struct
import tarfile
from typing import Any

VERSION = re.compile(r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)(?:-[0-9A-Za-z]+(?:[.-][0-9A-Za-z]+)*)?")
REVISION = re.compile(r"[0-9a-f]{40}")
DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
ARCHES = {"amd64": 62, "arm64": 183}
BINARY_MEMBERS = {"vaultwarden-eso-provider", "LICENSE", "THIRD-PARTY-LICENSES.txt"}
MAX_FILE = 64 * 1024 * 1024


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def read_regular(path: Path, limit: int = MAX_FILE) -> bytes:
    require(not path.is_symlink() and path.is_file(), "expected a regular artifact file")
    with path.open("rb") as stream:
        content = stream.read(limit + 1)
    require(0 < len(content) <= limit, "artifact is empty or exceeds its size limit")
    return content


def binary_name(version: str, arch: str) -> str:
    require(VERSION.fullmatch(version) is not None and arch in ARCHES, "invalid version or platform")
    return f"vaultwarden-eso-provider-{version}-linux-{arch}.tar.gz"


def check_elf(data: bytes, arch: str) -> None:
    require(arch in ARCHES and len(data) >= 64 and data[:6] == b"\x7fELF\x02\x01", "expected a 64-bit little-endian ELF binary")
    require(struct.unpack_from("<H", data, 18)[0] == ARCHES[arch], "binary architecture mismatch")


def package(binary: Path, license_file: Path, notices: Path, output: Path, arch: str) -> None:
    contents = {"vaultwarden-eso-provider": read_regular(binary), "LICENSE": read_regular(license_file),
                "THIRD-PARTY-LICENSES.txt": read_regular(notices)}
    check_elf(contents["vaultwarden-eso-provider"], arch)
    # New file only. Deterministic container metadata is not a reproducible-build claim.
    with output.open("xb") as raw, gzip.GzipFile(fileobj=raw, mode="wb", filename="", mtime=0) as zipped:
        with tarfile.open(fileobj=zipped, mode="w") as archive:
            for name in sorted(contents):
                entry = tarfile.TarInfo(name)
                entry.size, entry.mtime, entry.uid, entry.gid = len(contents[name]), 0, 0, 0
                entry.mode = 0o755 if name == "vaultwarden-eso-provider" else 0o644
                archive.addfile(entry, io.BytesIO(contents[name]))
    check_archive(output, arch)


def check_archive(path: Path, arch: str) -> dict[str, str]:
    found: dict[str, str] = {}
    require(not path.is_symlink() and path.is_file(), "missing native archive")
    with tarfile.open(path, "r:gz") as archive:
        for entry in archive:
            require(entry.name in BINARY_MEMBERS and entry.name not in found, "unexpected or duplicate archive member")
            require(entry.isfile() and 0 < entry.size <= MAX_FILE, "unsafe archive member")
            stream = archive.extractfile(entry)
            require(stream is not None, "unreadable archive member")
            data = stream.read(MAX_FILE + 1)
            require(len(data) == entry.size, "archive member size mismatch")
            if entry.name == "vaultwarden-eso-provider":
                check_elf(data, arch)
                require(entry.mode & 0o111 != 0, "binary is not executable")
            found[entry.name] = hashlib.sha256(data).hexdigest()
    require(set(found) == BINARY_MEMBERS, "native archive is incomplete")
    return found


def asset_names(version: str) -> list[str]:
    require(VERSION.fullmatch(version) is not None, "invalid release version")
    return [f"vaultwarden-eso-provider-{version}.tgz", "THIRD-PARTY-LICENSES.txt", *[
        name for arch in ARCHES for name in (binary_name(version, arch), f"sbom-linux-{arch}.spdx.json")]]


def inventory(directory: Path, version: str) -> list[dict[str, Any]]:
    result = []
    for name in asset_names(version):
        data = read_regular(directory / name)
        if name.endswith(".spdx.json"):
            sbom = json.loads(data)
            require(isinstance(sbom, dict) and str(sbom.get("spdxVersion", "")).startswith("SPDX-")
                    and sbom.get("SPDXID") == "SPDXRef-DOCUMENT", "invalid SPDX document")
        result.append({"name": name, "sha256": hashlib.sha256(data).hexdigest(), "bytes": len(data)})
    for arch in ARCHES:
        members = check_archive(directory / binary_name(version, arch), arch)
        require(members["THIRD-PARTY-LICENSES.txt"] == hashlib.sha256(read_regular(directory / "THIRD-PARTY-LICENSES.txt")).hexdigest(),
                "native archive notices differ from the published notices")
    return result


def manifest(directory: Path, version: str, revision: str, image_digest: str, chart_digest: str) -> dict[str, Any]:
    require(REVISION.fullmatch(revision) is not None, "invalid source revision")
    require(DIGEST.fullmatch(image_digest) is not None and DIGEST.fullmatch(chart_digest) is not None, "invalid registry digest")
    return {"schemaVersion": 1, "version": version, "sourceRevision": revision,
            "imageIndexDigest": image_digest, "ociChartDigest": chart_digest,
            "artifacts": inventory(directory, version)}


def write_bundle(directory: Path, version: str, revision: str, image: str, chart: str) -> None:
    record = manifest(directory, version, revision, image, chart)
    with (directory / "release-manifest.json").open("x", encoding="utf-8") as output:
        output.write(json.dumps(record, indent=2) + "\n")
    names = asset_names(version) + ["release-manifest.json"]
    with (directory / "SHA256SUMS").open("x", encoding="ascii") as output:
        for name in sorted(names):
            output.write(hashlib.sha256(read_regular(directory / name)).hexdigest() + "  " + name + "\n")


def verify(directory: Path) -> None:
    record = json.loads(read_regular(directory / "release-manifest.json"))
    require(set(record) == {"schemaVersion", "version", "sourceRevision", "imageIndexDigest", "ociChartDigest", "artifacts"}
            and record["schemaVersion"] == 1, "unknown release manifest shape")
    expected = manifest(directory, record["version"], record["sourceRevision"], record["imageIndexDigest"], record["ociChartDigest"])
    require(record == expected, "release manifest does not match downloaded assets")
    expected_sums = "".join(hashlib.sha256(read_regular(directory / name)).hexdigest() + "  " + name + "\n"
                            for name in sorted(asset_names(record["version"]) + ["release-manifest.json"]))
    require(read_regular(directory / "SHA256SUMS").decode("ascii") == expected_sums, "checksum allowlist differs from expected assets")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    pack = sub.add_parser("package")
    for key in ("binary", "license", "notices", "output"):
        pack.add_argument("--" + key, type=Path, required=True)
    pack.add_argument("--arch", choices=ARCHES, required=True)
    build = sub.add_parser("manifest")
    build.add_argument("--directory", type=Path, required=True)
    for key in ("version", "revision", "image", "chart"):
        build.add_argument("--" + key, required=True)
    check = sub.add_parser("verify")
    check.add_argument("--directory", type=Path, required=True)
    args = parser.parse_args()
    if args.command == "package":
        package(args.binary, args.license, args.notices, args.output, args.arch)
    elif args.command == "manifest":
        write_bundle(args.directory, args.version, args.revision, args.image, args.chart)
    else:
        verify(args.directory)
    print("Release bundle " + args.command + " passed.")


if __name__ == "__main__":
    try:
        main()
    except (ValueError, OSError, tarfile.TarError, KeyError, TypeError) as error:
        raise SystemExit("Release bundle failed: " + type(error).__name__) from None
