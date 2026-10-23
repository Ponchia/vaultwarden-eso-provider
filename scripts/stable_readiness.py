#!/usr/bin/env python3
"""Enforce the declared release scope; require fresh Cloud evidence only when claimed."""
from __future__ import annotations

import argparse
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import re

from release_bundle import VERSION, REVISION, readiness_scope, require

ROOT = Path(__file__).resolve().parents[1]
CHECKS = {"api-key-unlock", "field-and-map-reads", "missing-property", "selector-denial", "rotation", "restart", "item-deletion"}
HEX = re.compile(r"[0-9a-f]{64}")


def runtime_fingerprint(root: Path) -> str:
    paths = [root / name for name in ("Cargo.toml", "Cargo.lock", "Dockerfile", ".dockerignore")]
    paths.extend(p for p in (root / "crates").rglob("*") if p.is_file()
                 and "fuzz" not in p.relative_to(root / "crates").parts and "target" not in p.parts
                 and (p.suffix == ".rs" or p.name == "Cargo.toml"))
    paths.extend(p for p in (root / "deploy/helm/vaultwarden-eso-provider").rglob("*") if p.is_file())
    require(len(paths) > 4, "runtime inputs are missing")
    digest = hashlib.sha256()
    for path in sorted(paths):
        require(not path.is_symlink() and path.is_file(), "invalid runtime input")
        digest.update(path.relative_to(root).as_posix().encode() + b"\0")
        digest.update(hashlib.sha256(path.read_bytes()).digest())
    return digest.hexdigest()


def validate(report: dict, version: str, fingerprint: str, now: datetime | None = None) -> str:
    scope = readiness_scope(report, version)
    if scope == "vaultwarden-only":
        # This is a maintainer-selected support boundary, not backend evidence.
        # release_gates.py still requires all exact-head Vaultwarden/native jobs.
        return scope
    cloud = report["cloud"]
    require(isinstance(cloud, dict) and cloud.get("status") == "passed", "fresh dedicated-account Bitwarden Cloud verification is still pending (#75)")
    require(set(cloud) == {"status", "checkedAt", "backend", "sourceRevision", "runtimeInputsSha256", "artifactSha256", "architecture", "checks"},
            "qualification record contains unexpected or missing fields")
    require(cloud["backend"] in ("Bitwarden Cloud EU", "Bitwarden Cloud US") and cloud["architecture"] in ("amd64", "arm64"),
            "unknown qualified backend or platform")
    require(REVISION.fullmatch(cloud["sourceRevision"]) is not None and HEX.fullmatch(cloud["artifactSha256"]) is not None,
            "missing exact source/artifact identity")
    require(cloud["runtimeInputsSha256"] == fingerprint, "runtime inputs changed since the Cloud qualification")
    checked = datetime.fromisoformat(cloud["checkedAt"].replace("Z", "+00:00"))
    now = now or datetime.now(timezone.utc)
    require(checked.tzinfo is not None and now - timedelta(days=30) <= checked <= now + timedelta(minutes=5),
            "Cloud qualification is stale or has an invalid time")
    require(set(cloud["checks"]) == {"pbkdf2", "argon2"}, "both KDFs need live Cloud verification")
    for checks in cloud["checks"].values():
        require(isinstance(checks, list) and len(checks) == len(CHECKS) and set(checks) == CHECKS,
                "Cloud qualification is missing a required behavior")
    return scope


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tag", required=True)
    parser.add_argument("--status", action="store_true", help="Report backend-scope admission only; other release gates and publication approval remain separate")
    args = parser.parse_args()
    require(args.tag.startswith("v") and VERSION.fullmatch(args.tag[1:]) is not None, "invalid release tag")
    fingerprint = runtime_fingerprint(ROOT)
    report = json.loads((ROOT / "docs/release-readiness.json").read_text())
    try:
        scope = validate(report, args.tag[1:], fingerprint)
    except (ValueError, TypeError, KeyError):
        if not args.status:
            raise
        print(json.dumps({"ready": False, "gate": "backend-release-scope", "tag": args.tag,
                          "cloud": "unverified", "runtimeInputsSha256": fingerprint}))
        return
    status = {"ready": True, "gate": "backend-release-scope", "tag": args.tag,
              "releaseScope": scope, "cloud": report["cloud"]["status"],
              "runtimeInputsSha256": fingerprint, "otherReleaseGatesRequired": True}
    if "-" in args.tag:
        # Scope admission does not claim completed stable backend qualification.
        status["prerelease"] = True
    print(json.dumps(status))


if __name__ == "__main__":
    try:
        main()
    except (ValueError, TypeError, KeyError, OSError) as error:
        raise SystemExit("Stable release blocked: " + (str(error) if isinstance(error, ValueError) else type(error).__name__)) from None
