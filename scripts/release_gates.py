#!/usr/bin/env python3
"""Require exact-commit GitHub Actions evidence before publishing any tag."""
from __future__ import annotations

import json
import os
import subprocess

REQUIRED = ("Rust", "Minimum Rust", "License notices", "Helm", "Security", "Docker", "CodeQL Rust",
            "CodeQL Actions", "Vaultwarden and ESO", "Packaged provider (amd64)",
            "Packaged provider (arm64)")


def validate(data: dict, revision: str) -> None:
    checks = data.get("check_runs", [])
    if data.get("total_count") != len(checks):
        raise ValueError("incomplete check-run response")
    for name in REQUIRED:
        matching = [c for c in checks if c.get("name") == name and
                    c.get("head_sha") == revision and c.get("app", {}).get("id") == 15368]
        newest = max(matching, key=lambda c: c["id"], default={})
        if newest.get("status") != "completed" or newest.get("conclusion") != "success":
            raise ValueError("required exact-commit check has not passed: " + name)


def main() -> None:
    revision = os.environ["GITHUB_SHA"]
    result = subprocess.run(["gh", "api", f"repos/{os.environ['GITHUB_REPOSITORY']}/commits/{revision}/check-runs?per_page=100"],
                            check=True, capture_output=True, text=True, timeout=60)
    validate(json.loads(result.stdout), revision)
    print("All required source, attribution and native packaged checks passed on the release commit.")


if __name__ == "__main__":
    try:
        main()
    except (ValueError, KeyError, subprocess.SubprocessError) as error:
        raise SystemExit(str(error)) from None
