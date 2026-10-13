#!/usr/bin/env python3
"""Fetch an exact published release for isolated tests; never rebuild its bytes."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import subprocess

TAG = re.compile(r"v(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)(?:-[0-9A-Za-z]+(?:[.-][0-9A-Za-z]+)*)?")
SHA = re.compile(r"[0-9a-f]{40}")
DIGEST = re.compile(r"sha256:[0-9a-f]{64}")


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def evidence(body: str, heading: str, pattern: re.Pattern[str]) -> str:
    matches = re.findall(r"^- " + re.escape(heading) + r": `([^`]+)`$", body, re.MULTILINE)
    require(len(matches) == 1 and pattern.fullmatch(matches[0]) is not None,
            "missing, duplicate or invalid release evidence: " + heading)
    return matches[0]


def run(args: list[str]) -> str:
    result = subprocess.run(args, check=True, text=True, stdout=subprocess.PIPE, timeout=300)
    return result.stdout


def main() -> None:
    tag = os.environ["RELEASE_TAG"]
    revision = os.environ["QUALIFICATION_REVISION"]
    repo = os.environ["GITHUB_REPOSITORY"]
    require(TAG.fullmatch(tag) is not None, "release_tag must be a version tag")
    require(SHA.fullmatch(revision) is not None, "invalid source revision")
    require(re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repo) is not None, "invalid repository")
    source = run(["gh", "api", f"repos/{repo}/commits/{tag}", "--jq", ".sha"]).strip()
    require(source == revision, "dispatch must select the exact release tag, not another source tree")
    release = json.loads(run(["gh", "release", "view", tag, "--repo", repo, "--json", "body,isDraft,tagName"]))
    require(release["tagName"] == tag and not release["isDraft"], "release is not published")
    body = release["body"]
    require(evidence(body, "Source commit", SHA) == revision, "release source mismatch")
    image_digest = evidence(body, "Image index digest", DIGEST)
    chart_digest = evidence(body, "OCI Helm chart digest", DIGEST)
    chart_sha = evidence(body, "Chart archive SHA256", re.compile(r"[0-9a-f]{64}"))
    destination = Path(os.environ["RUNNER_TEMP"]) / "public-artifacts"
    destination.mkdir(exist_ok=True)
    chart = destination / f"vaultwarden-eso-provider-{tag[1:]}.tgz"
    require(not chart.exists(), "refusing to overwrite a downloaded chart")
    run(["gh", "release", "download", tag, "--repo", repo, "--dir", str(destination),
         "--pattern", chart.name, "--pattern", chart.name + ".sigstore.json"])
    require(hashlib.sha256(chart.read_bytes()).hexdigest() == chart_sha, "chart checksum mismatch")
    workflow = repo + "/.github/workflows/release.yml"
    identity = "https://github.com/" + workflow + "@refs/tags/" + tag
    provenance = ["--repo", repo, "--signer-workflow", workflow, "--source-digest", revision,
                  "--source-ref", "refs/tags/" + tag, "--deny-self-hosted-runners"]
    certificate = ["--certificate-identity", identity, "--certificate-oidc-issuer",
                   "https://token.actions.githubusercontent.com"]
    run(["gh", "attestation", "verify", str(chart), *provenance])
    run(["cosign", "verify-blob", "--bundle", str(chart) + ".sigstore.json", *certificate, str(chart)])
    image = "ghcr.io/" + repo.lower() + "@" + image_digest
    run(["cosign", "verify", *certificate, image])
    run(["gh", "attestation", "verify", "oci://" + image, *provenance])
    # Also prove the installable OCI chart contains the exact signed archive.
    oci_dir = Path(os.environ["RUNNER_TEMP"]) / "oci-chart"
    oci_dir.mkdir(exist_ok=True)
    run(["helm", "pull", "oci://ghcr.io/" + repo.split('/')[0].lower() +
         "/charts/vaultwarden-eso-provider", "--version", tag[1:], "--destination", str(oci_dir)])
    require(hashlib.sha256((oci_dir / chart.name).read_bytes()).hexdigest() == chart_sha,
            "OCI chart differs from signed release archive")
    run(["docker", "pull", image])
    run(["docker", "tag", image, "bweso-candidate:" + revision])
    with open(os.environ["GITHUB_ENV"], "a", encoding="utf-8") as output:
        output.write(f"QUALIFICATION_RELEASE_IMAGE_DIGEST={image_digest}\n")
        output.write(f"QUALIFICATION_RELEASE_CHART_DIGEST={chart_digest}\n")
    print("Published chart and image signatures, provenance, source and chart bytes verified.")


if __name__ == "__main__":
    try:
        main()
    except (KeyError, ValueError, subprocess.SubprocessError) as error:
        raise SystemExit(f"Release verification failed: {error}") from None
