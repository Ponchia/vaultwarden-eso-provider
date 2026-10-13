"""Credential-free identity checks shared by qualification fixtures and unit tests."""
from __future__ import annotations

import hashlib
import json
import re
from typing import Callable


class IdentityError(ValueError):
    """A fixed diagnostic that never exposes runtime or credential payloads."""


def canonical_digest(value: str) -> str:
    digest = value.split("://", 1)[-1].rsplit("@", 1)[-1]
    if re.fullmatch(r"sha256:[a-f0-9]{64}", digest) is None:
        raise IdentityError("image identity is not an immutable SHA-256 digest")
    return digest


def verify_native_image(observed: str, expected: str, fetch: Callable[[str], bytes], arch: str) -> None:
    """Resolve pod/build references to equal, hash-verified native configurations.

    kind/containerd can add a platformless import index. That wrapper is not a
    configuration digest. Follow the one unambiguous native manifest and check
    the platform again in its configuration; never treat a mutable tag as proof.
    """
    cache: dict[str, dict] = {}

    def load(digest: str) -> dict:
        if digest not in cache:
            raw = fetch(digest)
            if len(raw) > 1024 * 1024 or "sha256:" + hashlib.sha256(raw).hexdigest() != digest:
                raise IdentityError("container runtime returned mismatching image content")
            manifest = json.loads(raw)
            if not isinstance(manifest, dict):
                raise IdentityError("image content is not an object")
            cache[digest] = manifest
        return cache[digest]

    def config_digest(reference: str) -> str:
        current = canonical_digest(reference)
        for _ in range(5):
            manifest = load(current)
            if "architecture" in manifest and "os" in manifest:
                if manifest["architecture"] != arch or manifest["os"] != "linux":
                    raise IdentityError("image configuration does not match the native Linux platform")
                return current
            if isinstance(manifest.get("config"), dict) and "digest" in manifest["config"]:
                current = canonical_digest(manifest["config"]["digest"])
                continue
            descriptors = manifest.get("manifests", [])
            matches = [item for item in descriptors
                       if item.get("platform", {}).get("architecture") == arch
                       and item.get("platform", {}).get("os") == "linux"]
            unknown = [item for item in descriptors if "platform" not in item]
            # Optional platform fields on a single import/index wrapper are
            # valid OCI. Its eventual configuration must prove the platform.
            if not matches and len(unknown) == 1:
                matches = unknown
            if len(matches) != 1:
                raise IdentityError("image index did not identify one native Linux manifest")
            current = canonical_digest(matches[0]["digest"])
        raise IdentityError("image identity exceeded the supported manifest depth")

    try:
        if config_digest(observed) != config_digest(expected):
            raise IdentityError("running image differs from the built configuration")
    except (KeyError, TypeError, AttributeError, json.JSONDecodeError) as error:
        raise IdentityError("invalid image manifest structure") from error
