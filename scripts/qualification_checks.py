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
    """Bind the actual pod's image reference to the exact built configuration.

    A local kind import can rename an image. Follow only content-addressed
    manifests, checking their hashes and the native Linux platform at each step.
    """
    observed, expected = canonical_digest(observed), canonical_digest(expected)
    for _ in range(3):
        if observed == expected:
            return
        raw = fetch(observed)
        if len(raw) > 1024 * 1024 or "sha256:" + hashlib.sha256(raw).hexdigest() != observed:
            raise IdentityError("container runtime returned mismatching image content")
        try:
            manifest = json.loads(raw)
            if not isinstance(manifest, dict):
                raise IdentityError("image manifest is not an object")
            if "config" in manifest:
                if manifest["config"]["digest"] != expected:
                    raise IdentityError("running image differs from the built configuration")
                return
            matches = [item for item in manifest.get("manifests", [])
                       if item.get("platform", {}).get("architecture") == arch
                       and item.get("platform", {}).get("os") == "linux"]
            if len(matches) != 1:
                raise IdentityError("image index did not identify one native Linux manifest")
            observed = canonical_digest(matches[0]["digest"])
        except (KeyError, TypeError, AttributeError, json.JSONDecodeError) as error:
            raise IdentityError("invalid image manifest structure") from error
    raise IdentityError("image identity exceeded the supported manifest depth")
