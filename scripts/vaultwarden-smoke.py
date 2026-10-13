#!/usr/bin/env python3
"""Disposable Password Manager interoperability checks. Never use a real vault.

The fixture independently creates encrypted accounts/items with Python crypto,
then exercises the compiled Rust provider against an actual Vaultwarden server.
Optional ESO checks require the explicitly named disposable kind context.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import json
import os
from pathlib import Path
import secrets
import socket
import subprocess
import tempfile
import time
from typing import Any, Callable
import urllib.error
import urllib.parse
import urllib.request
import uuid

from argon2.low_level import Type, hash_secret_raw
from cryptography.hazmat.primitives import padding, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


class SmokeFailure(RuntimeError):
    """A safe diagnostic that does not echo credentials or HTTP payloads."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SmokeFailure(message)


def b64(value: bytes) -> str:
    return base64.b64encode(value).decode("ascii")


def encrypt(key: bytes, value: bytes | str) -> str:
    """Independent fixture encryption for Bitwarden type-2 encrypted strings."""
    plain = value.encode() if isinstance(value, str) else value
    iv = secrets.token_bytes(16)
    padder = padding.PKCS7(128).padder()
    padded = padder.update(plain) + padder.finalize()
    encryptor = Cipher(algorithms.AES(key[:32]), modes.CBC(iv)).encryptor()
    data = encryptor.update(padded) + encryptor.finalize()
    mac = hmac.digest(key[32:], iv + data, "sha256")
    return "2." + "|".join(map(b64, (iv, data, mac)))


def request(url: str, method: str = "GET", data: Any = None,
            token: str | None = None, form: bool = False) -> tuple[int, Any]:
    headers = {"Accept": "application/json", "Bitwarden-Client-Version": "2025.12.0"}
    body = None
    if data is not None:
        body = urllib.parse.urlencode(data).encode() if form else json.dumps(data).encode()
        headers["Content-Type"] = "application/x-www-form-urlencoded" if form else "application/json"
    if token is not None:
        headers["Authorization"] = "Bearer " + token
    req = urllib.request.Request(url, data=body, headers=headers, method=method)
    try:
        response = urllib.request.urlopen(req, timeout=90)
    except urllib.error.HTTPError as error:
        response = error
    with response:
        raw = response.read(1024 * 1024 + 1)
        require(len(raw) <= 1024 * 1024, "fixture response exceeded its size limit")
        if not raw:
            return response.code, None
        try:
            return response.code, json.loads(raw)
        except ValueError:
            return response.code, None


def success(url: str, method: str = "GET", data: Any = None,
            token: str | None = None, form: bool = False) -> Any:
    status, value = request(url, method, data, token, form)
    require(200 <= status < 300, f"fixture request failed: {method} {urllib.parse.urlparse(url).path} HTTP {status}")
    return value


def eventually(check: Callable[[], bool], message: str, seconds: int = 60) -> None:
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        try:
            if check():
                return
        except (OSError, urllib.error.URLError):
            pass
        time.sleep(0.5)
    raise SmokeFailure(message)


class EsoFixture:
    """Namespace-scoped fixture, restricted to this test's disposable cluster."""

    def __init__(self, kubeconfig: Path, namespace: str, webhook_url: str,
                 token: str, item: str):
        self.command = ["kubectl", "--kubeconfig", str(kubeconfig), "--context", "kind-bweso-interop"]
        self.namespace = namespace
        self.items: list[dict[str, Any]] = []
        self.create({"apiVersion": "v1", "kind": "Namespace", "metadata": {"name": namespace}})
        self.create({"apiVersion": "v1", "kind": "Secret", "metadata": {
            "name": "webhook-auth", "namespace": namespace,
            "labels": {"external-secrets.io/type": "webhook"}},
            "stringData": {"token": token}})
        self.create({"apiVersion": "external-secrets.io/v1", "kind": "SecretStore",
            "metadata": {"name": "vaultwarden", "namespace": namespace}, "spec": {"provider": {
                "webhook": {"url": webhook_url + "/v1/resolve", "method": "POST", "timeout": "90s",
                    "headers": {"Content-Type": "application/json", "Authorization": 'Bearer {{ index .auth "token" }}'},
                    "secrets": [{"name": "auth", "secretRef": {"name": "webhook-auth", "key": "token"}}],
                    "body": '{"remoteRef":{"key":{{ .remoteRef.key | toJson }},"property":{{ .remoteRef.property | toJson }}}}',
                    "result": {"jsonPath": "$.data.value"}}}}})
        for policy in ("Delete", "Retain"):
            resource = {"apiVersion": "external-secrets.io/v1", "kind": "ExternalSecret",
                "metadata": {"name": policy.lower(), "namespace": namespace}, "spec": {
                    "refreshInterval": "1s", "secretStoreRef": {"name": "vaultwarden", "kind": "SecretStore"},
                    "target": {"name": "target-" + policy.lower(), "creationPolicy": "Owner", "deletionPolicy": policy},
                    "data": [{"secretKey": "password", "remoteRef": {"key": "id:" + item, "property": "password"}}]}}
            self.create(resource)
            self.items.append(resource)

    def run(self, args: list[str], data: Any = None) -> str:
        result = subprocess.run(self.command + args,
            input=None if data is None else json.dumps(data), text=True, capture_output=True, timeout=45)
        require(result.returncode == 0, "disposable ESO fixture command failed: " + args[0])
        return result.stdout

    def create(self, resource: dict[str, Any]) -> None:
        # create avoids putting token values in last-applied annotations.
        self.run(["create", "-f", "-"], resource)

    def get(self, kind: str, name: str) -> dict[str, Any] | None:
        raw = self.run(["-n", self.namespace, "get", kind, name, "--ignore-not-found", "-o", "json"])
        return json.loads(raw) if raw.strip() else None

    def values_equal(self, expected: str) -> bool:
        for suffix in ("delete", "retain"):
            obj = self.get("secret", "target-" + suffix)
            if not obj or obj.get("data", {}).get("password") != b64(expected.encode()):
                return False
        return True

    def missing_property_preserves_targets(self, expected: str) -> None:
        for resource in self.items:
            resource["spec"]["data"][0]["remoteRef"]["property"] = "fixture-field-that-does-not-exist"
            # Patch only the owned data mapping. Full-object replace races ESO's
            # status writes and can fail on resourceVersion conflicts.
            self.run(["-n", self.namespace, "patch", "externalsecret", resource["metadata"]["name"],
                      "--type=merge", "--patch-file=/dev/stdin"], {"spec": {"data": resource["spec"]["data"]}})
        def failed() -> bool:
            return all(any(c.get("type") == "Ready" and c.get("status") == "False"
                for c in (self.get("externalsecret", item["metadata"]["name"]) or {}).get("status", {}).get("conditions", []))
                for item in self.items)
        eventually(failed, "ESO did not report missing-property synchronization failures")
        require(self.values_equal(expected), "missing property removed or changed an existing Kubernetes Secret")
        for resource in self.items:
            resource["spec"]["data"][0]["remoteRef"]["property"] = "password"
            # Patch only the owned data mapping. Full-object replace races ESO's
            # status writes and can fail on resourceVersion conflicts.
            self.run(["-n", self.namespace, "patch", "externalsecret", resource["metadata"]["name"],
                      "--type=merge", "--patch-file=/dev/stdin"], {"spec": {"data": resource["spec"]["data"]}})

    def verify_deleted(self, retained: str) -> None:
        eventually(lambda: self.get("secret", "target-delete") is None,
                   "ESO Delete policy did not remove a genuinely deleted source")
        obj = self.get("secret", "target-retain")
        require(bool(obj) and obj.get("data", {}).get("password") == b64(retained.encode()),
                "ESO Retain policy failed to preserve the target")

    def close(self) -> None:
        self.run(["delete", "namespace", self.namespace, "--wait=false"])


def account_fixture(base: str, binary: Path, kdf_name: str,
                    kubeconfig: Path | None, gateway: str | None,
                    provider_factory: Callable[..., Any] | None = None) -> None:
    password = secrets.token_urlsafe(36)
    email = f"bweso-{uuid.uuid4().hex}@example.test"
    kdf = {"kdf": 0, "kdfIterations": 600_000} if kdf_name == "pbkdf2" else {
        "kdf": 1, "kdfIterations": 3, "kdfMemory": 64, "kdfParallelism": 4}
    master = (hashlib.pbkdf2_hmac("sha256", password.encode(), email.encode(), 600_000)
        if kdf_name == "pbkdf2" else hash_secret_raw(password.encode(), hashlib.sha256(email.encode()).digest(),
            3, 64 * 1024, 4, 32, Type.ID, version=19))
    wrapping = hmac.digest(master, b"enc\x01", "sha256") + hmac.digest(master, b"mac\x01", "sha256")
    authentication_hash = b64(hashlib.pbkdf2_hmac("sha256", master, password.encode(), 1))
    user_key, item_key = secrets.token_bytes(64), secrets.token_bytes(64)
    asymmetric = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public = asymmetric.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    private = asymmetric.private_bytes(serialization.Encoding.DER, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    verification = success(base + "/identity/accounts/register/send-verification-email", "POST",
                           {"email": email, "name": "Disposable interoperability test"})
    require(isinstance(verification, str), "disposable backend must return registration verification without SMTP")
    success(base + "/identity/accounts/register/finish", "POST", {
        "email": email, "emailVerificationToken": verification, **kdf,
        "masterPasswordHash": authentication_hash, "key": encrypt(wrapping, user_key),
        "keys": {"publicKey": b64(public), "encryptedPrivateKey": encrypt(user_key, private)}})
    login = success(base + "/identity/connect/token", "POST", {
        "grant_type": "password", "scope": "api offline_access", "client_id": "cli",
        "username": email, "password": authentication_hash,
        "deviceIdentifier": str(uuid.uuid4()), "deviceName": "bweso-integration", "deviceType": "8"}, form=True)
    token = login["access_token"]
    profile = success(base + "/api/accounts/profile", token=token)
    client_id = "user." + profile["id"]
    api_key = success(base + "/api/accounts/api-key", "POST", {"masterPasswordHash": authentication_hash}, token)["apiKey"]
    value = secrets.token_urlsafe(28)
    note = "independent fixture\nmultiline: café 🌱"
    item_name = "bweso-fixture-" + uuid.uuid4().hex
    cipher = {"type": 1, "encryptedFor": profile["id"], "name": encrypt(item_key, item_name),
        "key": encrypt(user_key, item_key), "notes": encrypt(item_key, note),
        "login": {"username": encrypt(item_key, "fixture-user"), "password": encrypt(item_key, value)},
        "fields": [{"name": encrypt(item_key, "API_KEY"), "value": encrypt(item_key, "fixture-field"), "type": 1}]}
    item = success(base + "/api/ciphers", "POST", cipher, token)["id"]
    webhook_token = secrets.token_urlsafe(48)
    bind_host = gateway or "127.0.0.1"
    with socket.socket() as sock:
        sock.bind((bind_host, 0))
        port = sock.getsockname()[1]
    webhook = f"http://{bind_host}:{port}"
    env = {k: v for k, v in os.environ.items() if not k.startswith("BWESO_")}
    env.update({"BWESO_LISTEN": f"{bind_host}:{port}", "BWESO_SINGLE_ORIGIN_URL": base,
        "BWESO_CLIENT_ID": client_id, "BWESO_CLIENT_SECRET": api_key,
        "BWESO_MASTER_PASSWORD": password, "BWESO_WEBHOOK_AUTH_TOKEN": webhook_token,
        "BWESO_ALLOWED_KEYS": f"id:{item},name:{item_name}", "BWESO_CACHE_TTL_SECONDS": "1",
        "RUST_LOG": "info,tower_http=info"})
    eso = None
    with tempfile.TemporaryDirectory(prefix="bweso-interop-") as temp:
        log_path = Path(temp) / "provider.log"
        with log_path.open("wb") as log:
            process = (provider_factory(env, log, Path(temp)) if provider_factory else
                       subprocess.Popen([str(binary)], env=env, stdout=log, stderr=log))
            webhook = getattr(process, "webhook", webhook)
            try:
                eventually(lambda: request(webhook + "/livez")[0] == 204, "provider did not become live", 30)
                def resolve(prop: str | None = "password", key: str | None = None,
                            auth: str | None = webhook_token) -> tuple[int, Any]:
                    ref = {"key": key or "id:" + item}
                    if prop is not None:
                        ref["property"] = prop
                    return request(webhook + "/v1/resolve", "POST", {"remoteRef": ref}, auth)
                require(resolve(auth=None)[0] == 401, "unauthenticated read was not rejected")
                require(resolve(key="id:not-allowed")[0] == 403, "selector policy was not enforced")
                status, document = resolve()
                require(status == 200, f"{kdf_name} provider could not unlock/read the actual backend: HTTP {status}")
                require(document["data"]["value"] == value, "password did not match independent fixture")
                status, document = resolve(None)
                require(status == 200 and document["data"]["notes"] == note and document["data"]["API_KEY"] == "fixture-field",
                        "whole-item Unicode/multiline/custom-field extraction failed")
                status, document = resolve(key="name:" + item_name)
                require(status == 200 and document["data"]["value"] == value, "name selector failed")
                status, error = resolve("missing-sensitive-property")
                require(status == 422, "missing property must not produce a deletion signal")
                require(item not in json.dumps(error) and "missing-sensitive-property" not in json.dumps(error),
                        "public error disclosed a selector")
                if kubeconfig:
                    eso = EsoFixture(kubeconfig, "bweso-interop-" + uuid.uuid4().hex[:12], getattr(process, "eso_url", webhook), webhook_token, item)
                    eventually(lambda: eso.values_equal(value), "ESO did not create both target Secrets")
                    eso.missing_property_preserves_targets(value)
                if provider_factory:
                    process.restart()
                    eventually(lambda: (lambda r: r[0] == 200 and r[1]["data"]["value"] == value)(resolve()),
                               "packaged provider did not recover after restart", 120)
                    process.rollback_probe(resolve, kdf_name, value)
                    if eso:
                        process.cross_version_probe(resolve, kdf_name, value, eso)
                    if eso:
                        eso.run(["-n", eso.namespace, "delete", "secret", "target-delete"])
                        eventually(lambda: eso.values_equal(value), "ESO did not recreate the removed target", 120)
                rotated = secrets.token_urlsafe(28)
                cipher["login"]["password"] = encrypt(item_key, rotated)
                success(base + "/api/ciphers/" + item, "PUT", cipher, token)
                eventually(lambda: (lambda result: result[0] == 200 and result[1]["data"]["value"] == rotated)(resolve()),
                           "provider did not observe source rotation")
                if eso:
                    eventually(lambda: eso.values_equal(rotated), "ESO did not propagate rotation")
                success(base + "/api/ciphers/" + item + "/delete", "PUT", token=token)
                eventually(lambda: resolve()[0] == 404, "trashed item remained readable")
                if eso:
                    eso.verify_deleted(rotated)
                metrics_status, _ = request(webhook + "/metrics")
                require(metrics_status == 200, "metrics endpoint failed")
                require(process.poll() is None, "provider exited during interoperability checks")
            finally:
                try:
                    if eso:
                        eso.close()
                finally:
                    process.terminate()
                    try:
                        process.wait(timeout=15)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait(timeout=5)
        logs = log_path.read_text(errors="replace")
        require(not any(secret in logs for secret in (password, api_key, webhook_token, value, item, item_name)),
                "provider logs disclosed a fixture credential or selector")
    print(f"PASS: {kdf_name}: real-backend unlock, field/map reads, auth, policy, rotation, missing property, trash" +
          (", ESO Delete/Retain lifecycle" if kubeconfig else ""), flush=True)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", default="http://127.0.0.1:8081")
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--kubeconfig", type=Path)
    parser.add_argument("--kind-gateway")
    args = parser.parse_args()
    target = urllib.parse.urlparse(args.url)
    require(target.scheme == "http" and target.hostname in ("localhost", "127.0.0.1", "::1")
            and not target.username and not target.password and not target.query and not target.fragment,
            "only an explicitly disposable loopback backend is allowed")
    require(args.binary.is_file(), "provider binary does not exist")
    require(bool(args.kubeconfig) == bool(args.kind_gateway), "ESO testing needs both kubeconfig and kind gateway")
    if args.kubeconfig:
        require(os.environ.get("GITHUB_ACTIONS") == "true", "kind lifecycle fixture is restricted to its disposable CI runner")
        current = subprocess.check_output(["kubectl", "--kubeconfig", str(args.kubeconfig), "config", "current-context"], text=True).strip()
        require(current == "kind-bweso-interop", "refusing to use a non-fixture Kubernetes context")
    base = args.url.rstrip("/")
    eventually(lambda: request(base + "/alive")[0] == 200, "disposable Vaultwarden did not start", 90)
    for kdf in ("pbkdf2", "argon2"):
        account_fixture(base, args.binary.resolve(), kdf, args.kubeconfig, args.kind_gateway)


if __name__ == "__main__":
    try:
        main()
    except (SmokeFailure, KeyError) as error:
        # KeyError reveals only a field name. Do not dump HTTP bodies or env.
        raise SystemExit(f"FAIL: {error}") from None
