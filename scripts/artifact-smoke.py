#!/usr/bin/env python3
"""Test the packaged Helm chart and exact container in a disposable CI cluster.

Only synthetic accounts are allowed here. No Cloud credentials, browser state,
real email, kubeconfig, or fixture logs belong in uploaded evidence artifacts.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timedelta, timezone
import http.client
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import importlib.util
import ipaddress
import json
import os
import platform
from pathlib import Path
import socket
import ssl
import subprocess
import threading
from typing import Any
import urllib.parse
import uuid

from qualification_checks import IdentityError, verify_native_image

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

spec = importlib.util.spec_from_file_location("synthetic_fixture", Path(__file__).with_name("vaultwarden-smoke.py"))
if spec is None or spec.loader is None:
    raise SystemExit("Unable to load the independent fixture")
fixture = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixture)
require, eventually = fixture.require, fixture.eventually


class PrivateCAProxy:
    """Verified TLS from the pod to a loopback-only, disposable Vaultwarden."""

    def __init__(self, gateway: str, directory: Path):
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Disposable fixture CA")])
        now = datetime.now(timezone.utc)
        cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=1)).not_valid_after(now + timedelta(hours=2))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .add_extension(x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address(gateway))]), critical=False)
            .sign(key, hashes.SHA256()))
        self.pem = cert.public_bytes(serialization.Encoding.PEM).decode()
        leaf_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        leaf = (x509.CertificateBuilder().subject_name(x509.Name([
                x509.NameAttribute(NameOID.COMMON_NAME, "Disposable fixture TLS")]))
            .issuer_name(name).public_key(leaf_key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=1)).not_valid_after(now + timedelta(hours=1))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address(gateway))]), critical=False)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
            .sign(key, hashes.SHA256()))
        cert_path, key_path = directory / "fixture-ca.pem", directory / "fixture-tls.key"
        cert_path.write_bytes(leaf.public_bytes(serialization.Encoding.PEM))
        key_path.write_bytes(leaf_key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                             serialization.NoEncryption()))
        key_path.chmod(0o600)

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args: Any) -> None:
                pass

            def forward(self) -> None:
                size = int(self.headers.get("Content-Length", "0"))
                if not 0 <= size <= 32 * 1024 * 1024:
                    self.send_error(413)
                    return
                body = self.rfile.read(size) if size else None
                headers = {k: v for k, v in self.headers.items()
                           if k.lower() not in ("host", "connection", "transfer-encoding", "content-length")}
                connection = http.client.HTTPConnection("127.0.0.1", 8081, timeout=90)
                try:
                    connection.request(self.command, self.path, body=body, headers=headers)
                    response = connection.getresponse()
                    payload = response.read(32 * 1024 * 1024 + 1)
                    if len(payload) > 32 * 1024 * 1024:
                        self.send_error(502)
                        return
                    self.send_response(response.status)
                    self.send_header("Content-Type", response.getheader("Content-Type", "application/json"))
                    self.send_header("Content-Length", str(len(payload)))
                    self.end_headers()
                    self.wfile.write(payload)
                finally:
                    connection.close()

            do_GET = forward
            do_POST = forward

        self.server = ThreadingHTTPServer((gateway, 0), Handler)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(cert_path, key_path)
        self.server.socket = context.wrap_socket(self.server.socket, server_side=True)
        self.url = f"https://{gateway}:{self.server.server_port}"
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)


class HelmProvider:
    def __init__(self, args: argparse.Namespace, env: dict[str, str], log: Any, directory: Path):
        self.args, self.log, self.directory = args, log, directory
        self.namespace = "bweso-artifact-" + uuid.uuid4().hex[:12]
        self.kube = ["kubectl", "--kubeconfig", str(args.kubeconfig), "--context", "kind-bweso-interop"]
        self.helm = ["helm", "--kubeconfig", str(args.kubeconfig), "--kube-context", "kind-bweso-interop", "-n", self.namespace]
        self.forward: subprocess.Popen | None = None
        self.created = False
        self.closed = False
        self.proxy = PrivateCAProxy(args.kind_gateway, directory)
        try:
            self.run(self.kube + ["create", "namespace", self.namespace])
            self.created = True
            credentials = {name: env[variable] for name, variable in {
                "client-id": "BWESO_CLIENT_ID", "client-secret": "BWESO_CLIENT_SECRET",
                "master-password": "BWESO_MASTER_PASSWORD", "webhook-token": "BWESO_WEBHOOK_AUTH_TOKEN"}.items()}
            self.run(self.kube + ["-n", self.namespace, "create", "-f", "-"], {
                "apiVersion": "v1", "kind": "Secret", "metadata": {"name": "provider-credentials", "namespace": self.namespace},
                "stringData": credentials})
            repository, tag = args.image.rsplit(":", 1)
            values = {"fullnameOverride": "provider", "image": {"repository": repository, "tag": tag, "pullPolicy": "Never"},
                "credentials": {"existingSecret": {"name": "provider-credentials"}},
                "config": {"singleOriginUrl": self.proxy.url, "cacheTtlSeconds": 1},
                "caBundle": {"pem": self.proxy.pem},
                "selectorPolicy": {"allowedKeys": env["BWESO_ALLOWED_KEYS"].split(",")}}
            # Values hold only reference names, public fixture CA and synthetic selectors.
            self.values_path = directory / "values.json"
            self.values_path.write_text(json.dumps(values))
            self.run(self.helm + ["install", "provider", str(args.chart), "-f", str(self.values_path),
                                  "--wait", "--timeout", "180s"], timeout=210)
            self.image_id = self.run(self.kube + ["-n", self.namespace, "get", "pod", "-l", "app.kubernetes.io/instance=provider",
                                               "-o", "jsonpath={.items[0].status.containerStatuses[0].imageID}"]).strip()
            self.verify_image_digest(self.image_id, args.image_id)
            with socket.socket() as sock:
                sock.bind(("127.0.0.1", 0))
                self.port = sock.getsockname()[1]
            self.webhook = f"http://127.0.0.1:{self.port}"
            self.eso_url = f"http://provider.{self.namespace}.svc.cluster.local:8080"
            self.start_forward()
        except BaseException:
            self.terminate()
            raise

    @staticmethod
    def run(command: list[str], payload: Any = None, timeout: int = 60) -> str:
        result = subprocess.run(command, input=None if payload is None else json.dumps(payload),
                                capture_output=True, text=True, timeout=timeout)
        if result.returncode != 0 and Path(command[0]).name == "docker":
            # This branch runs only a CRI image-identity read. No credential input.
            detail = " ".join(result.stderr.split())[:700]
            raise fixture.SmokeFailure("container image-identity lookup failed: " + detail)
        require(result.returncode == 0, "packaged fixture command failed: " + Path(command[0]).name)
        return result.stdout

    def verify_image_digest(self, observed: str, expected_config: str) -> None:
        arch = {"aarch64": "arm64", "x86_64": "amd64"}.get(platform.machine(), "unknown")
        try:
            verify_native_image(observed, expected_config, lambda digest: self.run([
                "docker", "exec", "bweso-interop-control-plane", "ctr", "-n", "k8s.io", "content", "get", digest]).encode(), arch)
        except IdentityError as error:
            raise fixture.SmokeFailure(str(error)) from error

    def start_forward(self) -> None:
        self.forward = subprocess.Popen(self.kube + ["-n", self.namespace, "port-forward", "--address", "127.0.0.1",
                        "service/provider", f"{self.port}:8080"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        eventually(lambda: fixture.request(self.webhook + "/livez")[0] == 204, "packaged provider did not become live", 60)

    def stop_forward(self) -> None:
        if self.forward:
            self.forward.terminate()
            try:
                self.forward.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self.forward.kill()
                self.forward.wait(timeout=5)
            self.forward = None

    def restart(self) -> None:
        self.stop_forward()
        self.run(self.kube + ["-n", self.namespace, "rollout", "restart", "deployment/provider"])
        self.run(self.kube + ["-n", self.namespace, "rollout", "status", "deployment/provider", "--timeout=180s"], timeout=190)
        self.start_forward()

    def rollback_probe(self, resolve: Any, kdf_name: str, expected: str) -> None:
        self.stop_forward()
        self.run(self.helm + ["upgrade", "provider", str(self.args.chart), "-f", str(self.values_path),
                              "--set", "config.argon2MemoryLimitMiB=16,config.cacheRefreshRetryIntervalSeconds=0", "--wait", "--timeout", "180s"], timeout=210)
        self.start_forward()
        status, document = resolve()
        if kdf_name == "argon2":
            require(status == 500, "over-budget Argon2 did not fail without deleting the source")
        else:
            require(status == 200 and document["data"]["value"] == expected, "PBKDF2 configuration upgrade failed")
        self.stop_forward()
        self.run(self.helm + ["rollback", "provider", "1", "--wait", "--timeout", "180s"], timeout=210)
        self.start_forward()
        eventually(lambda: (lambda r: r[0] == 200 and r[1]["data"]["value"] == expected)(resolve()),
                   "Helm rollback did not restore working configuration", 120)

    def cross_version_probe(self, resolve: Any, kdf_name: str, expected: str, eso: Any) -> None:
        if not self.args.baseline_chart:
            return
        candidate_values = json.loads(self.values_path.read_text())
        baseline_values = dict(candidate_values)
        repository, tag = self.args.baseline_image.rsplit(":", 1)
        baseline_values["image"] = {"repository": repository, "tag": tag, "pullPolicy": "Never"}
        baseline_path = self.directory / "baseline-values.json"
        baseline_path.write_text(json.dumps(baseline_values))
        # We already restored the candidate by configuration rollback; capture that revision.
        history = json.loads(self.run(self.helm + ["history", "provider", "--output", "json"]))
        candidate_revision = str(history[-1]["revision"])
        self.stop_forward()
        self.run(self.helm + ["upgrade", "provider", str(self.args.baseline_chart), "-f", str(baseline_path),
                              "--wait", "--timeout", "180s"], timeout=210)
        self.start_forward()
        status, document = resolve()
        if kdf_name == "pbkdf2":
            require(status == 200 and document["data"]["value"] == expected,
                    f"released PBKDF2 chart/image rollback failed (HTTP {status})")
        else:
            require(status == 500, "known-incompatible released Argon2 path did not fail with the expected decryption error")
        require(eso.values_equal(expected), "cross-version rollback lost an existing ESO target")
        self.stop_forward()
        self.run(self.helm + ["rollback", "provider", candidate_revision, "--wait", "--timeout", "180s"], timeout=210)
        self.start_forward()
        eventually(lambda: (lambda r: r[0] == 200 and r[1]["data"]["value"] == expected)(resolve()),
                   "return to candidate after released-version rollback failed", 120)
        eventually(lambda: eso.values_equal(expected), "cross-version recovery lost target values", 120)

    def poll(self) -> int | None:
        return self.forward.poll() if self.forward else 0

    def terminate(self) -> None:
        if self.closed:
            return
        self.closed = True
        self.stop_forward()
        try:
            if self.created:
                logs = subprocess.run(self.kube + ["-n", self.namespace, "logs", "deployment/provider"],
                                      capture_output=True, timeout=30)
                self.log.write(logs.stdout)
                self.run(self.kube + ["delete", "namespace", self.namespace, "--wait=false"])
        finally:
            self.proxy.close()

    def wait(self, timeout: int = 15) -> int:
        return 0

    def kill(self) -> None:
        self.terminate()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--chart", type=Path, required=True)
    parser.add_argument("--image", required=True)
    parser.add_argument("--image-id", required=True)
    parser.add_argument("--kubeconfig", type=Path, required=True)
    parser.add_argument("--kind-gateway", required=True)
    parser.add_argument("--baseline-chart", type=Path)
    parser.add_argument("--baseline-image", default="bweso-baseline:0.4.0")
    args = parser.parse_args()
    require(os.environ.get("GITHUB_ACTIONS") == "true", "packaged fixture runs only in disposable GitHub CI")
    require(args.chart.is_file() and args.chart.suffix == ".tgz", "an exact packaged chart is required")
    if args.baseline_chart:
        require(args.baseline_chart.is_file(), "released baseline archive is missing")
    current = HelmProvider.run(["kubectl", "--kubeconfig", str(args.kubeconfig), "config", "current-context"]).strip()
    require(current == "kind-bweso-interop", "refusing a non-fixture cluster")
    eventually(lambda: fixture.request("http://127.0.0.1:8081/alive")[0] == 200, "disposable backend not ready", 90)
    for kdf in ("pbkdf2", "argon2"):
        fixture.account_fixture("http://127.0.0.1:8081", Path("/unused"), kdf, args.kubeconfig, args.kind_gateway,
                                lambda env, log, directory: HelmProvider(args, env, log, directory))
        print(f"PASS: {kdf}: packaged chart/image identity, private CA TLS, restart, target recreation, config upgrade/rollback, released baseline recovery", flush=True)


if __name__ == "__main__":
    try:
        main()
    except (fixture.SmokeFailure, subprocess.TimeoutExpired, KeyError) as error:
        raise SystemExit(f"FAIL: {type(error).__name__}: {error if isinstance(error, fixture.SmokeFailure) else 'fixture operation failed'}") from None
