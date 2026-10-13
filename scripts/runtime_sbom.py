#!/usr/bin/env python3
"""SPDX 2.3 inventory of the locked, target-filtered normal Cargo dependency graph.

No source paths, authors, browser state or environment values enter the report.
The graph is declared dependency evidence, not binary-level composition analysis.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import subprocess
import tomllib
from urllib.parse import quote

from release_bundle import ARCHES, REVISION, check_elf, read_regular, require

NAME = re.compile(r"[A-Za-z0-9_-]+")
VERSION = re.compile(r"[0-9][0-9A-Za-z.+-]*")
REGISTRY = "registry+https://github.com/rust-lang/crates.io-index"


def runtime_graph(metadata: dict, tree: str) -> tuple[str, dict[str, dict], dict[str, set[str]]]:
    # Cargo metadata can list optional dependencies that cargo tree correctly
    # excludes for the selected features. Use the actual normal-edge tree for
    # membership and relationships; metadata supplies license/source details.
    coordinates: dict[tuple[str, str], dict] = {}
    for package in metadata["packages"]:
        coordinate = (package["name"], package["version"])
        require(coordinate not in coordinates, "ambiguous package coordinates")
        coordinates[coordinate] = package
    nodes = {n["id"]: n for n in metadata["resolve"]["nodes"]}
    visited: dict[str, dict] = {}
    edges: dict[str, set[str]] = {}
    stack: list[str] = []
    root = None
    lines = tree.splitlines()
    require(0 < len(lines) <= 100000, "invalid dependency tree size")
    for line in lines:
        match = re.fullmatch(r"([0-9]+)([A-Za-z0-9_-]+) v([0-9][0-9A-Za-z.+-]*)(?: .*)?", line)
        require(match is not None, "unrecognized Cargo depth-tree line")
        depth, name, version = int(match[1]), match[2], match[3]
        require(depth <= len(stack) and (name, version) in coordinates, "incomplete dependency tree")
        package = coordinates[(name, version)]
        identity = package["id"]
        require(identity in nodes, "missing dependency metadata")
        if depth == 0:
            require(root is None and name == "vaultwarden-eso-provider" and package.get("source") is None,
                    "expected one provider package")
            root = identity
        else:
            parent = stack[depth - 1]
            require(any(d["pkg"] == identity and any(k["kind"] is None for k in d["dep_kinds"])
                        for d in nodes[parent]["deps"]), "tree edge is not a declared normal dependency")
            edges[parent].add(identity)
        visited[identity] = package
        edges.setdefault(identity, set())
        stack = stack[:depth] + [identity]
    require(root is not None, "provider tree is empty")
    return root, visited, edges


def generate(metadata: dict, lock: dict, binary: bytes, arch: str, revision: str, tree: str) -> dict:
    require(REVISION.fullmatch(revision) is not None, "invalid source revision")
    check_elf(binary, arch)
    root, packages, edges = runtime_graph(metadata, tree)
    checksums = {(p["name"], p["version"], p.get("source")): p.get("checksum") for p in lock["package"]}
    ids: dict[str, str] = {}
    result = []
    for identity, package in sorted(packages.items(), key=lambda item: (item[1]["name"], item[1]["version"])):
        name, version, source = package["name"], package["version"], package.get("source")
        require(NAME.fullmatch(name) is not None and VERSION.fullmatch(version) is not None, "invalid package name or version")
        require(source in (None, REGISTRY), "unsupported source must receive an explicit SBOM review")
        # Use public package coordinates rather than absolute Cargo path identities.
        spdx_id = "SPDXRef-Crate-" + hashlib.sha256((name + '@' + version + ':' + (source or 'workspace')).encode()).hexdigest()[:20]
        require(spdx_id not in ids.values(), "colliding package coordinates")
        ids[identity] = spdx_id
        row = {"SPDXID":spdx_id, "name":name, "versionInfo":version, "filesAnalyzed":False,
               "licenseConcluded":"NOASSERTION", "licenseDeclared":package.get("license") or "NOASSERTION",
               "copyrightText":"NOASSERTION", "downloadLocation":"NOASSERTION"}
        if source:
            checksum = checksums.get((name, version, source))
            require(isinstance(checksum, str) and re.fullmatch(r"[0-9a-f]{64}", checksum) is not None, "registry dependency has no locked checksum")
            row.update(downloadLocation=f"https://static.crates.io/crates/{name}/{name}-{quote(version)}.crate",
                       checksums=[{"algorithm":"SHA256", "checksumValue":checksum}],
                       externalRefs=[{"referenceCategory":"PACKAGE-MANAGER", "referenceType":"purl",
                                      "referenceLocator":f"pkg:cargo/{name}@{quote(version)}"}])
        else:
            require(name in ("vaultwarden-eso-provider", "bweso-core", "bweso-bitwarden"), "unexpected local package")
            row["sourceInfo"] = "Workspace source in Ponchia/vaultwarden-eso-provider at commit " + revision
        result.append(row)
    executable_sha = hashlib.sha256(binary).hexdigest()
    executable = {"SPDXID":"SPDXRef-ProviderBinary", "name":"vaultwarden-eso-provider", "versionInfo":packages[root]["version"],
                  "filesAnalyzed":False, "licenseConcluded":"NOASSERTION", "licenseDeclared":"Apache-2.0",
                  "copyrightText":"NOASSERTION", "downloadLocation":"NOASSERTION",
                  "checksums":[{"algorithm":"SHA256", "checksumValue":executable_sha}],
                  "sourceInfo":f"Linux {arch} executable extracted from the exact image built at {revision}. Declared normal Cargo dependencies; not a binary-level linker inventory."}
    relationships = [{"spdxElementId":"SPDXRef-DOCUMENT", "relationshipType":"DESCRIBES", "relatedSpdxElement":"SPDXRef-ProviderBinary"},
                     {"spdxElementId":"SPDXRef-ProviderBinary", "relationshipType":"GENERATED_FROM", "relatedSpdxElement":ids[root]}]
    relationships.extend({"spdxElementId":ids[parent], "relationshipType":"DEPENDS_ON", "relatedSpdxElement":ids[child]}
                         for parent in sorted(edges) for child in sorted(edges[parent]))
    return {"spdxVersion":"SPDX-2.3", "dataLicense":"CC0-1.0", "SPDXID":"SPDXRef-DOCUMENT",
            "name":f"vaultwarden-eso-provider-{packages[root]['version']}-linux-{arch}",
            "documentNamespace":f"https://github.com/Ponchia/vaultwarden-eso-provider/sbom/{revision}/{arch}/{executable_sha}",
            "creationInfo":{"creators":["Tool: bweso-runtime-sbom-1"], "created":datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')},
            "comment":"Target-filtered normal Cargo dependency graph from the lockfile, plus exact executable checksum. Build-only/dev-only dependencies are excluded. No independent audit or binary composition guarantee.",
            "packages":[executable, *result], "relationships":relationships}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, required=True)
    parser.add_argument('--arch', choices=ARCHES, required=True)
    parser.add_argument('--revision', required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    triple = ('x86_64' if args.arch == 'amd64' else 'aarch64') + '-unknown-linux-musl'
    raw = subprocess.run(['cargo','metadata','--locked','--format-version','1','--filter-platform',triple],
                         capture_output=True, text=True, check=True, timeout=180)
    tree = subprocess.run(['cargo','tree','--locked','-p','vaultwarden-eso-provider','--target',triple,
                           '--edges','normal','--prefix','depth','--format','{p}','--color','never'],
                          capture_output=True, text=True, check=True, timeout=180)
    sbom = generate(json.loads(raw.stdout), tomllib.loads(Path('Cargo.lock').read_text()),
                    read_regular(args.binary), args.arch, args.revision, tree.stdout)
    with args.output.open('x', encoding='utf-8') as output:
        output.write(json.dumps(sbom, indent=2) + '\n')
    print(f"SPDX inventory: {len(sbom['packages']) - 1} Cargo packages and the exact {args.arch} executable.")


if __name__ == '__main__':
    try:
        main()
    except (ValueError, KeyError, OSError, TypeError, subprocess.SubprocessError) as error:
        raise SystemExit('SPDX export failed: ' + type(error).__name__) from None
