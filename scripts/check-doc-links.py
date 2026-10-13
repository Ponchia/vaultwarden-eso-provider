#!/usr/bin/env python3
"""Check repository-relative Markdown targets without browsing external links."""
from pathlib import Path
import re
import subprocess
from urllib.parse import unquote, urlsplit

root = Path(__file__).resolve().parents[1]
tracked = subprocess.check_output(["git", "ls-files", "*.md"], cwd=root, text=True).splitlines()
failures = []
for relative in tracked:
    source = root / relative
    if not source.exists():
        continue  # A reviewed deletion in a working tree.
    text = re.sub(r"```.*?```", "", source.read_text(), flags=re.S)
    for target in re.findall(r"!?\[[^\]\n]*\]\(([^)\s]+)(?: [^)]*)?\)", text):
        parsed = urlsplit(target.strip("<>"))
        if parsed.scheme or parsed.netloc or not parsed.path:
            continue
        destination = (source.parent / unquote(parsed.path)).resolve()
        if not destination.is_relative_to(root) or not destination.exists():
            failures.append(f"{relative}: missing local link {target}")
if failures:
    raise SystemExit("\n".join(failures))
print(f"Local documentation targets checked in {len(tracked)} tracked Markdown files.")
