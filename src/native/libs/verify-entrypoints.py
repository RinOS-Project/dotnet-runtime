#!/usr/bin/env python3
"""Check a native shared library's exported entrypoints portably."""

from __future__ import annotations

import re
import subprocess
import sys
from collections import Counter
from pathlib import Path


_SYMBOL = re.compile(r"^[0-9A-Fa-f]+\s+T\s+_?([A-Za-z0-9_]+)$")
_ENTRYPOINT = re.compile(r"^\s+DllImportEntry\(([A-Za-z0-9_]+)\)")
_SKIP = {"init", "fini", "etext", "_chk_fail", "_stack_chk_fail", "PROCEDURE_LINKAGE_TABLE_"}


def _exported_symbols(library: Path, nm_command: str) -> list[str]:
    result = subprocess.run(
        [nm_command, str(library)],
        check=True,
        capture_output=True,
        text=True,
    )
    symbols: list[str] = []
    for raw_line in result.stdout.splitlines():
        match = _SYMBOL.match(raw_line.strip())
        if match and match.group(1) not in _SKIP:
            symbols.append(match.group(1))
    return symbols


def _declared_entrypoints(source: Path) -> list[str]:
    entries: list[str] = []
    for raw_line in source.read_text(encoding="utf-8").splitlines():
        match = _ENTRYPOINT.match(raw_line)
        if match:
            entries.append(match.group(1))
    return entries


def main(argv: list[str]) -> int:
    if len(argv) != 4:
        print(
            "Usage: verify-entrypoints.py <path to shared library> "
            "<path to entries.c file> <path to NM command>",
            file=sys.stderr,
        )
        return 1

    library = Path(argv[1])
    entries = Path(argv[2])
    try:
        exported = _exported_symbols(library, argv[3])
        declared = _declared_entrypoints(entries)
    except (OSError, subprocess.CalledProcessError) as error:
        print(f"ERROR: unable to inspect {library}: {error}", file=sys.stderr)
        return 1

    differences = sorted(
        name
        for name, count in (Counter(declared) + Counter(exported)).items()
        if count == 1
    )
    if differences:
        print(
            f"ERROR: {entries} file did not match entries exported from {library}",
            file=sys.stderr,
        )
        print("DIFFERENCES FOUND:", file=sys.stderr)
        print(",".join(differences), file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
