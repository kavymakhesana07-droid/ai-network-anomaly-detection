"""Validate that every pinned requirement in requirements/*.txt exists on PyPI.

A version that was never published (a typo, or a guess) only fails at image
build time with "No matching distribution found for ...", which costs a full CI
cycle to discover. This script catches it in seconds.

Usage:
    python scripts/check_pins.py            # report all problems
    python scripts/check_pins.py --strict   # non-zero exit on any problem
"""

from __future__ import annotations

import json
import re
import sys
import urllib.error
import urllib.request
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
REQ_DIR = REPO_ROOT / "requirements"

PIN = re.compile(
    r"^(?P<name>[A-Za-z0-9._-]+(?:\[[A-Za-z0-9,._-]+\])?)\s*==\s*(?P<version>[A-Za-z0-9.*+!-]+)"
)

# Pins that intentionally do not exist on PyPI and must be skipped, with a
# reason. Empty in practice - kept so an intentional exception is documented
# rather than silently added.
EXCEPTIONS: dict[str, str] = {}


def parse_pins(path: Path) -> list[tuple[str, str, int]]:
    """Return (name, version, lineno) for every == pin in a requirements file."""
    pins: list[tuple[str, str, int]] = []
    for lineno, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        line = raw.split("#", 1)[0].strip()
        if not line or line.startswith("-"):
            continue
        match = PIN.match(line)
        if match:
            pins.append((match["name"], match["version"], lineno))
    return pins


def normalize(name: str) -> str:
    """Normalize a requirement name to its PyPI form.

    Strips any extras first: "coverage[toml]" and "coverage" are the same
    project on PyPI, and the extras only affect what pip installs alongside it.
    """
    if "[" in name:
        name = name.split("[", 1)[0]
    return re.sub(r"[-_.]+", "-", name).lower()


def pypi_versions(name: str) -> list[str]:
    """Fetch the list of published versions for a project from PyPI."""
    url = f"https://pypi.org/pypi/{normalize(name)}/json"
    request = urllib.request.Request(url, headers={"User-Agent": "check-pins/1.0"})
    with urllib.request.urlopen(request, timeout=30) as response:  # noqa: S310
        payload = json.load(response)
    return list(payload.get("releases", {}))


def main() -> int:
    strict = "--strict" in sys.argv
    files = sorted(REQ_DIR.glob("*.txt"))
    if not files:
        print(f"no requirements files found in {REQ_DIR}")
        return 1

    total = 0
    problems: list[str] = []
    cache: dict[str, list[str]] = {}

    for path in files:
        pins = parse_pins(path)
        if not pins:
            continue
        print(f"\n{path.relative_to(REPO_ROOT)}  ({len(pins)} pins)")

        for name, version, lineno in pins:
            total += 1
            if normalize(name) in EXCEPTIONS:
                print(f"  SKIP  {name}=={version}  ({EXCEPTIONS[normalize(name)]})")
                continue

            key = normalize(name)
            if key not in cache:
                try:
                    cache[key] = pypi_versions(name)
                except urllib.error.HTTPError as exc:
                    cache[key] = []
                    problems.append(
                        f"{path.name}:{lineno}: {name}=={version} - "
                        f"package '{name}' not found on PyPI (HTTP {exc.code})"
                    )
                    print(f"  FAIL  {name}=={version}  (package not found)")
                    continue
                except (urllib.error.URLError, TimeoutError) as exc:
                    problems.append(f"{path.name}:{lineno}: {name} - network error: {exc}")
                    print(f"  SKIP  {name}  (network error, not verified)")
                    total -= 1
                    continue

            if version in cache[key]:
                print(f"  ok    {name}=={version}")
            else:
                available = [v for v in cache[key] if re.fullmatch(r"\d+(\.\d+)*", v)]
                suggestion = available[-1] if available else "none"
                problems.append(
                    f"{path.name}:{lineno}: {name}=={version} does not exist. "
                    f"Newest release on PyPI: {suggestion}"
                )
                print(f"  FAIL  {name}=={version}  (newest stable: {suggestion})")

    print(f"\n{'=' * 60}")
    print(f"checked {total} pins across {len(files)} files")

    if problems:
        print(f"\n{len(problems)} problem(s):")
        for problem in problems:
            print(f"  - {problem}")
        return 1 if strict else 0

    print("all pins resolve to a real PyPI release")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
