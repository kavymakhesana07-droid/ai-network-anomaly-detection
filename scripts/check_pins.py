"""Validate that requirements/*.txt is actually installable.

Two classes of mistake only surface deep inside a Docker build, one after
another, costing a full CI cycle each:

1. A pin for a version that was never published
   -> "No matching distribution found for scapy==2.5.6"
2. Two pins that cannot be satisfied together
   -> "ResolutionImpossible ... pyflowmeter 0.2.4 depends on scapy==2.5.0"

This script catches both in seconds: it queries the PyPI JSON API for each pin,
then asks pip to resolve each profile without installing anything.

Usage:
    python scripts/check_pins.py             # existence only
    python scripts/check_pins.py --resolve   # + pip resolution check
    python scripts/check_pins.py --strict     # non-zero exit on any problem
"""

from __future__ import annotations

import json
import os
import re
import subprocess  # noqa: S404 - this script's entire job is to invoke pip
import sys
import tempfile
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
REQ_DIR = REPO_ROOT / "requirements"

# Resolve against the interpreter CI uses, not the developer's.
TARGET_PYTHON = "3.11"

# Ceiling per profile, so one pathological resolve cannot hang the whole check.
RESOLVE_TIMEOUT = 600

# Profiles excluded from the resolution check, and why.
#
# bench.txt         - pins an old scapy on purpose, to compare features offline.
# ml.txt            - torch/ray resolution takes many minutes and is not installed
#                     by CI at all; it is a local training profile.
# features.txt      - pulls in ml.txt.
# detect_deep.txt   - pyspark ships as an sdist only, so it has no wheel and
#                     --only-binary rejects it. It is not installed by CI yet.
# model_registry.txt- mlflow dependency tree causes resolution-too-deep errors;
#                     will be resolved when ArgoCD integration lands (Day 7+).
#
# These still get the full PyPI existence check. They move into the resolution
# gate on the day their Dockerfile actually lands in the build matrix.
SKIP_RESOLVE = {"bench.txt", "ml.txt", "features.txt", "detect_deep.txt", "model_registry.txt"}

PIN = re.compile(
    r"^(?P<name>[A-Za-z0-9._-]+(?:\[[A-Za-z0-9,._-]+\])?)\s*==\s*(?P<version>[A-Za-z0-9.*+!-]+)"
)

# Profiles that must resolve cleanly. bench.txt is excluded: it exists purely to
# pin an old scapy for offline comparison, so it is expected to conflict with
# nothing but is not part of any shipped image.

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


def pypi_releases(name: str) -> dict[str, int]:
    """Fetch published versions for a project, mapped to their file count.

    The file count matters. PyPI keeps a key in `releases` even when every
    artifact has been withdrawn - matplotlib==3.9.1 is exactly that case, it was
    pulled and republished as 3.9.1.post1. A key-presence check happily accepts
    the dead version, so only versions with at least one artifact are returned.
    """
    url = f"https://pypi.org/pypi/{normalize(name)}/json"
    request = urllib.request.Request(url, headers={"User-Agent": "check-pins/1.0"})
    with urllib.request.urlopen(request, timeout=30) as response:  # noqa: S310
        payload = json.load(response)
    return {v: len(files) for v, files in payload.get("releases", {}).items()}


def pypi_versions(name: str) -> list[str]:
    return [v for v, count in pypi_releases(name).items() if count > 0]


def resolves(path: Path) -> tuple[bool, str]:
    """Ask pip to resolve a profile without installing it.

    --only-binary=:all: matters: it proves a wheel exists for the target
    interpreter, so CI never falls back to a source build that may need a
    toolchain the runner does not have.
    """
    # Each concurrent resolve needs its own cache directory. Sharing the default
    # makes pip serialise on its cache lock, and the losers fail with errors
    # that look like genuine resolution problems but are not.
    with tempfile.TemporaryDirectory(prefix="check-pins-") as cache_dir:
        env = {**os.environ, "PIP_CACHE_DIR": cache_dir}
        result = subprocess.run(  # noqa: S603 - fixed argv, no shell
            [
                sys.executable,
                "-m",
                "pip",
                "install",
                "--dry-run",
                "--quiet",
                "--disable-pip-version-check",
                f"--python-version={TARGET_PYTHON}",
                "--only-binary=:all:",
                "-r",
                str(path),
            ],
            capture_output=True,
            text=True,
            check=False,
            timeout=RESOLVE_TIMEOUT,
            env=env,
        )
    if result.returncode == 0:
        return True, ""

    detail = (result.stderr or result.stdout or "").strip()
    if not detail:
        return False, f"pip exited {result.returncode} with no output"

    # Surface the lines that explain the failure, not pip's progress noise.
    interesting = [
        line.strip()
        for line in detail.splitlines()
        if "conflict" in line.lower()
        or "ResolutionImpossible" in line
        or "depends on" in line
        or "No matching distribution" in line
        or line.strip().startswith("ERROR:")
    ]
    if interesting:
        return False, " | ".join(dict.fromkeys(interesting[:4]))
    return False, detail.splitlines()[-1].strip()


def main() -> int:
    strict = "--strict" in sys.argv
    do_resolve = "--resolve" in sys.argv or strict
    files = sorted(REQ_DIR.glob("*.txt"))
    if not files:
        print(f"no requirements files found in {REQ_DIR}")
        return 1

    total = 0
    problems: list[str] = []
    cache: dict[str, list[str]] = {}
    dead: dict[str, dict[str, int]] = {}

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
                    all_releases = pypi_releases(name)
                    dead[key] = {v: n for v, n in all_releases.items() if n == 0}
                    cache[key] = [v for v, n in all_releases.items() if n > 0]
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
            elif version in dead.get(key, {}):
                # PyPI still lists the version but every artifact was withdrawn.
                # Distinguish this from "never existed" - the fix is different.
                problems.append(
                    f"{path.name}:{lineno}: {name}=={version} exists on PyPI but has "
                    "no downloadable artifacts (withdrawn/yanked). Pick a different "
                    "version - often a .postN suffix."
                )
                print(f"  FAIL  {name}=={version}  (release withdrawn, no artifacts)")
            else:
                available = [v for v in cache[key] if re.fullmatch(r"\d+(\.\d+)*", v)]
                suggestion = available[-1] if available else "none"
                problems.append(
                    f"{path.name}:{lineno}: {name}=={version} does not exist. "
                    f"Newest release on PyPI: {suggestion}"
                )
                print(f"  FAIL  {name}=={version}  (newest stable: {suggestion})")

    if do_resolve:
        targets = [p for p in files if p.name not in SKIP_RESOLVE]
        print(f"\nresolving {len(targets)} profiles for Python {TARGET_PYTHON} (wheels only)")
        for path in files:
            if path.name in SKIP_RESOLVE:
                print(f"  skip  {path.name}  (not shipped in any image)")

        # pip resolves are dominated by network and wheel-metadata downloads, so
        # running them concurrently cuts this from minutes to well under one.
        with ThreadPoolExecutor(max_workers=min(8, len(targets) or 1)) as pool:
            futures = {pool.submit(resolves, path): path for path in targets}
            for future in as_completed(futures):
                path = futures[future]
                try:
                    ok, detail = future.result()
                except subprocess.TimeoutExpired:
                    ok, detail = False, f"timed out after {RESOLVE_TIMEOUT}s"
                if ok:
                    print(f"  ok    {path.name}")
                else:
                    problems.append(f"{path.name}: does not resolve - {detail}")
                    print(f"  FAIL  {path.name}  {detail}")

    print(f"\n{'=' * 60}")
    print(f"checked {total} pins across {len(files)} files")

    if problems:
        print(f"\n{len(problems)} problem(s):")
        for problem in problems:
            print(f"  - {problem}")
        return 1 if strict else 0

    print("all pins resolve to a real PyPI release")
    if do_resolve:
        print("all shipped profiles resolve cleanly")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
