"""Regression guards for the repository layout, config, and manifests.

These act as a canary: if the repo layout or config breaks, CI fails loudly
instead of silently passing. Most of the cases here were written in response to
a real failure, so each docstring records what broke and why.
"""

import re
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]


class TestProjectStructure:
    @pytest.mark.parametrize(
        "path",
        [
            "README.md",
            "Makefile",
            "docker-compose.yml",
            "pyproject.toml",
            "ingestion/pcap/main.py",
            "ingestion/pcap/Dockerfile",
            "feature_extraction/main.py",
            "feature_extraction/models.py",
            ".github/workflows/ci-cd.yaml",
            "k8s/base/kustomization.yaml",
            "k8s/overlays/dev/kustomization.yaml",
        ],
    )
    def test_required_file_exists(self, path: str):
        assert (REPO_ROOT / path).exists(), f"missing required file: {path}"

    @pytest.mark.parametrize(
        "path",
        [
            "ingestion/pcap",
            "ingestion/live_capture",
            "ingestion/netflow",
            "ingestion/zeek",
            "ingestion/cloud_flows",
            "feature_extraction",
            "detection/fast_path",
            "detection/deep_path",
            "detection/model_registry",
            "alerting",
            "output/siem",
            "output/dashboard",
            "output/integrations",
            "common",
        ],
    )
    def test_layer_directory_exists(self, path: str):
        """Every layer from ADR-0001 must be a real, importable package.

        The dirs hold only ``__init__.py`` until their implementation lands, but
        git does not track empty directories - so the marker file is what makes
        the declared architecture survive a clone.
        """
        directory = REPO_ROOT / path
        assert directory.is_dir(), f"missing layer dir: {path}"
        assert (directory / "__init__.py").is_file(), (
            f"{path} needs an __init__.py or git will not track it"
        )

    def test_no_untracked_empty_source_dirs(self):
        """Any package dir holding .py files must also be an importable package."""
        for init in REPO_ROOT.rglob("__init__.py"):
            if "__pycache__" in init.parts or ".venv" in init.parts:
                continue
            assert init.parent.is_dir()


class TestDockerImages:
    """The base image must exist before any service image can build.

    A service Dockerfile that does `FROM anomaly-detection/base:latest` with no
    ARG override fails on a clean CI runner with
    "pull access denied, repository does not exist", because that tag only
    exists in a developer's local image store.
    """

    def test_base_image_is_declared_in_compose(self):
        import yaml

        with (REPO_ROOT / "docker-compose.yml").open(encoding="utf-8") as fh:
            services = yaml.safe_load(fh)["services"]
        assert "base" in services, "compose must declare the shared base image"
        build = services["base"]["build"]
        assert build["dockerfile"] == "Dockerfile.base"

    def test_base_image_never_starts(self):
        """The base is built, not run - it must stay behind a profile."""
        import yaml

        with (REPO_ROOT / "docker-compose.yml").open(encoding="utf-8") as fh:
            base = yaml.safe_load(fh)["services"]["base"]
        assert "build-only" in base.get("profiles", []), (
            "base must be profile-gated so `docker compose up` does not try to run it"
        )

    def test_service_dockerfiles_use_overridable_base(self):
        service_dockerfiles = sorted(
            p
            for p in REPO_ROOT.rglob("Dockerfile")
            if "__pycache__" not in p.parts and p.name != "Dockerfile.base"
        )
        assert service_dockerfiles, "expected at least one service Dockerfile"

        for path in service_dockerfiles:
            text = path.read_text(encoding="utf-8")
            rel = path.relative_to(REPO_ROOT)
            assert "ARG BASE_IMAGE=" in text, (
                f"{rel} must declare ARG BASE_IMAGE so CI can inject the published tag"
            )
            assert "FROM ${BASE_IMAGE}" in text, f"{rel} must build FROM ${{BASE_IMAGE}}"
            assert "FROM anomaly-detection/base" not in text, (
                f"{rel} hardcodes the base image instead of using the ARG"
            )

    def test_makefile_builds_base_before_services(self):
        makefile = (REPO_ROOT / "Makefile").read_text(encoding="utf-8")
        assert "build: base" in makefile, "`make build` must depend on `make base`"


class TestRequirementPins:
    """Every `==` pin must name a version that PyPI actually published.

    A phantom pin is invisible locally and only surfaces as
    "No matching distribution found for scapy==2.5.6" deep inside a Docker
    build, which costs a full CI cycle per mistake.
    """

    # Extras are part of the name for pip ("coverage[toml]") but not for PyPI,
    # so they must be matched here and stripped before lookup.
    PIN = re.compile(
        r"^(?P<name>[A-Za-z0-9._-]+(?:\[[A-Za-z0-9,._-]+\])?)\s*==\s*(?P<version>[A-Za-z0-9.*+!-]+)"
    )

    def test_all_pins_use_exact_equality(self):
        """`>=` in a requirements file makes builds non-reproducible."""
        offenders: list[str] = []
        for path in sorted((REPO_ROOT / "requirements").glob("*.txt")):
            for lineno, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
                line = raw.split("#", 1)[0].strip()
                if not line or line.startswith("-"):
                    continue
                if "==" not in line:
                    offenders.append(f"{path.name}:{lineno}: {line}")
        assert not offenders, "pin these exactly, not with >=: " + ", ".join(offenders)

    def test_pin_format_is_parsable(self):
        """scripts/check_pins.py must be able to parse every non-comment line."""
        unparsable: list[str] = []
        for path in sorted((REPO_ROOT / "requirements").glob("*.txt")):
            for lineno, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
                line = raw.split("#", 1)[0].strip()
                if not line or line.startswith("-"):
                    continue
                if not self.PIN.match(line):
                    unparsable.append(f"{path.name}:{lineno}: {line}")
        assert not unparsable, "unparsable requirement lines: " + ", ".join(unparsable)

    def test_check_pins_script_exists(self):
        assert (REPO_ROOT / "scripts" / "check_pins.py").is_file()

    def test_ci_runs_the_pin_check(self):
        """The check is worthless in CI unless CI actually runs it."""
        import yaml

        with (REPO_ROOT / ".github" / "workflows" / "ci-cd.yaml").open(encoding="utf-8") as fh:
            data = yaml.safe_load(fh)
        steps = data["jobs"]["lint"]["steps"]
        names = [s.get("name", "") for s in steps]
        assert any("PyPI" in n for n in names), (
            f"lint job must verify pins against PyPI, got: {names}"
        )


class TestPyprojectIsValid:
    def test_pyproject_parses(self):
        import tomllib

        with Path(REPO_ROOT / "pyproject.toml").open("rb") as fh:
            data = tomllib.load(fh)
        assert data["project"]["name"] == "anomaly-detection"
        assert data["project"]["requires-python"] == ">=3.11"

    def test_version_is_static_not_dynamic(self):
        """Dependabot's pip fetcher cannot resolve a dynamic version.

        It silently reports '/pyproject.toml not parseable' and skips the repo.
        """
        import tomllib

        with Path(REPO_ROOT / "pyproject.toml").open("rb") as fh:
            project = tomllib.load(fh)["project"]
        assert "version" in project, "static version required for Dependabot"
        assert "dynamic" not in project, "dynamic metadata breaks Dependabot"
        assert isinstance(project["version"], str)

    def test_inline_tables_are_single_line(self):
        """Regression guard for the bug that broke Dependabot.

        TOML forbids newlines inside inline tables, so
        ``per-file-ignores = {`` ... ``}`` spread over several lines is invalid
        and tomllib raises. Assert every inline table stays on one line.
        """
        import tomllib

        raw = Path(REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8")
        for lineno, line in enumerate(raw.splitlines(), start=1):
            stripped = line.strip()
            if stripped.endswith("{"):
                pytest.fail(
                    f"pyproject.toml:{lineno} opens an inline table at end of line. "
                    "TOML does not allow newlines inside {}. Use a [table.sub] header."
                )
        # And the file must still parse, which is the real contract.
        with Path(REPO_ROOT / "pyproject.toml").open("rb") as fh:
            tomllib.load(fh)

    def test_author_email(self):
        import tomllib

        with Path(REPO_ROOT / "pyproject.toml").open("rb") as fh:
            data = tomllib.load(fh)
        assert data["project"]["authors"][0]["email"] == "kavymakhesana07@gmail.com"


class TestK8sManifests:
    def test_dev_overlay_is_valid_yaml(self):
        import yaml

        path = REPO_ROOT / "k8s" / "overlays" / "dev" / "kustomization.yaml"
        with Path(path).open(encoding="utf-8") as fh:
            data = yaml.safe_load(fh)
        assert data["kind"] == "Kustomization"
        assert data["namespace"] == "anomaly-detection"

    def test_namespace_manifest(self):
        import yaml

        path = REPO_ROOT / "k8s" / "base" / "namespace.yaml"
        with Path(path).open(encoding="utf-8") as fh:
            docs = list(yaml.safe_load_all(fh))
        names = {d["metadata"]["name"] for d in docs if d}
        assert "anomaly-detection" in names
        assert "streaming" in names
        assert "monitoring" in names


class TestCIWorkflow:
    def test_workflow_triggers_on_master(self):
        """Regression guard: CI must run on the repo's actual default branch."""
        import yaml

        path = REPO_ROOT / ".github" / "workflows" / "ci-cd.yaml"
        with Path(path).open(encoding="utf-8") as fh:
            data = yaml.safe_load(fh)
        branches = data[True]["push"]["branches"]  # YAML parses bare `on:` as True
        assert "master" in branches

    def test_docker_compose_services(self):
        import yaml

        path = REPO_ROOT / "docker-compose.yml"
        with Path(path).open(encoding="utf-8") as fh:
            data = yaml.safe_load(fh)
        services = data["services"]
        assert "redpanda" in services
        assert "feature-extractor" in services
        assert "fast-path" in services
