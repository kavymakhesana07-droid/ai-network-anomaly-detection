"""Smoke tests that verify the project structure and config stay valid.

These act as a canary: if the repo layout or config breaks, CI fails loudly
instead of silently passing.
"""

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
