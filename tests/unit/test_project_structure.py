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
            "ingestion/live_capture",
            "ingestion/netflow",
            "ingestion/zeek",
            "ingestion/cloud_flows",
            "detection/fast_path",
            "detection/deep_path",
            "alerting",
        ],
    )
    def test_planned_module_directory_exists(self, path: str):
        """These dirs are created up front; their implementation lands on later days."""
        assert (REPO_ROOT / path).is_dir(), f"missing planned module dir: {path}"


class TestPyprojectIsValid:
    def test_pyproject_parses(self):
        import tomllib

        with Path(REPO_ROOT / "pyproject.toml").open("rb") as fh:
            data = tomllib.load(fh)
        assert data["project"]["name"] == "anomaly-detection"
        assert data["project"]["requires-python"] == ">=3.11"

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
