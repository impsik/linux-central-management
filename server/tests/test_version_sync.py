import ast
from pathlib import Path
import shutil
import subprocess
import sys

import pytest


REPO_ROOT = Path(__file__).resolve().parents[2]
GENERATED_FILES = (
    "server/app/version.py",
    "agent/cmd/fleet-agent/version.go",
)


@pytest.fixture
def checkout(tmp_path):
    (tmp_path / "scripts").mkdir()
    shutil.copyfile(REPO_ROOT / "scripts/sync-version.py", tmp_path / "scripts/sync-version.py")
    (tmp_path / "VERSION").write_text("0.1.0-beta.1\n", encoding="utf-8")
    return tmp_path


def run_sync(checkout, *args):
    return subprocess.run(
        [sys.executable, str(checkout / "scripts/sync-version.py"), *args],
        cwd=checkout,
        capture_output=True,
        text=True,
        check=False,
    )


def generated_snapshot(checkout):
    return {
        name: ((checkout / name).read_bytes(), (checkout / name).stat().st_mtime_ns)
        for name in GENERATED_FILES
        if (checkout / name).exists()
    }


def test_check_reports_missing_files_without_creating_them(checkout):
    result = run_sync(checkout, "--check")

    assert result.returncode == 1
    for name in GENERATED_FILES:
        assert name in result.stderr
    assert not (checkout / "server").exists()
    assert not (checkout / "agent").exists()


@pytest.mark.parametrize("version", ["0.1.0-beta.1", "1.0.0", "2.3.4-rc.2+build.001"])
def test_sync_generates_both_languages_and_is_idempotent(checkout, version):
    (checkout / "VERSION").write_text(version + "\n", encoding="utf-8")

    result = run_sync(checkout)
    assert result.returncode == 0, result.stderr
    module = ast.parse((checkout / GENERATED_FILES[0]).read_text(encoding="utf-8"))
    assignment = module.body[0]
    assert isinstance(assignment, ast.Assign)
    assert assignment.targets[0].id == "APP_VERSION"
    assert ast.literal_eval(assignment.value) == version
    assert f'const AgentVersion = "{version}"' in (
        checkout / GENERATED_FILES[1]
    ).read_text(encoding="utf-8")

    original = generated_snapshot(checkout)
    assert run_sync(checkout, "--check").returncode == 0
    assert generated_snapshot(checkout) == original
    assert run_sync(checkout).returncode == 0
    assert generated_snapshot(checkout) == original


def test_check_detects_drift_without_repairing_files(checkout):
    assert run_sync(checkout).returncode == 0
    (checkout / GENERATED_FILES[0]).write_text('APP_VERSION = "stale"\n', encoding="utf-8")
    (checkout / "VERSION").write_text("0.2.0-beta.1\n", encoding="utf-8")
    original = generated_snapshot(checkout)

    result = run_sync(checkout, "--check")

    assert result.returncode == 1
    for name in GENERATED_FILES:
        assert name in result.stderr
    assert generated_snapshot(checkout) == original
    assert run_sync(checkout).returncode == 0
    assert run_sync(checkout, "--check").returncode == 0


@pytest.mark.parametrize(
    "version",
    ["", "v1.2.3", "1.2", "01.2.3", "1.02.3", "1.2.03", "1.2.3-01",
     "1.2.3-beta..1", "1.2.3+build..1", "1.2.3; bad", "1.2.3\n2.0.0"],
)
def test_invalid_version_never_changes_generated_files(checkout, version):
    assert run_sync(checkout).returncode == 0
    original = generated_snapshot(checkout)
    (checkout / "VERSION").write_text(version, encoding="utf-8")

    for args in [(), ("--check",)]:
        result = run_sync(checkout, *args)
        assert result.returncode == 2
        assert "valid SemVer" in result.stderr
        assert generated_snapshot(checkout) == original


def test_missing_version_fails_without_creating_generated_files(checkout):
    (checkout / "VERSION").unlink()

    result = run_sync(checkout)

    assert result.returncode == 2
    assert "VERSION" in result.stderr
    assert not generated_snapshot(checkout)
