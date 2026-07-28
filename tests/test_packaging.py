from pathlib import Path
import tomllib


def test_project_uses_scanner_package_discovery_and_declares_http_runtime_dependencies():
    with (Path(__file__).parents[1] / "pyproject.toml").open("rb") as file:
        pyproject = tomllib.load(file)

    setuptools = pyproject["tool"]["setuptools"]
    assert setuptools["packages"]["find"]["include"] == ["scanner*"]
    assert not isinstance(setuptools["packages"], list)

    dependencies = pyproject["project"]["dependencies"]
    declared_packages = {dependency.split("[", 1)[0].split(">", 1)[0] for dependency in dependencies}
    assert {"fastapi", "uvicorn", "httpx", "pydantic"} <= declared_packages

    assert any(dependency.startswith("pytest") for dependency in pyproject["project"]["optional-dependencies"]["dev"])
