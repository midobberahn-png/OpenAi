"""Schichtgrenzen (docs/02-repo-struktur.md §1).

Die Ruff-Regel ``banned-api`` ist die erste Verteidigungslinie, aber sie lässt
sich per ``# noqa`` oder Konfigurationsänderung aushebeln. Dieser Test prüft
die Grenze am Quelltext selbst und schlägt auch dann fehl, wenn die Lint-Regel
unwirksam gemacht wurde.

Erlaubte Richtung:  apps → core → contracts
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
CONTRACTS = REPO / "packages" / "contracts" / "jarvis_contracts"
CORE = REPO / "packages" / "core" / "jarvis_core"

FORBIDDEN_IN_CONTRACTS = {"jarvis_core", "jarvis_api", "jarvis_providers", "jarvis_integrations"}
FORBIDDEN_IN_CORE = {"jarvis_api", "jarvis_providers", "jarvis_integrations"}


def _imported_roots(path: Path) -> set[str]:
    """Wurzelmodule aller absoluten Importe einer Datei."""
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    roots: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            roots.update(alias.name.split(".", 1)[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            roots.add(node.module.split(".", 1)[0])
    return roots


def _python_files(root: Path) -> list[Path]:
    return sorted(p for p in root.rglob("*.py") if "__pycache__" not in p.parts)


def test_contracts_verzeichnis_existiert() -> None:
    assert CONTRACTS.is_dir(), "Pfadannahme des Tests stimmt nicht mehr"
    assert CORE.is_dir()


@pytest.mark.invariant("layering-contracts-independent")
@pytest.mark.parametrize("path", _python_files(CONTRACTS), ids=lambda p: p.name)
def test_contracts_importiert_nichts_aus_dem_projekt(path: Path) -> None:
    """``contracts`` ist die Quelle der Wahrheit und darf von nichts abhängen.

    Ein Import nach oben würde einen Zyklus erzeugen und die Generierung von
    OpenAPI/TypeScript-Typen an Anwendungscode koppeln.
    """
    violations = _imported_roots(path) & FORBIDDEN_IN_CONTRACTS
    assert not violations, f"{path.name} importiert nach oben: {sorted(violations)}"


@pytest.mark.parametrize("path", _python_files(CORE), ids=lambda p: p.name)
def test_core_kennt_keine_konkreten_provider(path: Path) -> None:
    """``core`` spricht ausschließlich über Protokolle.

    Ein direkter Provider- oder Integrationsimport hier hieße: Der Kern wäre
    an einen Anbieter gebunden — genau das schließt ADR-009 aus.
    """
    violations = _imported_roots(path) & FORBIDDEN_IN_CORE
    assert not violations, f"{path.name} importiert eine Implementierung: {sorted(violations)}"


@pytest.mark.invariant("layering-no-provider-sdk-in-core")
def test_kein_provider_sdk_im_kern() -> None:
    """Kein OpenAI-, Anthropic- oder Google-Typ existiert außerhalb der
    Adapterschicht (Architekturprinzip 2)."""
    sdks = {"openai", "anthropic", "google", "ollama", "litellm", "langchain", "langgraph"}
    offenders: list[str] = []
    for path in [*_python_files(CORE), *_python_files(CONTRACTS)]:
        found = _imported_roots(path) & sdks
        if found:
            offenders.append(f"{path.relative_to(REPO)}: {sorted(found)}")
    assert not offenders, "Provider-SDK im Kern gefunden:\n" + "\n".join(offenders)
