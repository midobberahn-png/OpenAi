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
FORBIDDEN_IN_CORE = {
    "jarvis_api",
    "jarvis_providers",
    "jarvis_integrations",
    # Kein Webframework im Kern.
    #
    # Ergänzt, als die Ablaufsteuerung eines Planschrittes aus der Routendatei
    # in den Kern zog. Der bequeme Weg wäre gewesen, die ``HTTPException``
    # mitzunehmen — und damit die Entscheidung „welcher Statuscode?" in eine
    # Schicht zu legen, die von HTTP nichts wissen soll. Ein Kern, der 409
    # kennt, ist ein Kern, der nur noch über HTTP benutzbar ist; ein Worker,
    # der Läufe fortsetzt, spricht kein HTTP.
    "fastapi",
    "starlette",
}


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


@pytest.mark.invariant("policy-single-entry-point")
def test_execution_grant_wird_nur_im_gateway_erzeugt() -> None:
    """Findet jede Konstruktion außerhalb von ``approval.py``.

    Die erste Fassung suchte ausschließlich ``ExecutionGrant(...)`` als
    ``ast.Name``. Ein externes Review hat sie mit ``approval.ExecutionGrant(...)``
    umgangen — ein Attributzugriff, und der Test blieb grün. Seitdem wird jeder
    Aufruf geprüft, dessen *aufgerufener Name* am Ende ``ExecutionGrant`` heißt,
    unabhängig davon, wie er erreicht wird.

    Zusätzlich werden Import-Aliase erfasst: ``from ... import ExecutionGrant as
    EG`` verschiebt den Namen, nicht die Sache.

    Wichtig zur Einordnung: Dieser Test ist seit dem Bypass-Befund **nicht mehr
    die eigentliche Absicherung**. Die trägt die nominale Prüfung in
    ``ToolRegistry.execute()``. Ein AST-Test kennt nur die Muster, die man ihm
    beigebracht hat; die Laufzeit kennt das Objekt.
    """
    gateway = CORE / "policy" / "approval.py"
    offenders: list[str] = []

    for path in [*_python_files(CORE), *_python_files(REPO / "apps")]:
        if path == gateway:
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))

        # Aliase auflösen: Unter welchen Namen ist die Klasse hier bekannt?
        namen = {"ExecutionGrant"}
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom):
                for alias in node.names:
                    if alias.name == "ExecutionGrant" and alias.asname:
                        namen.add(alias.asname)

        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                gerufen = node.func
                # Sowohl Name(...) als auch modul.Name(...) und a.b.Name(...)
                schluss = (
                    gerufen.id
                    if isinstance(gerufen, ast.Name)
                    else gerufen.attr
                    if isinstance(gerufen, ast.Attribute)
                    else ""
                )
                if schluss in namen:
                    offenders.append(f"{path.relative_to(REPO)}:{node.lineno}")
            if isinstance(node, ast.Name) and node.id == "_GRANT_SENTINEL":
                offenders.append(f"{path.relative_to(REPO)}:{node.lineno} (Sentinel)")

    assert not offenders, (
        "ExecutionGrant wird außerhalb des Approval Gateways erzeugt — das wäre "
        "die Umgehung des Ausführungs-Gates:\n" + "\n".join(offenders)
    )


@pytest.mark.invariant("undo-is-bound-to-its-invocation")
def test_undo_grant_wird_nur_im_undo_gateway_erzeugt() -> None:
    """Dieselbe Suche wie beim Ausführungs-Grant, für den Rücknahme-Grant.

    Der Grund ist derselbe und wiegt hier eher schwerer: Ein selbst gebauter
    ``UndoGrant`` wäre ein Löschweg ohne Zugehörigkeitsprüfung. Wer ihn
    konstruieren kann, löscht fremde Termine, ohne dass Frist, Anspruch oder
    Eigentümer je geprüft würden.

    Und dieselbe Einordnung: Der AST-Test kennt nur die Muster, die man ihm
    beigebracht hat. Die eigentliche Absicherung ist die nominale Prüfung in
    ``ToolRegistry.undo()``.
    """
    gateway = CORE / "policy" / "undo.py"
    offenders: list[str] = []

    for path in [*_python_files(CORE), *_python_files(REPO / "apps")]:
        if path == gateway:
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))

        namen = {"UndoGrant"}
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom):
                for alias in node.names:
                    if alias.name == "UndoGrant" and alias.asname:
                        namen.add(alias.asname)

        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                gerufen = node.func
                schluss = (
                    gerufen.id
                    if isinstance(gerufen, ast.Name)
                    else gerufen.attr
                    if isinstance(gerufen, ast.Attribute)
                    else ""
                )
                if schluss in namen:
                    offenders.append(f"{path.relative_to(REPO)}:{node.lineno}")
            if isinstance(node, ast.Name) and node.id == "_UNDO_SENTINEL":
                offenders.append(f"{path.relative_to(REPO)}:{node.lineno} (Sentinel)")

    assert not offenders, (
        "UndoGrant wird außerhalb des Undo-Gateways erzeugt — das wäre ein Löschweg "
        "ohne Zugehörigkeitsprüfung:\n" + "\n".join(offenders)
    )


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


ORCHESTRATOR = CORE / "orchestrator"


@pytest.mark.parametrize("path", _python_files(ORCHESTRATOR), ids=lambda p: p.name)
def test_der_orchestrator_importiert_nicht_aus_agents(path: Path) -> None:
    """Die Richtung zwischen ``agents`` und ``orchestrator`` ist eine Einbahnstraße.

    ``agents`` benutzt Executor und Budgetzähler des Orchestrators — nie
    umgekehrt. Beim Anschließen der Agentenschleife war der bequeme Weg, die
    Zusammensetzung (``AgentStepSource``) im Orchestrator abzulegen und dort
    ``ModelLoop`` zu importieren. Das schließt den Kreis, und zwar sofort:
    ``agents.runtime`` importiert ``orchestrator.executor``, was das Paket
    ``orchestrator`` lädt, was die neue Datei lädt, die ``agents`` lädt.

    Gemessen an einem ``ImportError`` beim ersten Testlauf und nicht
    vorhergesehen — deshalb steht die Grenze jetzt als Test da und nicht als
    guter Vorsatz. Der Ablauf kennt ein Protokoll (``AgentStepRunner``); was es
    erfüllt, entsteht bei den Agenten.
    """
    module = [
        node.module
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"), filename=str(path)))
        if isinstance(node, ast.ImportFrom) and node.level == 0 and node.module
    ]
    verstoesse = [m for m in module if m.startswith("jarvis_core.agents")]
    assert not verstoesse, (
        f"{path.name} importiert aus jarvis_core.agents: {sorted(verstoesse)}. "
        "Der Orchestrator spricht über Protokolle; die Zusammensetzung gehört "
        "zu den Agenten."
    )


PERMISSIONS_ROUTE = REPO / "apps" / "api" / "jarvis_api" / "routes" / "permissions.py"
PERMISSION_STORE = REPO / "apps" / "api" / "jarvis_api" / "db" / "permission_store.py"
SCHREIBENDE_RECHTE = {"upsert_grant", "revoke_grant"}


@pytest.mark.invariant("permissions-change-only-at-the-edge")
def test_berechtigungen_aendert_nur_die_kante() -> None:
    """Rechte erteilt ein Mensch, kein Werkzeug.

    Die gefährliche Richtung ist das Erteilen: Ein Scope auf ``allow`` nimmt
    jede künftige Bestätigung aus dem Weg — genau den Dialog, den ein Mensch
    liest, bevor etwas nach außen wirkt. Ein Werkzeug, das Berechtigungen
    schreibt, wäre damit der kürzeste Weg von „ein Modell hat Fremdinhalt
    gelesen" zu „das Modell darf jetzt mehr".

    Der Typ kann das nicht verhindern — ``PermissionAdmin`` ist ein Protokoll,
    und wer es hereinreicht, kann es benutzen. Deshalb steht die Grenze hier:
    ``upsert_grant`` und ``revoke`` werden **ausschließlich** in der Route und
    in ihrer eigenen Implementierung gerufen.

    Die Methode heißt ``revoke_grant`` und nicht ``revoke``, und das ist die
    Lehre aus der ersten Fassung dieses Tests: ``revoke`` heißt anderswo auch
    das Beenden einer Sitzung, und der Test schlug an drei Stellen an, die
    nichts mit Berechtigungen zu tun haben. Der Ausweg wäre eine Ausnahmeliste
    gewesen — und eine Ausnahmeliste wächst, bis sie den Test aufhebt. Ein
    eindeutiger Name kostet nichts.
    """
    erlaubt = {PERMISSIONS_ROUTE, PERMISSION_STORE}
    offenders: list[str] = []

    for path in [*_python_files(CORE), *_python_files(REPO / "apps")]:
        if path in erlaubt:
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and node.func.attr in SCHREIBENDE_RECHTE
            ):
                offenders.append(f"{path.relative_to(REPO)}:{node.lineno} ({node.func.attr})")

    assert not offenders, (
        "Berechtigungen werden außerhalb der Kante geschrieben:\n"
        + "\n".join(offenders)
        + "\nRechte erteilt ein Mensch, kein Werkzeug."
    )


@pytest.mark.invariant("permissions-change-only-at-the-edge")
def test_kein_werkzeug_traegt_einen_berechtigungs_scope() -> None:
    """Und keines darf je einen bekommen.

    Die Gegenrichtung derselben Grenze: Selbst wenn niemand den schreibenden
    Port hereinreicht, wäre ein Werkzeug mit einem Scope aus der
    Berechtigungsfamilie die Ankündigung, dass es einen geben soll. Der
    Scope-Katalog kennt keinen solchen — und dieser Test hält fest, dass das
    eine Entscheidung ist und kein Zufall.
    """
    from jarvis_core.tools.builtin import CALENDAR_CREATE, FILES_READ

    for spec in (CALENDAR_CREATE, FILES_READ):
        assert not any(scope.startswith("permissions.") for scope in spec.scopes), (
            f"{spec.name} verlangt einen Berechtigungs-Scope: {spec.scopes}"
        )
