"""Die HTTP-Grenze — Identität entsteht an genau einer Stelle.

Der Angriff, gegen den diese Suite steht, ist der kürzeste im ganzen System:
Ein Feld ``user_id`` in einem Request-Body. Es sieht harmlos aus, es ist
bequem, und es führt über Policy und Approval geradewegs zu einem
``ExecutionGrant`` für ein fremdes Konto.

Geprüft wird am Quelltext, nicht am Verhalten. Ein Verhaltenstest zeigt, dass
die *heutigen* Endpunkte sauber sind; der Strukturtest schlägt auch dann fehl,
wenn in einem Jahr jemand einen Endpunkt ergänzt, für den niemand einen Test
schreibt. Dieselbe Begründung wie beim ``ExecutionGrant``.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

pytestmark = pytest.mark.security

REPO = Path(__file__).resolve().parents[2]
ROUTES = REPO / "apps" / "api" / "jarvis_api" / "routes"
DEPS = REPO / "apps" / "api" / "jarvis_api" / "deps.py"

IDENTITAETSFELDER = {"user_id", "session_id", "owner_id", "actor_id", "invocation_id"}
"""Namen, die eine Identität behaupten. Ein Request darf sie nicht mitbringen."""

OEFFENTLICH = {
    "bootstrap",
    "login_start",
    "login_finish",
    "register_finish",
    "health",
}
"""Endpunkte ohne Sitzungspflicht — jeder mit Begründung:

* ``bootstrap`` — legt den ersten Nutzer an; es gibt noch niemanden, der sich
  anmelden könnte. Die Einmaligkeit trägt die Datenbank.
* ``login_start`` / ``login_finish`` — der Weg zur Sitzung selbst.
* ``register_finish`` — der Nutzer steckt in der Challenge, die beim Start
  ausgestellt wurde. Eine Sitzungspflicht hier machte den Bootstrap unmöglich,
  ohne etwas hinzuzufügen.
* ``health`` — Erreichbarkeit, ohne Daten.

Die Liste ist ausdrücklich hier und nicht im Anwendungscode: Eine neue
öffentliche Route zu erklären ist damit eine sichtbare Änderung an einer
Testdatei, kein Weglassen eines Parameters.
"""


def _route_files() -> list[Path]:
    return sorted(p for p in ROUTES.rglob("*.py") if "__pycache__" not in p.parts)


def _endpoints(tree: ast.AST) -> list[ast.FunctionDef | ast.AsyncFunctionDef]:
    """Funktionen mit einem ``@router.<methode>``-Dekorator."""
    found: list[ast.FunctionDef | ast.AsyncFunctionDef] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
            continue
        for deco in node.decorator_list:
            call = deco.func if isinstance(deco, ast.Call) else deco
            if (
                isinstance(call, ast.Attribute)
                and isinstance(call.value, ast.Name)
                and call.value.id == "router"
            ):
                found.append(node)
                break
    return found


def _annotation_name(node: ast.expr | None) -> str:
    return ast.unparse(node) if node is not None else ""


def test_routen_verzeichnis_existiert() -> None:
    assert ROUTES.is_dir(), "Pfadannahme des Tests stimmt nicht mehr"
    assert _route_files(), "Ohne Routen prüft dieser Test nichts"


@pytest.mark.invariant("identity-derives-from-session")
@pytest.mark.parametrize("path", _route_files(), ids=lambda p: p.name)
def test_kein_request_modell_traegt_eine_identitaet(path: Path) -> None:
    """Kein Pydantic-Modell in den Routen hat ein Feld ``user_id`` & Co.

    Der Test trifft absichtlich *alle* Modelle der Datei, nicht nur die als
    Body verwendeten: Ein Modell, das heute nur intern genutzt wird, ist
    morgen ein Request-Body.
    """
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    treffer: list[str] = []

    for node in ast.walk(tree):
        if not isinstance(node, ast.ClassDef):
            continue
        basen = {ast.unparse(b) for b in node.bases}
        if "BaseModel" not in basen:
            continue
        for stmt in node.body:
            if (
                isinstance(stmt, ast.AnnAssign)
                and isinstance(stmt.target, ast.Name)
                and stmt.target.id in IDENTITAETSFELDER
            ):
                treffer.append(f"{node.name}.{stmt.target.id}")

    assert not treffer, (
        f"{path.name}: Request-Modelle führen Identitätsfelder {treffer}. "
        "Die Identität stammt aus der Sitzung, nicht aus dem Request."
    )


@pytest.mark.invariant("identity-derives-from-session")
@pytest.mark.parametrize("path", _route_files(), ids=lambda p: p.name)
def test_kein_endpunkt_nimmt_eine_identitaet_entgegen(path: Path) -> None:
    """Kein Endpunkt hat einen Parameter ``user_id`` oder ``session_id``.

    Ausgenommen ist, was als ``CurrentSession`` typisiert ist — das *ist* die
    geprüfte Identität. Ein Pfadparameter darf eine Ressource benennen
    (``target_id``), aber keine Identität behaupten.
    """
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    treffer: list[str] = []

    for func in _endpoints(tree):
        for arg in [*func.args.args, *func.args.kwonlyargs]:
            if arg.arg not in IDENTITAETSFELDER:
                continue
            if _annotation_name(arg.annotation) == "CurrentSession":
                continue
            treffer.append(f"{func.name}({arg.arg})")

    assert not treffer, (
        f"{path.name}: Endpunkte nehmen eine Identität entgegen: {treffer}. "
        "Sie muss aus CurrentSession stammen."
    )


@pytest.mark.invariant("identity-derives-from-session")
@pytest.mark.parametrize("path", _route_files(), ids=lambda p: p.name)
def test_jeder_endpunkt_ist_geschuetzt_oder_ausdruecklich_oeffentlich(path: Path) -> None:
    """Eine vergessene Sitzungsprüfung ist der klassische Fehler der Schicht.

    Deshalb die umgekehrte Beweislast: Jeder Endpunkt verlangt eine Sitzung,
    es sei denn, er steht in der begründeten Ausnahmeliste dieser Datei.
    """
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    ungeschuetzt: list[str] = []

    for func in _endpoints(tree):
        if func.name in OEFFENTLICH:
            continue
        annotationen = {
            _annotation_name(a.annotation) for a in [*func.args.args, *func.args.kwonlyargs]
        }
        if "CurrentSession" not in annotationen:
            ungeschuetzt.append(func.name)

    assert not ungeschuetzt, (
        f"{path.name}: Endpunkte ohne Sitzungsprüfung: {ungeschuetzt}. "
        "Entweder CurrentSession ergänzen oder in OEFFENTLICH begründen."
    )


@pytest.mark.invariant("identity-derives-from-session")
def test_die_sitzung_wird_an_genau_einer_stelle_gelesen() -> None:
    """``session_token_from`` ist der einzige Ort, an dem ein Token aus dem
    Request gelesen wird.

    Sobald eine Route selbst in Cookies oder Header greift, gibt es einen
    zweiten Weg zur Identität — und der durchläuft die Prüfung nicht.
    """
    treffer: list[str] = []
    for path in _route_files():
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Attribute):
                continue
            if node.attr in {"cookies", "headers", "query_params"} and isinstance(
                node.value, ast.Name
            ):
                treffer.append(f"{path.name}:{node.lineno} ({node.value.id}.{node.attr})")

    assert not treffer, (
        "Routen greifen selbst auf Request-Daten zu: " + ", ".join(treffer) + ". "
        "Der Zugriff gehört ausschließlich in deps.session_token_from()."
    )


@pytest.mark.invariant("identity-derives-from-session")
def test_current_session_prueft_tatsaechlich() -> None:
    """Die Dependency darf keine Sitzung ohne Verifikation herausgeben.

    Geprüft am Quelltext: ``current_session`` ruft ``verify`` auf und wirft bei
    ``None``. Ein Rückgabewert ohne diesen Pfad wäre eine Identität, die nur
    behauptet wurde.
    """
    tree = ast.parse(DEPS.read_text(encoding="utf-8"), filename=str(DEPS))
    funktion = next(
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.AsyncFunctionDef) and node.name == "current_session"
    )
    quelle = ast.dump(funktion)
    assert "verify" in quelle, "current_session verifiziert den Token nicht"
    assert "HTTPException" in quelle, "current_session lehnt eine ungültige Sitzung nicht ab"


@pytest.mark.invariant("auth-endpoints-rate-limited")
@pytest.mark.parametrize("path", _route_files(), ids=lambda p: p.name)
def test_jeder_oeffentliche_endpunkt_ist_begrenzt(path: Path) -> None:
    """Wieder die umgekehrte Beweislast — und diesmal trifft sie genau die
    Endpunkte, die sie braucht.

    Ein Endpunkt ohne Sitzungspflicht ist ein Endpunkt, den jeder aufrufen
    kann. Zwei der vier erzeugen dabei Datenbankzustand (Challenges), einer
    legt einen Nutzer an. Ohne Grenze ist das der bequemste Weg, die Tabelle
    zu füllen, bis nichts mehr geht.

    ``health`` ist ausgenommen: Er liest nichts und schreibt nichts. Eine
    Grenze dort würde im Störungsfall die Überwachung aussperren — also genau
    dann, wenn man sie braucht.
    """
    ohne_grenze_erlaubt = {"health"}
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    fehlend: list[str] = []

    for func in _endpoints(tree):
        if func.name not in OEFFENTLICH or func.name in ohne_grenze_erlaubt:
            continue
        dekoratoren = ast.dump(ast.Module(body=func.decorator_list, type_ignores=[]))
        if "rate_limited" not in dekoratoren:
            fehlend.append(func.name)

    assert not fehlend, (
        f"{path.name}: Öffentliche Endpunkte ohne Zugriffsgrenze: {fehlend}. "
        "Wer ohne Anmeldung erreichbar ist, braucht eine."
    )
