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
API = REPO / "apps" / "api" / "jarvis_api"
ROUTES = API / "routes"
DEPS = API / "deps.py"

IDENTITAETSFELDER = {"user_id", "session_id", "owner_id", "actor_id", "invocation_id"}
"""Namen, die eine Identität behaupten. Ein Request darf sie nicht mitbringen."""

RESSOURCE_STATT_IDENTITAET = {
    ("undo.py", "undo_invocation", "invocation_id"),
}
"""Wo ein Name aus ``IDENTITAETSFELDER`` die **adressierte Ressource** meint.

Jede Zeile braucht eine Begründung, und hier ist sie:

``POST /invocations/{id}/undo`` nimmt einen ausgeführten Aufruf zurück. Der
Aufruf *ist* der Gegenstand — wie ``run_id`` bei ``/runs/{id}/advance`` und
``action_id`` bei ``/actions/{id}/respond``. Eine Identität behauptet er
nicht: Wem der Aufruf gehört, entscheidet der Lauf, und die Zugehörigkeit
steht in der ``WHERE``-Klausel von ``claim_undo`` — nicht in einer Prüfung
darüber und schon gar nicht im Request.

Warum ``invocation_id`` überhaupt auf der Liste steht: Im Bestätigungsablauf
darf ein Client sie **nicht** nennen. Dort benennt er die Aktion, und welche
Invokation daran hängt, ist eine Aussage des Systems über sich selbst — ein
Client, der sie mitbrächte, verknüpfte eine Bestätigung mit einem fremden
Aufruf. Diese Ausnahme hebt das nicht auf; sie sagt nur, dass es einen zweiten
Ablauf gibt, in dem dieselbe Kennung etwas anderes ist."""

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
    """Alle Dateien, die Endpunkte tragen könnten — nicht nur ``routes/``.

    Der Scan lag lange allein auf dem Verzeichnis. Ein externes Review hat
    darauf hingewiesen, dass eine Route auch anderswo entstehen kann; und
    tatsächlich lebt ``/health`` in ``main.py`` und wurde von keinem
    Strukturtest gesehen — es stand in der Ausnahmeliste, ohne je geprüft
    worden zu sein.

    Jetzt zählt die gesamte API-Schicht. Ein Endpunkt außerhalb von
    ``routes/`` ist dadurch nicht verboten, aber er ist sichtbar.
    """
    return sorted(
        p for p in API.rglob("*.py") if "__pycache__" not in p.parts and "migrations" not in p.parts
    )


HTTP_METHODEN = {"get", "post", "put", "patch", "delete", "head", "options", "api_route"}


def _endpoints(tree: ast.AST) -> list[ast.FunctionDef | ast.AsyncFunctionDef]:
    """Funktionen mit einem HTTP-Dekorator — **egal, wie das Objekt heißt**.

    Die erste Fassung suchte wörtlich ``router.<methode>``. Ein externes Review
    hat sie mit zwei Zeilen umgangen::

        _alias = router

        @_alias.post("/…")
        async def ohne_sitzung(payload: MitUserId): ...

    Elf von elf Strukturtests blieben grün, während ein Endpunkt ohne
    Sitzungsprüfung ``user_id`` aus dem Body las. Der Fehler lag nicht im
    Alias, sondern in der Annahme: Der Test hat nach einem *Namen* gesucht,
    obwohl ihn die *Form* interessiert.

    Jetzt zählt jeder Dekorator, dessen Attribut eine HTTP-Methode ist. Ein
    Endpunkt, der so nicht erkannt wird, ist auch für FastAPI keiner.
    """
    found: list[ast.FunctionDef | ast.AsyncFunctionDef] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
            continue
        for deco in node.decorator_list:
            call = deco.func if isinstance(deco, ast.Call) else deco
            if isinstance(call, ast.Attribute) and call.attr in HTTP_METHODEN:
                found.append(node)
                break
    return found


def _annotation_name(node: ast.expr | None) -> str:
    return ast.unparse(node) if node is not None else ""


PYDANTIC_BASEN = {"BaseModel", "pydantic.BaseModel"}
"""Wie ``BaseModel`` in einer Basisklassenliste geschrieben sein kann."""


def _pydantic_modelle(tree: ast.Module) -> set[str]:
    """Alle Klassen der Datei, die von ``BaseModel`` erben — auch über Ecken.

    Die Auflösung läuft, bis sich nichts mehr ändert: ``class A(BaseModel)``,
    ``class B(A)``, ``class C(B)``. Eine feste Zahl von Durchgängen wäre eine
    Annahme über die Tiefe der Vererbung, und genau solche Annahmen sind der
    Grund, warum dieser Test überarbeitet werden musste.
    """
    klassen = [n for n in ast.walk(tree) if isinstance(n, ast.ClassDef)]
    modelle: set[str] = set()
    gewachsen = True
    while gewachsen:
        gewachsen = False
        for klasse in klassen:
            if klasse.name in modelle:
                continue
            basen = {ast.unparse(b) for b in klasse.bases}
            if basen & (PYDANTIC_BASEN | modelle):
                modelle.add(klasse.name)
                gewachsen = True
    return modelle


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

    **Und alle Modelle heißt auch: die geerbten.** Die erste Fassung verlangte
    ``BaseModel`` als *direkte* Basisklasse. Eine externe Prüfung hat den
    Ausweg benannt, und er kostet zwei Zeilen:

        class RequestBase(BaseModel): ...
        class EvilRequest(RequestBase):
            user_id: UUID

    ``EvilRequest`` ist für FastAPI ein vollwertiges Request-Modell und war für
    diesen Test keines. Jetzt wird die Vererbung innerhalb der Datei
    aufgelöst — so weit, wie sie sich statisch verfolgen lässt: Eine Basis aus
    einem anderen Modul erkennt der Test nicht, und das steht hier, statt
    unausgesprochen zu bleiben.
    """
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    treffer: list[str] = []

    # Erst die Modelle bestimmen, dann ihre Felder: Eine Ableitung kann vor
    # ihrer Basis stehen, und ``ast.walk`` läuft nicht in Definitionsreihenfolge.
    modelle = _pydantic_modelle(tree)

    for node in ast.walk(tree):
        if not isinstance(node, ast.ClassDef) or node.name not in modelle:
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
            if (path.name, func.name, arg.arg) in RESSOURCE_STATT_IDENTITAET:
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


RESSOURCEN_PARAMETER = {"run_id", "action_id"}
"""Pfadparameter, die auf ein Objekt mit Eigentümer zeigen.

Anders als die Identitätsfelder oben sind sie **erlaubt** — eine Ressource zu
benennen ist der Sinn einer URL. Nur folgt daraus die nächste Pflicht: Wer
etwas benennt, das jemandem gehört, muss prüfen, ob es dem Anfragenden
gehört."""

ZUGEHOERIGKEITSPRUEFER = {"_eigener_lauf", "_eigene_aktion"}
"""Die einzigen Stellen, an denen ein fremdes Objekt geladen werden darf.

Sie liefern entweder das Objekt des angemeldeten Nutzers oder 404. Dass es
genau zwei benannte Funktionen sind, ist der Punkt: Die Prüfung an einer
Stelle zu haben heißt, sie an einer Stelle lesen zu können."""


@pytest.mark.invariant("resource-ownership-checked-once")
@pytest.mark.parametrize("path", _route_files(), ids=lambda p: p.name)
def test_endpunkt_mit_ressourcenkennung_prueft_die_zugehoerigkeit(path: Path) -> None:
    """Wer eine fremde Kennung entgegennimmt, muss die Zugehörigkeit prüfen.

    Die Sitzungsprüfung sagt nur, **wer** fragt. Sie sagt nichts darüber, ob
    das angefragte Objekt dem Fragenden gehört — und genau dort liegt der
    nächste kurze Angriff nach ``user_id`` im Body: eine gültige Sitzung, eine
    fremde ``run_id``.

    Ein Verhaltenstest deckt das für die heutigen Endpunkte ab. Dieser Test
    deckt den ab, den in einem Jahr jemand ergänzt.
    """
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    ungeprueft: list[str] = []

    for func in _endpoints(tree):
        benannt = {a.arg for a in [*func.args.args, *func.args.kwonlyargs]} & RESSOURCEN_PARAMETER
        if not benannt:
            continue
        aufgerufen = {
            node.func.id
            for node in ast.walk(func)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
        }
        if not aufgerufen & ZUGEHOERIGKEITSPRUEFER:
            ungeprueft.append(f"{func.name}({', '.join(sorted(benannt))})")

    assert not ungeprueft, (
        f"{path.name}: Endpunkte nehmen eine fremde Kennung entgegen, ohne die "
        f"Zugehörigkeit zu prüfen: {ungeprueft}. Eine gültige Sitzung ist keine "
        f"Berechtigung an einem beliebigen Objekt — {sorted(ZUGEHOERIGKEITSPRUEFER)} benutzen."
    )


@pytest.mark.invariant("resource-ownership-checked-once")
@pytest.mark.parametrize("path", _route_files(), ids=lambda p: p.name)
def test_kein_endpunkt_laedt_am_zugehoerigkeitspruefer_vorbei(path: Path) -> None:
    """Die Gegenrichtung: kein direktes ``load()`` im Endpunkt.

    Der Test oben verlangt den Aufruf des Prüfers. Er allein genügte nicht —
    ein Endpunkt könnte ihn aufrufen *und* daneben selbst laden. Der zweite
    Zugriff hätte die Prüfung nicht, und im Diff sähe alles richtig aus.

    Dieselbe Überlegung wie beim Router-Alias: Nicht der Aufruf ist das
    Problem, sondern der zweite Weg zum selben Ziel.
    """
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    treffer: list[str] = []

    for func in _endpoints(tree):
        for node in ast.walk(func):
            if (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and node.func.attr == "load"
            ):
                treffer.append(f"{func.name}:{node.lineno}")

    assert not treffer, (
        f"{path.name}: Endpunkte laden direkt: {treffer}. Das Laden fremder Objekte "
        f"gehört in {sorted(ZUGEHOERIGKEITSPRUEFER)} — dort steht die Prüfung."
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
        # ``deps.py`` ist die eine erlaubte Stelle — dort liegen
        # ``session_token_from`` und ``client_identifier``, und beide müssen
        # den Request lesen. Genau deshalb sind sie dort und nirgends sonst.
        if path == DEPS:
            continue
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

    Geprüft am Quelltext: ``current_session`` ruft die Prüfung des
    Sitzungsmanagers auf und wirft, wenn keine Sitzung herauskommt. Ein
    Rückgabewert ohne diesen Pfad wäre eine Identität, die nur behauptet wurde.

    **Zwei zulässige Namen, und das ist kein Aufweichen.** ``verify`` gibt die
    Sitzung oder ``None``, ``pruefen`` dieselbe Sitzung samt Ablehnungsgrund
    fürs Protokoll — beide gehen durch dieselbe Prüfung, ``verify`` ruft
    inzwischen ``pruefen`` auf. Was diese Wache sichert, ist nicht ein Name,
    sondern dass hier überhaupt geprüft wird.
    """
    tree = ast.parse(DEPS.read_text(encoding="utf-8"), filename=str(DEPS))
    funktion = next(
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.AsyncFunctionDef) and node.name == "current_session"
    )
    quelle = ast.dump(funktion)
    assert "verify" in quelle or "pruefen" in quelle, "current_session verifiziert den Token nicht"
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
        if not any(_hat_grenze(deco) for deco in func.decorator_list):
            fehlend.append(func.name)

    assert not fehlend, (
        f"{path.name}: Öffentliche Endpunkte ohne Zugriffsgrenze: {fehlend}. "
        "Wer ohne Anmeldung erreichbar ist, braucht eine."
    )


def _hat_grenze(deco: ast.expr) -> bool:
    """Steht in ``dependencies=[…]`` ein ``Depends(rate_limited(…))``?

    **Herkunft: externe Prüfung von ``61d4428``.** Die erste Fassung suchte den
    Namen ``rate_limited`` irgendwo im Dekorator — ein Vorkommen und keine
    Form. Ein Kommentar, ein Vorgabewert, ein gleichnamiges Feld hätte gereicht.

    Jetzt wird die Form geprüft: das Schlüsselwort ``dependencies``, darin ein
    ``Depends``-Aufruf, und darin ein Aufruf von ``rate_limited``.

    Was auch das nicht leistet, und deshalb steht es hier: Ein Strukturtest
    beweist nicht, dass die Dependency zur Laufzeit greift. Den Beweis führt
    ``tests/integration/test_rate_limit.py`` am Statuscode ``429`` — die beiden
    gehören zusammen, und keiner ersetzt den anderen.
    """
    if not isinstance(deco, ast.Call):
        return False
    for kw in deco.keywords:
        if kw.arg != "dependencies":
            continue
        for eintrag in ast.walk(kw.value):
            if (
                isinstance(eintrag, ast.Call)
                and _aufrufname(eintrag) == "Depends"
                and any(
                    isinstance(arg, ast.Call) and _aufrufname(arg) == "rate_limited"
                    for arg in eintrag.args
                )
            ):
                return True
    return False


def _aufrufname(node: ast.Call) -> str:
    """Der letzte Namensteil eines Aufrufs — ``a.b.c(…)`` ergibt ``c``."""
    if isinstance(node.func, ast.Name):
        return node.func.id
    if isinstance(node.func, ast.Attribute):
        return node.func.attr
    return ""


@pytest.mark.invariant("identity-derives-from-session")
@pytest.mark.parametrize("path", _route_files(), ids=lambda p: p.name)
def test_kein_zweitname_fuer_den_router(path: Path) -> None:
    """Ein Alias auf den Router ist ein zweiter Eingang.

    Der Test oben erkennt Endpunkte inzwischen an der HTTP-Methode statt am
    Objektnamen und ist damit gegen Aliase unempfindlich. Diese Prüfung kommt
    trotzdem dazu, weil ein Alias auch ohne Umgehungsabsicht ein schlechtes
    Zeichen ist: Wer einen zweiten Namen für denselben Router einführt, hat
    entweder einen Grund, den man lesen können sollte, oder keinen.
    """
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    aliase: list[str] = []

    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Assign)
            and isinstance(node.value, ast.Name)
            and node.value.id == "router"
        ):
            aliase.extend(t.id for t in node.targets if isinstance(t, ast.Name))
        if (
            isinstance(node, ast.AnnAssign)
            and isinstance(node.value, ast.Name)
            and node.value.id == "router"
            and isinstance(node.target, ast.Name)
        ):
            aliase.append(node.target.id)

    assert not aliase, (
        f"{path.name}: Zweitname(n) für den Router: {aliase}. "
        "Ein zweiter Name für denselben Eingang ist ein zweiter Eingang."
    )


@pytest.mark.invariant("identity-derives-from-session")
@pytest.mark.parametrize("path", _route_files(), ids=lambda p: p.name)
def test_keine_route_am_dekorator_vorbei(path: Path) -> None:
    """``add_api_route()`` registriert eine Route ohne Dekorator.

    Der Aufruf ist legitim — FastAPI bietet ihn für dynamische Fälle an —,
    aber er ist für den Strukturtest unsichtbar: Es gibt keine Funktion mit
    Dekorator, an der sich eine Sitzungsprüfung ablesen ließe. Wer ihn
    braucht, muss die Prüfung an anderer Stelle nachweisen, und das soll eine
    bewusste Entscheidung sein statt einer stillen.

    Dieselbe Überlegung wie beim Router-Alias: Nicht der Aufruf ist das
    Problem, sondern dass er die Prüfung umgeht, ohne dass es jemandem
    auffällt.
    """
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    treffer = [
        f"{path.name}:{node.lineno}"
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr in {"add_api_route", "add_websocket_route", "add_route"}
    ]

    assert not treffer, (
        f"Route ohne Dekorator registriert: {treffer}. Für den Strukturtest ist sie "
        "unsichtbar — die Sitzungsprüfung muss dann anderswo nachgewiesen werden."
    )


@pytest.mark.invariant("plan-step-claimed-before-effect")
def test_die_route_orchestriert_den_planschritt_nicht_selbst() -> None:
    """Der Ablauf eines Planschrittes gehört in den Kern, nicht in die Route.

    **Der Test hat einen Anlass, und der ist kein Stilhinweis.** An der Grenze
    zwischen HTTP-Schicht und Ablauf sind zwei Sicherheitslücken kurz
    nacheinander entstanden, beide an derselben Reihenfolge:

    * Der Anspruch auf den Schritt stand hinter der Wirkung statt davor.
    * Nachdem er davor stand, gab ein ``except`` ihn nach der Wirkung frei.

    Beide Male, weil *Anspruch → Wirkung → Festschreiben* über eine
    Routenfunktion verteilt war und sich nicht an einer Stelle überblicken
    ließ. Seit ``RunAdvancer`` steht die Reihenfolge an einer Stelle — und
    dieser Test hält fest, dass sie dort bleibt.

    Geprüft wird am Quelltext und nicht am Verhalten: Verhaltenstests zeigen,
    dass die *heutigen* Pfade sauber sind; ein AST-Test schlägt auch dann fehl,
    wenn in einem Jahr jemand „nur schnell" wieder ein ``execute_tool`` in die
    Route schreibt.
    """
    baum = ast.parse((ROUTES / "runs.py").read_text(encoding="utf-8"))

    # Der **Planschritt** ist gemeint, nicht jede Route der Datei.
    #
    # ``POST /runs/{id}/steps`` ruft weiterhin selbst den Executor: Dort nennt
    # der Aufrufer das Werkzeug, es gibt keinen Plan, keinen Anspruch und keine
    # Phasen — der Ablauf ist ein Aufruf und ein Speichern. Ihn mitzuverbieten
    # hieße, eine Grenze zu ziehen, die es nicht gibt.
    #
    # ``_planschritte`` liest ``ready_steps`` für die Anzeige. Lesen ist keine
    # Orchestrierung.
    (funktion,) = [
        k for k in ast.walk(baum) if isinstance(k, ast.AsyncFunctionDef) and k.name == "advance_run"
    ]

    aufrufe = {
        k.func.attr
        for k in ast.walk(funktion)
        if isinstance(k, ast.Call) and isinstance(k.func, ast.Attribute)
    }
    verboten = {
        "execute_tool",  # die Wirkung selbst
        "claim_step",  # der Anspruch …
        "reclaim_step",  # … seine Übernahme nach Ablauf der Frist …
        "release_step",  # … und seine Freigabe: die Stelle beider Befunde
        "for_step",  # der Modellaufruf
        "finish",  # der Abschluss des Laufs
        "ready_steps",  # die Auswahl des fälligen Schrittes
        "save",  # das Festschreiben
    }
    gefunden = aufrufe & verboten
    assert not gefunden, (
        f"advance_run orchestriert wieder selbst: {sorted(gefunden)}. Der Ablauf "
        "gehört in jarvis_core.orchestrator.advance — dort ist die Reihenfolge "
        "Anspruch → Wirkung → Festschreiben an einer Stelle sichtbar."
    )


# --------------------------------------------------------------------------
# Prüfungen der Prüfungen
#
# Zwei Strukturtests dieser Datei haben sich in externen Prüfungen als zu
# schwach erwiesen — einmal ein Router-Alias, einmal indirekte Vererbung. Ein
# Test, der nichts findet, sieht aus wie ein Test, der nichts zu finden hat.
# Deshalb bekommen die Erkenner hier ihre eigenen Fälle.
# --------------------------------------------------------------------------


def test_indirekte_vererbung_gilt_als_pydantic_modell() -> None:
    """Der Ausweg aus der externen Prüfung, nachgestellt.

    ``EvilRequest`` ist für FastAPI ein vollwertiges Request-Modell. Erkennt
    ihn der Erkenner nicht, geht ein ``user_id`` im Body durch, ohne dass ein
    Test anschlägt.
    """
    tree = ast.parse(
        "from pydantic import BaseModel\n"
        "class RequestBase(BaseModel): pass\n"
        "class Mittelbau(RequestBase): pass\n"
        "class EvilRequest(Mittelbau): pass\n"
        "class Fremd: pass\n"
    )

    modelle = _pydantic_modelle(tree)

    assert {"RequestBase", "Mittelbau", "EvilRequest"} <= modelle
    assert "Fremd" not in modelle, "Wer nicht erbt, ist keins."


def test_ein_erwaehnter_name_ist_keine_zugriffsgrenze() -> None:
    """Der Unterschied zwischen Vorkommen und Form.

    Beide Dekoratoren unten enthalten die Zeichenfolge ``rate_limited``. Nur
    einer davon hängt tatsächlich eine Dependency ein.
    """
    echt, getarnt = ast.parse(
        "@router.post('/a', dependencies=[Depends(rate_limited(BOOTSTRAP))])\n"
        "async def a(): ...\n"
        "@router.post('/b', response_model=rate_limited)\n"
        "async def b(): ...\n"
    ).body

    assert isinstance(echt, ast.AsyncFunctionDef) and isinstance(getarnt, ast.AsyncFunctionDef)
    assert _hat_grenze(echt.decorator_list[0])
    assert not _hat_grenze(getarnt.decorator_list[0]), (
        "Ein Name im Dekorator ist keine Zugriffsgrenze."
    )
