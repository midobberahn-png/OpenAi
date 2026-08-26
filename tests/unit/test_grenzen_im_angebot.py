"""Was ein Modell über seine Grenzen erfährt — und wer es ihm sagt.

**Der Befund dahinter:** Die Argumentquelle traf ``projektnotiz.md`` in 0 von 3
Fällen, wenn nur die freigegebene Wurzel bekannt war. Zwei Hälften beheben das
(ADR-019): ``files.list`` zum Nachsehen und die Auskunft, *wo* nachzusehen ist.
Diese Suite prüft die zweite.

**Gemessen wird sie gegen ein echtes Modell** (``test_ollama_live.py``,
``TestWasEinModellNichtRatenMuss``) — und genau deshalb steht diese Suite hier:
Der Live-Durchstich wird in CI übersprungen, weil dort kein Modell läuft. Was
nur mit Ollama geprüft ist, ist in der Pipeline ungeprüft.

Die tragende Entscheidung ist, **wo** der Satz entsteht: bei der Einschränkung
selbst (``hints()``), also dort, wo die Grenze auch durchgesetzt wird. Eine
Auskunft, die daneben gepflegt wird, driftet ab — und dann verspricht das
Angebot etwas, das die Ablehnung später bestreitet.
"""

from __future__ import annotations

import uuid

import pytest

from jarvis_contracts import (
    FilesConstraints,
    PermissionGrant,
    PermissionMode,
    ScopeConstraints,
    mit_hinweisen,
)
from jarvis_core.policy import PolicyEngine
from jarvis_core.tools import ToolRegistry
from jarvis_core.tools.builtin import FILES_READ
from tests.fakes import NOW

pytestmark = pytest.mark.security

NUTZER = uuid.uuid4()


class FakePermissions:
    """Berechtigungen aus einem Wörterbuch — mehr braucht diese Frage nicht."""

    def __init__(self, grants: dict[str, PermissionGrant] | None = None) -> None:
        self.grants = grants or {}

    async def get_grant(self, user_id: uuid.UUID, scope: str) -> PermissionGrant | None:
        return self.grants.get(scope)

    async def granted_scopes(self, user_id: uuid.UUID) -> set[str]:
        return set(self.grants)


def _grant(scope: str, constraints: ScopeConstraints) -> PermissionGrant:
    return PermissionGrant(
        scope=scope, mode=PermissionMode.ALLOW, constraints=constraints, granted_at=NOW
    )


class TestDieEinschraenkungErklaertSichSelbst:
    def test_die_wurzeln_stehen_im_satz(self) -> None:
        hinweise = FilesConstraints(allowed_roots=["/a/notizen", "/b/projekte"]).hints()

        assert "/a/notizen" in hinweise["path"]
        assert "/b/projekte" in hinweise["path"]

    def test_die_gesperrten_endungen_stehen_nicht_darin(self) -> None:
        """Eine Liste von Absagen ist kein Startpunkt.

        Ein Modell, das sie aufzählen könnte, wüsste nur, was es nicht darf —
        und es wäre eine Auskunft mehr über die Konfiguration.
        """
        hinweise = FilesConstraints(allowed_roots=["/a"], forbidden_extensions=[".sh"]).hints()

        assert ".sh" not in hinweise["path"]

    def test_ohne_eigene_einschraenkung_wird_nichts_erklaert(self) -> None:
        """Vorgabe ist leer — dieselbe Beweislast wie bei
        ``model_visible_fields``: Wer etwas preisgeben will, sagt es."""
        assert ScopeConstraints().hints() == {}


class TestDasSchemaTraegtDieGrenze:
    def test_der_hinweis_wird_angehaengt_nicht_ersetzt(self) -> None:
        """Die Beschreibung sagt, *was* ein Argument ist; der Hinweis, *welche
        Werte* dieser Nutzer nennen darf. Beides ist wahr."""
        vorher = FILES_READ.parameters["properties"]["path"]["description"]

        neu = mit_hinweisen(FILES_READ, {"path": "Zugelassen sind: /a."})

        beschreibung = neu.parameters["properties"]["path"]["description"]
        assert beschreibung.startswith(vorher)
        assert beschreibung.endswith("Zugelassen sind: /a.")

    def test_die_spezifikation_im_katalog_bleibt_unberuehrt(self) -> None:
        """**Der teuerste denkbare Fehler an dieser Stelle.**

        Der Katalog ist je Prozess derselbe für alle. Würde er hier verändert,
        bekäme der nächste Nutzer die Grenzen des vorigen zu sehen.
        """
        mit_hinweisen(FILES_READ, {"path": "Zugelassen sind: /geheim."})

        assert "geheim" not in str(FILES_READ.parameters)

    def test_ohne_hinweise_kommt_dieselbe_spezifikation_zurueck(self) -> None:
        assert mit_hinweisen(FILES_READ, {}) is FILES_READ

    def test_ein_unbekanntes_argument_wird_uebergangen(self) -> None:
        """Kein Fehler: Eine Einschränkung darf ein Feld nennen, das dieses
        Werkzeug nicht führt — sie gilt je Scope, nicht je Werkzeug."""
        neu = mit_hinweisen(FILES_READ, {"gibtsnicht": "…"})

        assert set(neu.parameters["properties"]) == set(FILES_READ.parameters["properties"])


class TestDasAngebotDerPolicy:
    def _engine(self, permissions: FakePermissions) -> PolicyEngine:
        registry = ToolRegistry()
        registry.register(FILES_READ, lambda **_: None)
        return PolicyEngine(registry, permissions)  # type: ignore[arg-type]

    async def test_mit_berechtigung_stehen_die_wurzeln_im_schema(self) -> None:
        engine = self._engine(
            FakePermissions(
                {"files.read": _grant("files.read", FilesConstraints(allowed_roots=["/a/notizen"]))}
            )
        )

        angeboten = await engine.angebot(FILES_READ, NUTZER)

        assert "/a/notizen" in angeboten.parameters["properties"]["path"]["description"]

    async def test_ohne_berechtigung_bleibt_die_spezifikation_unveraendert(self) -> None:
        """Was nicht erteilt ist, wird auch nicht beschrieben — und angeboten
        wird das Werkzeug dann ohnehin nicht."""
        engine = self._engine(FakePermissions())

        angeboten = await engine.angebot(FILES_READ, NUTZER)

        assert angeboten.parameters == FILES_READ.parameters

    async def test_eine_zurueckgezogene_berechtigung_verschwindet_aus_dem_satz(self) -> None:
        """Der Grund, warum das je Aufruf ermittelt wird und nicht einmal.

        Ein Hinweis, der eine entzogene Freigabe weiter nennt, ist die
        schlechteste Sorte Falschaussage: Das Modell hält sich daran, und die
        Ablehnung kommt trotzdem.
        """
        rechte = FakePermissions(
            {"files.read": _grant("files.read", FilesConstraints(allowed_roots=["/a/notizen"]))}
        )
        engine = self._engine(rechte)
        zuerst = await engine.angebot(FILES_READ, NUTZER)
        assert "/a/notizen" in zuerst.parameters["properties"]["path"]["description"]

        rechte.grants.clear()

        assert (await engine.angebot(FILES_READ, NUTZER)).parameters == FILES_READ.parameters


class TestDerAgentenwegBekommtDasselbe:
    def test_die_registry_reicht_hinweise_ins_schema(self) -> None:
        """Der zweite Ort, an dem ein Modell Werkzeuge sieht.

        Eine Auskunft, die nur an einem von zwei Modellwegen anliegt, ist
        keine — der Sub-Agent riete sonst genau dort weiter, wo die
        Argumentquelle es nicht mehr tut.
        """
        registry = ToolRegistry()
        registry.register(FILES_READ, lambda **_: None)

        schema = registry.to_schema(
            {"files.read"}, hinweise={"files.read": {"path": "Zugelassen sind: /a."}}
        )

        beschreibung = schema[0]["input_schema"]["properties"]["path"]["description"]
        assert "Zugelassen sind: /a." in beschreibung

    def test_ohne_hinweise_bleibt_das_schema_wie_es_war(self) -> None:
        registry = ToolRegistry()
        registry.register(FILES_READ, lambda **_: None)

        assert registry.to_schema({"files.read"}) == registry.to_schema({"files.read"}, hinweise={})
