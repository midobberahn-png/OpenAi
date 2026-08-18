"""Werkzeugkatalog.

Die Registry entscheidet nichts, aber ihre Ausgaben fließen in
Sicherheitsentscheidungen ein: ``safe_when_tainted`` verengt Werkzeugsets,
``required_scopes`` prüft die Vollständigkeit des Katalogs, ``to_schema``
bestimmt, was ein Modell überhaupt sieht.
"""

from __future__ import annotations

import pytest

from jarvis_contracts import DataClass, PayloadInspectability, RiskLevel, ToolSpec
from jarvis_core.tools import DuplicateTool, ToolRegistry, UnknownTool


def _spec(name: str, **kw: object) -> ToolSpec:
    base: dict[str, object] = {
        "name": name,
        "description": f"Werkzeug {name} mit ausreichend langer Beschreibung.",
        "parameters": {"type": "object", "properties": {}},
        "risk": RiskLevel.LOW,
    }
    base.update(kw)
    return ToolSpec(**base)  # type: ignore[arg-type]


class TestRegistrierung:
    def test_leere_registry(self) -> None:
        reg = ToolRegistry()
        assert len(reg) == 0
        assert reg.get("x") is None
        assert "x" not in reg

    def test_registrieren_und_finden(self) -> None:
        reg = ToolRegistry()
        reg.register(_spec("system.time"))
        assert len(reg) == 1
        assert "system.time" in reg
        assert reg.require("system.time").name == "system.time"

    @pytest.mark.invariant("tool-no-silent-override")
    @pytest.mark.security
    def test_doppelte_registrierung_wird_abgelehnt(self) -> None:
        """Ein überschriebenes Werkzeug wäre ein stiller Wechsel der
        Berechtigungen hinter demselben Namen."""
        reg = ToolRegistry()
        reg.register(_spec("mail.send", risk=RiskLevel.LOW))
        with pytest.raises(DuplicateTool, match="bereits registriert"):
            reg.register(
                _spec(
                    "mail.send",
                    risk=RiskLevel.HIGH,
                    scopes=["mail.send"],
                    requires_preview=True,
                )
            )

    def test_unbekanntes_werkzeug_wirft_eigene_ausnahme(self) -> None:
        reg = ToolRegistry()
        with pytest.raises(UnknownTool):
            reg.require("gibt.es.nicht")
        with pytest.raises(UnknownTool):
            reg.handler("gibt.es.nicht")

    def test_werkzeug_ohne_implementierung(self) -> None:
        """Spezifikation und Implementierung sind getrennt: Wer Berechtigungen
        prüfen will, braucht den Handler nicht."""
        reg = ToolRegistry()
        reg.register(_spec("system.time"))
        assert reg.get("system.time") is not None
        with pytest.raises(UnknownTool, match="keine Implementierung"):
            reg.handler("system.time")

    async def test_handler_wird_zurueckgegeben(self) -> None:
        from jarvis_contracts import ToolResult

        async def handler() -> ToolResult:
            return ToolResult(ok=True, display="fertig")

        reg = ToolRegistry()
        reg.register(_spec("system.time"), handler)
        result = await reg.handler("system.time")()
        assert result.ok


class TestAbfragen:
    def _filled(self) -> ToolRegistry:
        reg = ToolRegistry()
        reg.register(_spec("system.time", forbidden_when_tainted=False))
        reg.register(
            _spec(
                "mail.read",
                scopes=["mail.read"],
                data_class=DataClass.P2,
                forbidden_when_tainted=False,
            )
        )
        reg.register(
            _spec(
                "calendar.create",
                risk=RiskLevel.MEDIUM,
                scopes=["calendar.create"],
                requires_preview=True,
                payload_inspectability=PayloadInspectability.STRUCTURED,
            )
        )
        reg.register(
            _spec(
                "mail.send",
                risk=RiskLevel.HIGH,
                scopes=["mail.send", "mail.draft"],
                requires_preview=True,
            )
        )
        return reg

    def test_namen_und_sortierte_spezifikationen(self) -> None:
        reg = self._filled()
        assert reg.names() == {"system.time", "mail.read", "calendar.create", "mail.send"}
        assert [s.name for s in reg.all_specs()] == [
            "calendar.create",
            "mail.read",
            "mail.send",
            "system.time",
        ]

    def test_benoetigte_scopes(self) -> None:
        """Grundlage der Prüfung, dass der Scope-Katalog vollständig ist."""
        assert self._filled().required_scopes() == {
            "mail.read",
            "calendar.create",
            "mail.send",
            "mail.draft",
        }

    @pytest.mark.security
    def test_unbedenkliche_werkzeuge_bei_kontamination(self) -> None:
        safe = self._filled().safe_when_tainted()
        assert safe == {"system.time", "mail.read"}
        assert "mail.send" not in safe
        assert "calendar.create" not in safe, (
            "Sanierbar heißt nicht unbedenklich — die Entscheidung fällt erst in der "
            "Policy Engine, weil sie von den Argumenten abhängt."
        )

    def test_filter_nach_risiko(self) -> None:
        names = [s.name for s in self._filled().by_risk(RiskLevel.MEDIUM)]
        assert names == ["calendar.create", "mail.send"]

    def test_schema_enthaelt_nur_die_uebergebenen_namen(self) -> None:
        """Die Verengung durch Berechtigungen und Taint hat der Aufrufer
        vorgenommen — die Registry entscheidet das nicht selbst."""
        schema = self._filled().to_schema({"system.time", "mail.read"})
        assert [entry["name"] for entry in schema] == ["mail.read", "system.time"]
        assert all({"name", "description", "input_schema"} == set(e) for e in schema)

    def test_schema_ohne_auswahl_liefert_alles(self) -> None:
        assert len(self._filled().to_schema()) == 4

    def test_unbekannte_namen_im_schema_werden_uebergangen(self) -> None:
        schema = self._filled().to_schema({"system.time", "gibt.es.nicht"})
        assert [e["name"] for e in schema] == ["system.time"]
