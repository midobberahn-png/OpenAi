"""Werkzeugkatalog.

Die Registry entscheidet nichts, aber ihre Ausgaben fließen in
Sicherheitsentscheidungen ein: ``safe_when_tainted`` verengt Werkzeugsets,
``required_scopes`` prüft die Vollständigkeit des Katalogs, ``to_schema``
bestimmt, was ein Modell überhaupt sieht.
"""

from __future__ import annotations

from typing import ClassVar
from uuid import UUID, uuid4

import pytest

from jarvis_contracts import DataClass, PayloadInspectability, RiskLevel, ToolSpec
from jarvis_core.tools import (
    DuplicateTool,
    ForgedAuthorization,
    ToolRegistry,
    UnknownTool,
)

RUN = UUID("33333333-3333-3333-3333-333333333333")
USER = UUID("11111111-1111-1111-1111-111111111111")


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

    @pytest.mark.security
    @pytest.mark.invariant("policy-single-entry-point")
    def test_registry_gibt_keinen_handler_heraus(self) -> None:
        """Es gibt bewusst keine Methode, die den Handler zurückgibt.

        Wer ein Werkzeug ausführen will, braucht eine ExecutionAuthorization.
        Eine Methode wie ``handler(name)`` wäre der zweite Ausführungspfad —
        also der Pfad, den niemand prüft.
        """
        assert not hasattr(ToolRegistry, "handler")
        assert hasattr(ToolRegistry, "execute")

    @pytest.mark.security
    @pytest.mark.invariant("policy-single-entry-point")
    async def test_ausfuehrung_verlangt_passenden_hash(self) -> None:
        """Ein Grant mit fremdem Hash darf nicht ausführen — die Registry prüft
        eigenständig nach, weil Autorisierung und Ausführung getrennte Aufrufe
        sind."""
        from jarvis_contracts import ToolResult

        called: list[dict[str, object]] = []

        async def handler(**kwargs: object) -> ToolResult:
            called.append(kwargs)
            return ToolResult(ok=True, display="fertig")

        reg = ToolRegistry()
        reg.register(_spec("system.time"), handler)

        class FakeAuth:
            tool_name = "system.time"
            arguments: ClassVar[dict[str, object]] = {}
            verified_hash = "0" * 64
            run_id = RUN
            user_id = USER

        with pytest.raises(ForgedAuthorization, match="weichen von der Autorisierung ab"):
            await reg.execute(FakeAuth(), run_id=RUN, user_id=USER)  # type: ignore[arg-type]
        assert not called, "Der Handler darf bei falschem Hash nicht laufen"

    @pytest.mark.security
    @pytest.mark.invariant("grant-bound-to-run")
    async def test_grant_aus_einem_anderen_lauf_wird_abgewiesen(self) -> None:
        """Grant Confusion: Der Grant ist gültig, Hash und Werkzeugname stimmen —
        er gehört nur zu einem anderen Lauf.

        Ohne diese Prüfung wäre die Laufbindung reine Konvention: Ein Grant, der
        versehentlich oder absichtlich über eine Laufgrenze getragen wird, führte
        aus, weil an ihm selbst nichts falsch ist.
        """
        from jarvis_contracts import ToolResult
        from jarvis_core.policy.approval import payload_hash

        called: list[dict[str, object]] = []

        async def handler(**kwargs: object) -> ToolResult:
            called.append(kwargs)
            return ToolResult(ok=True, display="fertig")

        reg = ToolRegistry()
        reg.register(_spec("system.time"), handler)

        class Auth:
            tool_name = "system.time"
            arguments: ClassVar[dict[str, object]] = {}
            verified_hash = payload_hash("system.time", {})
            run_id = RUN
            user_id = USER

        with pytest.raises(ForgedAuthorization, match="anderen Lauf"):
            await reg.execute(Auth(), run_id=uuid4(), user_id=USER)  # type: ignore[arg-type]
        with pytest.raises(ForgedAuthorization, match="anderen Lauf"):
            await reg.execute(Auth(), run_id=RUN, user_id=uuid4())  # type: ignore[arg-type]
        assert not called, "Ein fremder Grant darf den Handler nicht erreichen"

    async def test_ausfuehrung_mit_gueltigem_grant(self) -> None:
        from jarvis_contracts import ToolResult
        from jarvis_core.policy.approval import payload_hash

        async def handler(**kwargs: object) -> ToolResult:
            return ToolResult(ok=True, display="fertig")

        reg = ToolRegistry()
        reg.register(_spec("system.time"), handler)

        class Auth:
            tool_name = "system.time"
            arguments: ClassVar[dict[str, object]] = {}
            verified_hash = payload_hash("system.time", {})
            run_id = RUN
            user_id = USER

        result = await reg.execute(Auth(), run_id=RUN, user_id=USER)  # type: ignore[arg-type]
        assert result.ok

    async def test_werkzeug_ohne_implementierung(self) -> None:
        """Spezifikation und Implementierung sind getrennt: Wer Berechtigungen
        prüfen will, braucht den Handler nicht."""
        from jarvis_core.policy.approval import payload_hash

        reg = ToolRegistry()
        reg.register(_spec("system.time"))
        assert reg.get("system.time") is not None

        class Auth:
            tool_name = "system.time"
            arguments: ClassVar[dict[str, object]] = {}
            verified_hash = payload_hash("system.time", {})
            run_id = RUN
            user_id = USER

        with pytest.raises(UnknownTool, match="keine Implementierung"):
            await reg.execute(Auth(), run_id=RUN, user_id=USER)  # type: ignore[arg-type]


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
