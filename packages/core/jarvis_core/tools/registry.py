"""Werkzeugkatalog.

Siehe docs/06-agenten-tools.md §4.

Die Registry hält Spezifikationen und Ausführungsfunktionen getrennt: Wer die
Berechtigungen eines Werkzeugs prüfen will, braucht dessen Implementierung
nicht. Das erlaubt es, den Katalog zu inspizieren und zu dokumentieren, ohne
Code auszuführen.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from datetime import UTC, datetime
from secrets import compare_digest
from typing import TYPE_CHECKING, Any
from uuid import UUID

from jarvis_contracts import RiskLevel, ToolResult, ToolSpec
from jarvis_core.ports.grants import GrantConsumer, UndoConsumer

if TYPE_CHECKING:  # nur für die Typprüfung — zur Laufzeit ein lokaler Import
    from jarvis_core.policy.approval import ExecutionGrant
    from jarvis_core.policy.undo import UndoGrant

__all__ = [
    "DuplicateTool",
    "ForgedAuthorization",
    "GrantAlreadyUsed",
    "ToolHandler",
    "ToolRegistry",
    "UndoHandler",
    "UndoMismatch",
    "UnguardedExecution",
    "UnknownTool",
]

ToolHandler = Callable[..., Awaitable[ToolResult]]

UndoHandler = Callable[[str], Awaitable[ToolResult]]
"""Nimmt **einen** Aufruf zurück, adressiert durch dessen Rücknahmepunkt.

Genau ein Parameter, und keine ``**kwargs`` wie beim Ausführungs-Handler: Was
zurückgenommen wird, steht nicht in Argumenten, die jemand mitbringen könnte,
sondern in dem, was das Werkzeug bei der Ausführung selbst notiert hat."""


class DuplicateTool(Exception):
    """Zwei Werkzeuge mit demselben Namen.

    Programmierfehler, nicht Laufzeitzustand: Ein überschriebenes Werkzeug wäre
    ein stiller Wechsel der Berechtigungen hinter demselben Namen.
    """


class UnknownTool(Exception):
    """Ein Werkzeug wurde angefordert, das nicht registriert ist.

    Tritt insbesondere bei halluzinierten Werkzeugnamen auf und muss deshalb
    klar von einem Berechtigungsfehler unterscheidbar bleiben.
    """


class ForgedAuthorization(Exception):
    """Eine Autorisierung passt nicht zu dem Aufruf, für den sie vorgelegt wird.

    Eigene Klasse und ausdrücklich nicht ``UnknownTool``: Ein unbekannter
    Werkzeugname ist ein Modellfehler und alltäglich, eine nicht passende
    Autorisierung ist ein Sicherheitsvorfall und gehört als solcher ins
    Audit-Log. Beide unter derselben Ausnahme zu führen hieße, das eine im
    Rauschen des anderen zu verlieren.
    """


class GrantAlreadyUsed(Exception):
    """Ein Grant ließ sich nicht einlösen.

    Eigene Klasse und nicht ``ForgedAuthorization``: Der Grant ist echt, die
    Prüfungen gehen durch, und trotzdem darf er nicht wirken. Ein Retry auf
    der falschen Ebene sieht genau so aus — und ist etwas anderes als der
    Versuch, eine Erlaubnis zu fälschen. Im Audit-Log sollen sich die beiden
    unterscheiden lassen.

    Der Regelfall ist die zweite Vorlage. Bei der persistenten Implementierung
    kommt ein zweiter Fall hinzu: eine Invokation, die nie protokolliert wurde.
    Beide enden hier, weil beide dasselbe bedeuten — es gibt keinen Anspruch,
    der eingelöst werden könnte. Die Meldung nennt deshalb beide Ursachen.
    """


class UndoMismatch(Exception):
    """``supports_undo`` und der registrierte Undo-Handler widersprechen sich.

    Konfigurationsfehler, und einer, der beim Start auffallen muss statt beim
    ersten Versuch: Der Wert steht in der Vorschau, die ein Mensch **vor** der
    Bestätigung liest.
    """


class UnguardedExecution(Exception):
    """Ausführung ohne eingerichteten Grant-Verbrauch.

    Konfigurationsfehler, kein Angriff — aber einer, der die Zusicherung
    ``grant-single-use`` still aufheben würde. Deshalb bricht die Ausführung
    ab, statt ungesichert durchzulaufen.
    """


class ToolRegistry:
    """Katalog aller verfügbaren Werkzeuge."""

    def __init__(
        self,
        *,
        grants: GrantConsumer | None = None,
        undo_grants: UndoConsumer | None = None,
    ) -> None:
        self._specs: dict[str, ToolSpec] = {}
        self._handlers: dict[str, ToolHandler] = {}
        self._undo: dict[str, UndoHandler] = {}
        self._undo_grants = undo_grants
        """Der Verbrauch der Rücknahme-Erlaubnis — neben dem Grant-Verbrauch
        und nicht statt seiner. Dieselbe Zeile, zwei verschiedene Wirkungen:
        Der eine wird verbraucht, bevor ein Werkzeug wirkt, der andere, bevor
        eine Rücknahme wirkt. ``None`` weist die Rücknahme ab — ein fehlender
        Sicherheitskontext muss schließen."""

        self._grants = grants
        """Der Grant-Verbrauch. ``None`` ist zulässig, solange nur der Katalog
        gelesen wird — für ``execute()`` nicht. Die Registry wird an vielen
        Stellen bloß zum Nachschlagen gebaut (Schema-Erzeugung, Policy-Prüfung
        ohne Ausführung); ein Pflichtparameter zwänge dort eine Abhängigkeit
        auf, die nichts absichert. Fehlt er beim Ausführen, wird abgewiesen —
        ein fehlender Sicherheitskontext muss schließen, nicht öffnen."""

    def register(
        self,
        spec: ToolSpec,
        handler: ToolHandler | None = None,
        *,
        undo: UndoHandler | None = None,
    ) -> None:
        """Nimmt ein Werkzeug auf — mit Ausführung und, wo es sie gibt, Rücknahme.

        ``undo`` muss zu ``ToolSpec.supports_undo`` passen. Die Prüfung steht
        hier und nicht als guter Vorsatz irgendwo: Ein Werkzeug, das
        Umkehrbarkeit *verspricht* und keine hat, senkt die Aufmerksamkeit vor
        der Bestätigung — genau dort, wo sie gebraucht wird. Und ein Werkzeug
        mit Rücknahme, das sie nicht anbietet, verschweigt sie.

        **Sie gilt nur, wenn auch ein Ausführungs-Handler dabei ist.** Ein
        Katalog ohne Implementierung ist ein zulässiger und häufiger Fall —
        Schema-Erzeugung, Policy-Prüfung ohne Ausführung —, und wo nichts
        ausgeführt wird, ist auch nichts zurückzunehmen. Die erste Fassung
        prüfte ohne diese Bedingung und brachte fünf Suiten zum Anschlagen, die
        den Katalog nur lesen; die Zeile hier ist die Lehre daraus.
        """
        if spec.name in self._specs:
            raise DuplicateTool(
                f"Werkzeug {spec.name!r} ist bereits registriert. Ein Überschreiben "
                "würde die Berechtigungen hinter demselben Namen still austauschen."
            )
        if spec.supports_undo and handler is not None and undo is None:
            raise UndoMismatch(
                f"{spec.name!r} führt supports_undo=True und hat keinen Undo-Handler. "
                "Der Wert speist ActionPreview.reversible — den Satz „das kannst du "
                "rückgängig machen“, den ein Mensch vor seiner Bestätigung liest."
            )
        if undo is not None and not spec.supports_undo:
            raise UndoMismatch(
                f"{spec.name!r} bringt einen Undo-Handler mit und führt "
                "supports_undo=False. Eine Rücknahme, die niemandem angeboten wird, "
                "ist keine."
            )
        self._specs[spec.name] = spec
        if handler is not None:
            self._handlers[spec.name] = handler
        if undo is not None:
            self._undo[spec.name] = undo

    def get(self, name: str) -> ToolSpec | None:
        return self._specs.get(name)

    def require(self, name: str) -> ToolSpec:
        spec = self._specs.get(name)
        if spec is None:
            raise UnknownTool(f"Unbekanntes Werkzeug: {name!r}")
        return spec

    async def execute(
        self,
        auth: ExecutionGrant,
        *,
        run_id: UUID,
        user_id: UUID,
        now: datetime | None = None,
    ) -> ToolResult:
        """Führt ein Werkzeug aus — der einzige Weg dorthin.

        Es gibt bewusst keine Methode, die den Handler herausgibt. Wer ein
        Werkzeug ausführen will, braucht einen ``ExecutionGrant``, und der
        entsteht ausschließlich im ``ApprovalGateway`` nach Hash-Vergleich und
        erneuter Policy-Prüfung.

        **Fünf Prüfungen, und zwei davon haben hier einmal gefehlt:**

        1. **Herkunft.** ``type(auth) is ExecutionGrant`` — nominal, nicht
           strukturell. Frühere Fassungen nahmen ein ``Protocol`` entgegen und
           prüften nur die Attribute. Das war ein Gate-Bypass: Ein
           ``SimpleNamespace`` mit passendem Werkzeugnamen, korrekt berechnetem
           Hash und beliebigen IDs erfüllte das Protokoll und führte
           ``mail.send`` aus — ohne Policy Engine, ohne Approval Gateway, ohne
           Grant. Strukturelle Typisierung fragt „sieht es so aus?"; hier muss
           die Frage lauten „kommt es von dort?".

           ``type(...) is`` und nicht ``isinstance``: Eine Unterklasse könnte
           ``__init__`` überschreiben und damit den Sentinel im Konstruktor
           umgehen.

        2. **Hash.** Autorisierung und Ausführung sind getrennte Aufrufe;
           zwischen ihnen könnte ein Aufrufer andere Argumente einsetzen.
        3. **Lauf.** ``run_id`` und ``user_id`` müssen zu dem Kontext passen, in
           dem tatsächlich ausgeführt wird. Ohne diese Prüfung wäre ein gültiger
           Grant aus Lauf A in Lauf B verwendbar — Werkzeugname und Argumente
           passen dort ja weiterhin.
        4. **Implementierung.** Ein registrierter Spec ohne Handler ist ein
           Konfigurationsfehler und kein Berechtigungsproblem.

        5. **Verbrauch.** Die vier Prüfungen oben sind allesamt Aussagen über
           den Grant, und sie gelten beim zweiten Mal unverändert: Der Typ
           bleibt derselbe, der Hash passt weiterhin, Lauf und Nutzer auch. Ein
           externer Prüfer hat daraus zwei Ausführungen aus einer Bestätigung
           gemacht, zehn nebenläufige aus derselben. Der Verbrauch ist die
           einzige der fünf Prüfungen, die den *Zustand* verändert — deshalb
           steht sie zuletzt, unmittelbar vor dem Handler.

           Dass sie zuletzt steht, ist bedeutungstragend: Stünde sie vor den
           anderen, würde ein Grant mit falschem Hash den Anspruch verbrennen,
           und ein Angreifer könnte fremde Erlaubnisse entwerten, ohne sie
           einzulösen. Dieselbe Überlegung wie beim Nonce-Verbrauch und beim
           Ausführungsanspruch.

        Der Aufrufer nennt ``run_id`` und ``user_id`` ausdrücklich, statt dass
        die Registry sie dem Grant entnimmt: Ein Vergleich eines Wertes mit sich
        selbst prüft nichts.

        ``now`` geht nur in den Vermerk des Verbrauchs ein, nicht in eine
        Entscheidung — anders als bei den Fristen des Approval Gateways, wo der
        Zeitpunkt ausdrücklich hereingereicht wird.
        """
        # Lokal, um den Zyklus zu vermeiden: Die Policy-Schicht braucht die
        # Registry zur Werkzeugauflösung.
        from jarvis_core.policy.approval import ExecutionGrant as _Grant

        if type(auth) is not _Grant:
            raise ForgedAuthorization(
                "Die vorgelegte Autorisierung ist kein ExecutionGrant. Ein Objekt, das "
                "nur so aussieht, ist keines — Erlaubnis entsteht ausschließlich im "
                "ApprovalGateway."
            )

        spec = self.require(auth.tool_name)
        handler = self._handlers.get(auth.tool_name)
        if handler is None:
            raise UnknownTool(f"Für {auth.tool_name!r} ist keine Implementierung registriert.")

        from jarvis_core.policy.approval import payload_hash

        actual = payload_hash(spec.name, auth.arguments)
        if not compare_digest(actual, auth.verified_hash):
            raise ForgedAuthorization(
                f"Argumente von {spec.name!r} weichen von der Autorisierung ab — "
                "Ausführung abgebrochen."
            )
        if auth.run_id != run_id or auth.user_id != user_id:
            raise ForgedAuthorization(
                f"Die Autorisierung für {spec.name!r} gehört zu einem anderen Lauf oder "
                "Nutzer. Eine Erlaubnis gilt für genau einen Aufruf in genau einem Lauf."
            )

        if self._grants is None:
            raise UnguardedExecution(
                f"Für {spec.name!r} ist kein Grant-Verbrauch eingerichtet. Ohne ihn wäre "
                "dieselbe Erlaubnis beliebig oft einlösbar; die Ausführung wird "
                "abgebrochen."
            )
        if not await self._grants.consume(auth.invocation_id, now=now or datetime.now(tz=UTC)):
            raise GrantAlreadyUsed(
                f"Die Erlaubnis für {spec.name!r} ließ sich nicht einlösen: Sie wurde "
                "bereits verwendet, oder es gibt keinen protokollierten Aufruf, zu dem "
                "sie gehört. Eine Bestätigung führt höchstens einmal aus."
            )

        return await handler(**auth.arguments)

    async def undo(self, auth: UndoGrant, *, user_id: UUID) -> ToolResult:
        """Nimmt einen Aufruf zurück — der einzige Weg dorthin.

        Dieselbe Bauart wie ``execute()``, und aus demselben Grund: Es gibt
        keine Methode, die einen Undo-Handler herausgibt. Wer zurücknehmen
        will, braucht einen ``UndoGrant``, und der entsteht ausschließlich im
        ``UndoGateway`` — nach Zugehörigkeit, Frist und Anspruch.

        **Drei Prüfungen statt fünf, und die Lücke ist keine.** Es gibt keinen
        Payload-Hash zu vergleichen: Eine Rücknahme hat keine Argumente, die
        ein Mensch bestätigt hätte, sondern genau einen Rücknahmepunkt, den das
        Werkzeug selbst notiert hat. Und der Verbrauch steht nicht hier,
        sondern im Gate: Er *ist* der Anspruch — die Zeile wechselt auf
        ``undone``, bevor dieser Aufruf überhaupt beginnt.

        **Vier Prüfungen, und die vierte hat gefehlt.** Die erste Fassung
        verließ sich darauf, dass der Anspruch am Gate genügt — er sichert
        aber nur den Übergang *Aufruf → Erlaubnis*. Wer die ausgestellte
        Erlaubnis behält, legt sie erneut vor: Typ, Nutzer und Werkzeugname
        gelten unverändert, und der Handler lief ein zweites Mal. Gemeldet von
        einer externen Prüfung zu ``61d4428``, nachgemessen in
        ``tests/unit/test_undo_replay.py`` — vier von fünf Tests schlugen fehl.

        Dasselbe Muster wie beim Ausführungs-Grant, dieselbe Reparatur: ein
        Verbrauch an der ``invocation_id``, als **letzter** Schritt vor dem
        Handler.

        Was hier weiterhin **nicht** steht, ist ein Hash-Vergleich: Eine
        Rücknahme hat keine Argumente, die ein Mensch bestätigt hätte, sondern
        genau einen Rücknahmepunkt, den das Werkzeug selbst notiert hat.
        """
        from jarvis_core.policy.undo import UndoGrant as _UndoGrant

        if type(auth) is not _UndoGrant:
            raise ForgedAuthorization(
                "Die vorgelegte Autorisierung ist kein UndoGrant. Ein Objekt, das nur so "
                "aussieht, ist keines — eine Rücknahme entsteht ausschließlich im "
                "UndoGateway."
            )
        if auth.user_id != user_id:
            raise ForgedAuthorization(
                "Die Rücknahme gehört zu einem anderen Nutzer. Ein Vergleich eines "
                "Wertes mit sich selbst prüft nichts — deshalb nennt der Aufrufer den "
                "Nutzer ausdrücklich."
            )

        handler = self._undo.get(auth.tool_name)
        if handler is None:
            raise UnknownTool(
                f"Für {auth.tool_name!r} ist keine Rücknahme registriert. Der Aufruf ist "
                "protokolliert als zurücknehmbar, dieser Prozess kann es nicht — ein "
                "Konfigurationsfehler und kein Berechtigungsproblem."
            )

        if self._undo_grants is None:
            raise UnguardedExecution(
                f"Für die Rücknahme von {auth.tool_name!r} ist kein Verbrauch "
                "eingerichtet. Ohne ihn wäre dieselbe Erlaubnis beliebig oft einlösbar; "
                "die Rücknahme wird abgebrochen."
            )
        if not await self._undo_grants.consume_undo(auth.invocation_id, now=datetime.now(tz=UTC)):
            raise GrantAlreadyUsed(
                f"Die Rücknahme von {auth.tool_name!r} ließ sich nicht einlösen: Sie "
                "wurde bereits eingelöst, oder es gibt keinen beanspruchten Vorgang, zu "
                "dem sie gehört. Eine Erlaubnis nimmt höchstens einmal zurück."
            )

        return await handler(auth.undo_token)

    def names(self) -> set[str]:
        return set(self._specs)

    def all_specs(self) -> list[ToolSpec]:
        return [self._specs[n] for n in sorted(self._specs)]

    def required_scopes(self) -> set[str]:
        """Alle Scopes, die irgendein Werkzeug benötigt.

        Grundlage der Prüfung, dass der Scope-Katalog vollständig ist — ein
        Werkzeug mit unbekanntem Scope wäre zur Laufzeit nicht freigebbar.
        """
        return {scope for spec in self._specs.values() for scope in spec.scopes}

    def safe_when_tainted(self) -> set[str]:
        """Werkzeuge, die in einem kontaminierten Lauf noch zulässig sind.

        Wird der Agent Runtime übergeben, um das Werkzeugset zu verengen
        (docs/06-agenten-tools.md §5).
        """
        return {name for name, spec in self._specs.items() if not spec.is_blocked_by_taint()}

    def by_risk(self, minimum: RiskLevel) -> list[ToolSpec]:
        return [s for s in self.all_specs() if s.risk >= minimum]

    def to_schema(self, names: set[str] | None = None) -> list[dict[str, Any]]:
        """Werkzeugdefinitionen für ein Sprachmodell.

        Nur die übergebenen Namen — der Aufrufer hat die Verengung durch
        Berechtigungen und Taint bereits vorgenommen. Die Registry entscheidet
        das nicht selbst.
        """
        selected = (
            self.all_specs()
            if names is None
            else [self._specs[n] for n in sorted(names) if n in self._specs]
        )
        return [
            {
                "name": spec.name,
                "description": spec.description,
                "input_schema": spec.parameters,
            }
            for spec in selected
        ]

    def __len__(self) -> int:
        return len(self._specs)

    def __contains__(self, name: object) -> bool:
        return isinstance(name, str) and name in self._specs
