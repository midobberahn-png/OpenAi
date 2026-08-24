"""Laufpersistenz auf PostgreSQL.

Erfüllt ``RunStore``. Drei Entscheidungen, und alle drei sind anderswo im
Projekt schon einmal gefallen:

**Eigene Transaktion je Schreibvorgang.** Dieselbe Bauart wie beim
Werkzeugprotokoll und beim Grant-Verbrauch, und hier die Wurzel der Kette: Das
Protokoll braucht eine committete Zeile in ``runs`` als Fremdschlüssel, und der
Anspruch braucht das Protokoll. Ein Lauf, der nur in der Transaktion des
Requests existiert, bricht die Kette an ihrem ersten Glied — mit einer
``IntegrityError`` beim Protokollieren, laut und nicht still.

**Der Statusvergleich steht in der ``WHERE``-Klausel.** ``load()`` … entscheiden
… ``save()`` ist bei zwei Schreibern ein Überschreiben. Ein
``if run.status == erwartet:`` davor prüfte einen Wert, der zum Zeitpunkt des
Schreibens schon veraltet sein kann. Dieselbe Überlegung wie bei Nonce,
Ausführungsanspruch und Grant-Verbrauch — der vierte Fall desselben Musters,
diesmal von vornherein an der richtigen Stelle.

**Der Status wird nicht gefolgert, sondern verlangt.** ``save()`` bekommt den
erwarteten Status vom Aufrufer. Aus ``run.status`` ließe er sich nicht
gewinnen: Der übergebene Lauf trägt bereits den neuen.

Was hier **nicht** geprüft wird, ist die Zulässigkeit des Übergangs. Die
entscheidet ``fsm.assert_transition()`` im Kern. Diese Schicht beantwortet nur,
ob die Zeile noch dort steht, wo der Aufrufer sie vermutet.
"""

from __future__ import annotations

import json
from datetime import timedelta
from typing import Any
from uuid import UUID, uuid4

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from jarvis_contracts import Run, RunStatus
from jarvis_core.ports.runs import RunNotStored, RunStateConflict

__all__ = ["PostgresRunStore"]


_SPALTEN = (
    "id, user_id, conversation_id, trigger, status, classification, routing, plan, "
    "state, taint_level, data_class, budget, usage, trace_id, error, started_at, "
    "finished_at, sanitized_from_run_id"
)

_INSERT = text(
    f"""
    INSERT INTO runs ({_SPALTEN}) VALUES (
        :id, :user_id, :conversation_id, :trigger, :status,
        CAST(:classification AS jsonb), CAST(:routing AS jsonb), CAST(:plan AS jsonb),
        CAST(:state AS jsonb), :taint_level, :data_class,
        CAST(:budget AS jsonb), CAST(:usage AS jsonb), :trace_id,
        CAST(:error AS jsonb), :started_at, :finished_at, :sanitized_from_run_id
    )
    """
)
"""Ohne ``ON CONFLICT``: Eine zweite Anlage desselben Laufs ist ein Fehler und
keine Wiederholung. Die ID entsteht beim Anlegen; trifft sie auf eine
bestehende Zeile, stimmt eine Annahme des Aufrufers nicht — das soll auffallen.
Der Gegenfall ist ``tool_invocations``, wo ``ON CONFLICT DO NOTHING`` richtig
ist, weil eine wiederaufgenommene Ausführung denselben Schritt erneut
protokolliert."""

_SELECT = text(f"SELECT {_SPALTEN} FROM runs WHERE id = :id")

_LISTE = text(
    f"""
    SELECT {_SPALTEN}
      FROM runs
     WHERE user_id = :user_id
     ORDER BY started_at DESC
     LIMIT :limit
    """
)
"""``user_id`` steht in der Abfrage und nicht in einem Filter darüber: Die
Einschränkung auf den Eigentümer soll nicht weglassbar sein. Der Index
``ix_runs_user_started`` bedient genau diese Reihenfolge."""

_CLAIM = text(
    """
    UPDATE runs
       SET state = state || jsonb_build_object(
               'current_step', CAST(:seq AS integer),
               'claim_id', CAST(:claim_id AS text),
               'claimed_at', to_jsonb(now())
           )
     WHERE id = :id
       AND status = :erwarteter_status
       AND (state ->> 'current_step') IS NULL
    RETURNING id
    """
)
"""Der Anspruch auf einen Planschritt — ein bedingtes UPDATE, mehr braucht es
nicht.

``(state ->> 'current_step') IS NULL`` ist die eigentliche Bedingung: wahr
genau dann, wenn kein Schritt beansprucht ist.

**``->>`` und nicht ``->``, und das ist kein Geschmack.** ``->`` liefert
JSONB; für einen freigegebenen Anspruch ist das ``jsonb 'null'`` und damit
*nicht* SQL-``NULL`` — die Bedingung wäre nach der ersten Freigabe für immer
falsch und der Lauf dauerhaft blockiert. ``->>`` liefert Text und ergibt
SQL-``NULL`` sowohl bei fehlendem Schlüssel als auch bei JSON-``null``. Genau
diese zweite Lesart ist gemeint, weil ``_RELEASE`` JSON-``null`` schreibt.

``claimed_at`` kommt aus ``now()`` und damit aus **der Datenbank**, nicht aus
dem Arbeitsspeicher des Anspruchstellers. Wer später die Frist misst, liest
dieselbe Uhr wie der, der sie gesetzt hat — bei zwei Arbeitern auf zwei
Rechnern ist das nicht selbstverständlich, und eine um Minuten falsch gehende
Uhr gäbe entweder einen laufenden Schritt frei oder ließe einen hängenden
liegen.

``claim_id`` wird mitgeschrieben und ist das Fencing-Token: Es sagt nicht nur,
**dass** der Schritt beansprucht ist, sondern **von wem**. ``||`` statt zweier
``jsonb_set``, weil beide Schlüssel gemeinsam gelten müssen — ein Anspruch ohne
Inhaber ließe sich nicht sicher freigeben (``RunState`` weist das zurück).

Zu prüfen, ob nur *dieser* Schritt frei ist, wäre die schwächere Zusage: Dann
liefen zwei verschiedene Schritte desselben Laufs gleichzeitig, und der zweite
entschiede über einen Taint-Zustand, den der erste gerade ändert."""

_RELEASE = text(
    """
    UPDATE runs
       SET state = state || jsonb_build_object(
               'current_step', NULL, 'claim_id', NULL, 'claimed_at', NULL
           )
     WHERE id = :id
       AND (state ->> 'claim_id') = :claim_id
    RETURNING id
    """
)
"""Gibt den Anspruch zurück, ohne den Schritt als erledigt zu führen.

**Alle drei Anspruchsfelder fallen gemeinsam.** ``claimed_at`` stehen zu
lassen erzeugte eine Frist ohne Anspruch — einen Zustand, den ``RunState``
zurückweist. Der Fehler entstünde beim Schreiben und schlüge beim **Laden** zu,
also genau dann, wenn eine Wiederaufnahme den Lauf braucht. Gemessen: Der Test
über die freigegebene Frist fiel darüber, bevor er über die Frist selbst
etwas aussagen konnte.

``AND (state ->> 'claim_id') = :claim_id`` ist das Fencing. Ohne diese Zeile
gibt jeder Aufräumer jeden Anspruch frei — auch den, der inzwischen einem
anderen gehört. Heute räumt nur der Inhaber auf; mit der Wiederaufnahme
hängender Läufe gibt es zwei Anwärter, und dann trifft die bedingungslose
Freigabe den falschen.

Ohne Statusbedingung und ohne Trefferprüfung: Wessen Anspruch nicht mehr gilt,
hat nichts freizugeben, und das ist kein Fehler — es ist der Ausgang, den das
Fencing herbeiführen soll."""

_RECLAIM = text(
    """
    UPDATE runs
       SET state = state || jsonb_build_object(
               'claim_id', CAST(:claim_id AS text),
               'claimed_at', to_jsonb(now())
           )
     WHERE id = :id
       AND status = :erwarteter_status
       AND (state ->> 'current_step')::integer = :seq
       AND (state ->> 'claim_id') IS NOT NULL
       AND (state ->> 'claimed_at')::timestamptz < now() - CAST(:frist AS interval)
    RETURNING id
    """
)
"""Vergibt einen **abgelaufenen** Anspruch neu — die Gegenrichtung zu ``_CLAIM``.

Der Unterschied zu ``_CLAIM`` ist die erste Bedingung: Dort muss der Schritt
frei sein, hier muss er belegt sein. Beides in einer Anweisung
zusammenzufassen wäre der Fehler, der die Zusage aufhebt — ein ``OR`` über
„frei oder abgelaufen" gäbe jedem Anspruchsteller stillschweigend das Recht
zur Übernahme, und dieses Recht soll eine eigene, benannte Entscheidung
bleiben.

``AND (state ->> 'claimed_at')::timestamptz < now() - :frist`` ist die Frist.
Fehlt ``claimed_at``, ist der Vergleich ``NULL`` und damit nicht wahr: Ein
Anspruch ohne Frist wird **nicht** übernommen. Das ist der sichere Ausgang und
kein Versehen — solche Ansprüche stammen aus der Zeit vor dem Feld, und „keine
Angabe" als „lange her" zu lesen hieße, mitten in einem Rollout den Schritt
eines gerade arbeitenden Prozesses zu übernehmen.

``current_step = :seq`` und nicht bloß „irgendein Anspruch": Übernommen wird
ein *bestimmter* Schritt. Steht der Lauf inzwischen bei einem anderen, hat sich
die Lage geändert, und die Übernahme beruht auf einer veralteten Beurteilung.

**Was diese Anweisung nicht kann.** Sie sperrt den alten Arbeiter vom
*Schreiben* aus — sein Fencing-Token gilt nicht mehr. Sie hält ihn nicht davon
ab, *zu wirken*: Ein Prozess, der gerade im Handler steht, legt den Termin an,
gleichgültig, wem der Anspruch inzwischen gehört. Deshalb ist die Frist eine
Obergrenze für die Dauer eines Schrittes und kein Timeout. Was daraus folgt —
nämlich nachzusehen, was der Schritt schon bewirkt hat —, entscheidet der
Kern (``jarvis_core.orchestrator.recovery``), nicht dieser Speicher."""

_UPDATE = text(
    """
    UPDATE runs
       SET conversation_id = :conversation_id,
           trigger = :trigger,
           status = :status,
           classification = CAST(:classification AS jsonb),
           routing = CAST(:routing AS jsonb),
           plan = CAST(:plan AS jsonb),
           state = CASE
               WHEN CAST(:claim_id AS text) IS NULL
               -- Wer sich auf keinen Anspruch beruft, darf ihn auch nicht
               -- ändern: Die beiden Anspruchsfelder werden aus der Zeile
               -- übernommen statt aus dem Arbeitsspeicher des Schreibers.
               THEN CAST(:state AS jsonb) || jsonb_build_object(
                        'current_step', state -> 'current_step',
                        'claim_id', state -> 'claim_id'
                    )
               ELSE CAST(:state AS jsonb)
           END,
           taint_level = :taint_level,
           data_class = :data_class,
           budget = CAST(:budget AS jsonb),
           usage = CAST(:usage AS jsonb),
           trace_id = :trace_id,
           error = CAST(:error AS jsonb),
           started_at = :started_at,
           finished_at = :finished_at,
           sanitized_from_run_id = :sanitized_from_run_id
     WHERE id = :id
       AND status = :erwarteter_status
       AND (CAST(:claim_id AS text) IS NULL OR (state ->> 'claim_id') = :claim_id)
    RETURNING id
    """
)
"""``AND status = :erwarteter_status`` ist die Grundzusicherung.

Dazu das Fencing: Wer sich auf einen Anspruch beruft, schreibt nur, solange er
**noch seiner** ist. ``:claim_id IS NULL`` lässt den anspruchslosen Pfad
(``POST /runs/{id}/steps``) unverändert durch — er beruft sich auf keinen und
darf deshalb nicht an einem fremden scheitern.

Der ``CAST`` davor ist kein Zierrat: Ohne ihn kann PostgreSQL den Typ eines
Parameters, der nur in ``IS NULL`` vorkommt, nicht herleiten und bricht mit
``AmbiguousParameterError`` ab.

Warum das nötig ist, obwohl der Status schon verglichen wird: Ein abgelaufener
und ein neuer Arbeiter sehen beide ``executing``. Ein Vergleich, der für beide
gilt, unterscheidet sie nicht — und der Langsamere überschriebe das Ergebnis
des Schnelleren.

**Und der ``CASE`` um ``state`` herum ist die zweite Hälfte davon.** Die
``WHERE``-Bedingung schützt nur den, der sich auf einen Anspruch *beruft*; wer
ihn gar nicht erwähnt, ging daran vorbei — und schrieb ihn mit dem ganzen
``state``-Dokument weg. Gemessen: Nach einem anspruchslosen ``save()`` war der
Schritt wieder frei, obwohl sein Inhaber noch arbeitete. Damit stand derselbe
doppelte Seiteneffekt wieder offen, nur über eine andere Tür.

Ein Anspruch, der in einem Dokument liegt, das andere im Ganzen schreiben, ist
kein Anspruch. Sauberer wären eigene Spalten — das bräuchte eine Migration und
steht als Nachtrag im Dossier.

Trefferzahl null heißt: Die Zeile steht woanders — oder es gibt sie nicht.
Beides muss unterschieden werden, deshalb folgt im selben Transaktionsrahmen
eine Abfrage auf die ID. Sie ist billig und läuft nur im Fehlerfall."""

_EXISTIERT = text("SELECT status FROM runs WHERE id = :id")


def _json(wert: Any) -> str | None:
    """Nested Verträge als JSON, ``None`` als SQL-NULL.

    ``mode="json"`` und nicht ``model_dump()``: Sonst landen ``UUID``,
    ``datetime`` und ``Decimal`` als Python-Objekte im Dump, die
    ``json.dumps`` nicht kennt. Ein ``default=str`` würde sie zwar
    hindurchlassen, aber unumkehrbar — beim Lesen käme eine Zeichenkette
    zurück, wo ein Betrag stand.
    """
    if wert is None:
        return None
    if hasattr(wert, "model_dump"):
        return json.dumps(wert.model_dump(mode="json"), ensure_ascii=False)
    return json.dumps(wert, ensure_ascii=False)


def _parameter(run: Run) -> dict[str, Any]:
    return {
        "id": run.id,
        "user_id": run.user_id,
        "conversation_id": run.conversation_id,
        "trigger": str(run.trigger),
        "status": str(run.status),
        "classification": _json(run.classification),
        "routing": _json(run.routing),
        "plan": _json(run.plan),
        "state": _json(run.state),
        "taint_level": str(run.taint_level),
        "data_class": str(run.data_class),
        "budget": _json(run.budget),
        "usage": _json(run.usage),
        "trace_id": run.trace_id,
        "error": _json(run.error),
        "started_at": run.started_at,
        "finished_at": run.finished_at,
        "sanitized_from_run_id": run.sanitized_from_run_id,
    }


class PostgresRunStore:
    """Läufe, dauerhaft und mit geprüftem Fortschreiben."""

    def __init__(self, engine: AsyncEngine) -> None:
        self._engine = engine
        """Eine Engine, keine Verbindung — der Lauf muss committed sein, bevor
        das Werkzeugprotokoll ihn als Fremdschlüssel braucht."""

    async def create(self, run: Run) -> None:
        async with self._engine.begin() as conn:
            await conn.execute(_INSERT, _parameter(run))

    async def load(self, run_id: UUID) -> Run | None:
        async with self._engine.connect() as conn:
            zeile = (await conn.execute(_SELECT, {"id": run_id})).mappings().first()
        if zeile is None:
            return None
        return Run.model_validate(dict(zeile))

    async def list_for_user(self, user_id: UUID, *, limit: int = 50) -> list[Run]:
        async with self._engine.connect() as conn:
            zeilen = (
                (await conn.execute(_LISTE, {"user_id": user_id, "limit": limit})).mappings().all()
            )
        return [Run.model_validate(dict(z)) for z in zeilen]

    async def claim_step(
        self, run_id: UUID, seq: int, *, erwarteter_status: RunStatus
    ) -> UUID | None:
        """Beansprucht einen Planschritt in **eigener** Transaktion.

        ``self._engine.begin()`` und nicht die Verbindung des Requests — der
        Unterschied ist derselbe wie beim Grant-Verbrauch und hat dieselbe
        Ursache: Ein Anspruch, der in der Transaktion des Aufrufers steht, wird
        mit ihr zurückgerollt. Er gälte dann *während* der Ausführung und wäre
        danach wieder frei, obwohl der Termin im Kalender steht.

        Der Rückgabewert unterscheidet nicht zwischen „schon beansprucht" und
        „Lauf steht woanders". Beides heißt für den Aufrufer dasselbe: nicht
        jetzt, nicht von dir.
        """
        kennung = uuid4()
        async with self._engine.begin() as conn:
            treffer = await conn.execute(
                _CLAIM,
                {
                    "id": run_id,
                    "seq": seq,
                    "claim_id": str(kennung),
                    "erwarteter_status": str(erwarteter_status),
                },
            )
            return kennung if treffer.first() is not None else None

    async def reclaim_step(
        self, run_id: UUID, seq: int, *, erwarteter_status: RunStatus, frist: timedelta
    ) -> UUID | None:
        """Übernimmt einen abgelaufenen Anspruch — ebenfalls in eigener Transaktion.

        Aus demselben Grund wie beim Anspruch selbst: Eine Übernahme, die mit
        der Transaktion des Aufrufers zurückgerollt werden kann, gälte nur
        während der Ausführung. Der alte Arbeiter wäre danach wieder im Recht,
        obwohl der neue bereits gewirkt hat.

        ``None`` heißt: nicht übernommen. Die Frist läuft noch, der Lauf steht
        woanders, der Schritt ist ein anderer — oder ein zweiter Übernehmer war
        schneller. Der Aufrufer muss die Fälle nicht unterscheiden; für ihn
        heißen sie alle „nicht du".
        """
        kennung = uuid4()
        async with self._engine.begin() as conn:
            treffer = await conn.execute(
                _RECLAIM,
                {
                    "id": run_id,
                    "seq": seq,
                    "claim_id": str(kennung),
                    "erwarteter_status": str(erwarteter_status),
                    # Als ``timedelta`` und nicht als Zeitpunkt: Gerechnet wird
                    # in der Datenbank (``now() - :frist``), damit Anfang und
                    # Ende der Messung auf **derselben** Uhr stehen. asyncpg
                    # bindet den Parameter typisiert an ``interval`` — eine
                    # Zeichenkette wie ``"900.0 seconds"`` weist es ab.
                    "frist": frist,
                },
            )
            return kennung if treffer.first() is not None else None

    async def release_step(self, run_id: UUID, claim_id: UUID) -> None:
        """Gibt den Anspruch zurück — ebenfalls in eigener Transaktion.

        Sonst hinge die Freigabe an einem Request, der gerade scheitert, und
        würde mit ihm zurückgerollt: Der Anspruch bliebe stehen, obwohl nichts
        geschehen ist.

        Trifft die Kennung nicht, geschieht nichts, und das ist kein Fehler:
        Der Anspruch gehört jemand anderem, und genau das soll die Bedingung
        herbeiführen.
        """
        async with self._engine.begin() as conn:
            await conn.execute(_RELEASE, {"id": run_id, "claim_id": str(claim_id)})

    async def save(
        self, run: Run, *, erwarteter_status: RunStatus, claim_id: UUID | None = None
    ) -> None:
        async with self._engine.begin() as conn:
            parameter = _parameter(run)
            parameter["erwarteter_status"] = str(erwarteter_status)
            parameter["claim_id"] = str(claim_id) if claim_id is not None else None
            if (await conn.execute(_UPDATE, parameter)).first() is not None:
                return

            # Null Treffer — jetzt erst die Ursache klären.
            aktuell = (await conn.execute(_EXISTIERT, {"id": run.id})).scalar_one_or_none()

        if aktuell is None:
            raise RunNotStored(f"Kein Lauf mit der ID {run.id}.")
        raise RunStateConflict(
            f"Lauf {run.id} steht in {aktuell!r}, erwartet war {str(erwarteter_status)!r}. "
            "Ein anderer Schreiber war schneller; neu laden und die Entscheidung "
            "wiederholen."
        )
