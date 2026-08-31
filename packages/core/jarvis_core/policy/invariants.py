"""Sicherheits-Invarianten als Code.

Testabdeckung ist ab hier die falsche Leitkennzahl. 96 % sagen nichts darüber,
ob der Ablauf ``tainted → Bestätigung → veränderter Payload → Ausführung``
abgewehrt wird — fünfzig zusätzliche Tests für Getter heben die Zahl, nicht
die Sicherheit.

Stattdessen: **Security Invariant Coverage**. Jede Invariante ist hier
benannt; Tests binden sich per ``@pytest.mark.invariant("<id>")`` daran. Ein
Meta-Test schlägt fehl, sobald eine Invariante ohne Test dasteht oder ein
Test sich auf eine unbekannte Invariante beruft.

Damit lässt sich die Kennzahl nicht nachträglich passend machen: Eine
Invariante zu streichen ist eine sichtbare Änderung an dieser Datei.
"""

from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, ConfigDict

__all__ = ["INVARIANTS", "Invariant", "InvariantStatus", "invariant_ids"]


class InvariantStatus(StrEnum):
    ENFORCED = "enforced"
    """Durchgesetzt und durch mindestens einen Test belegt."""

    PLANNED = "planned"
    """Beschlossen, aber der Kontrollpunkt existiert noch nicht.

    Ausdrücklich geführt, damit nicht der Eindruck entsteht, etwas sei
    abgesichert, bevor es das ist.
    """


class Invariant(BaseModel):
    model_config = ConfigDict(frozen=True)

    id: str
    title: str
    statement: str
    """Was gilt — als prüfbare Aussage, nicht als Absichtserklärung."""

    why: str
    """Was passiert, wenn die Invariante fällt."""

    status: InvariantStatus
    component: str


INVARIANTS: tuple[Invariant, ...] = (
    # -- Taint ----------------------------------------------------------
    Invariant(
        id="taint-monotonic",
        title="Kontamination ist monoton",
        statement="Ein Lauf, der einmal TAINTED ist, wird durch keinen Vorgang wieder CLEAN.",
        why="Andernfalls genügte ein beliebiges Werkzeug als Waschmaschine für den Zustand.",
        status=InvariantStatus.ENFORCED,
        component="contracts.classification",
    ),
    Invariant(
        id="taint-no-implicit-clearing",
        title="Keine stillschweigende Sanierung",
        statement=(
            "Kontamination wird ausschließlich über das Sanitization-Gate aufgehoben — "
            "und dort nur durch eine Nutzerbestätigung, nie durch Programmfluss."
        ),
        why="Ein impliziter Pfad zurück nach CLEAN wäre die Umgehung des gesamten Schutzes.",
        status=InvariantStatus.ENFORCED,
        component="core.policy.engine",
    ),
    Invariant(
        id="taint-precedes-permission",
        title="Taint wird vor der Berechtigung geprüft",
        statement=("Eine erteilte Berechtigung schaltet in einem kontaminierten Lauf nichts frei."),
        why=(
            "Bei umgekehrter Reihenfolge wäre genau der Fall offen, auf den es ankommt: "
            "Vollberechtigung für mail.send nach dem Lesen einer präparierten Mail."
        ),
        status=InvariantStatus.ENFORCED,
        component="core.policy.engine",
    ),
    Invariant(
        id="taint-cross-run-isolation",
        title="Kontamination überschreitet keine Laufgrenze",
        statement="Ein sanierter Lauf startet sauber und ohne Kontext des Herkunftslaufs.",
        why="Sonst wäre der saubere Lauf nur eine Umbenennung des kontaminierten.",
        status=InvariantStatus.ENFORCED,
        component="contracts.runs",
    ),
    Invariant(
        id="taint-memory-quarantine",
        title="Gedächtnis ist kein zeitversetzter Kanal",
        statement=(
            "Gedächtniskandidaten aus kontaminierten Läufen werden nie automatisch "
            "übernommen — unabhängig von der Konfidenz."
        ),
        why=(
            "Die Taint-Sperre gilt nur für die Dauer eines Laufs. Ein geschriebener "
            "„Fakt“ wirkt Wochen später in einem sauberen Lauf, vorbei an jeder Sperre."
        ),
        status=InvariantStatus.ENFORCED,
        component="contracts.memory",
    ),
    # -- Payload und Außenwirkung ---------------------------------------
    Invariant(
        id="payload-outbound-classification",
        title="Außenwirkung schlägt Struktur",
        statement=(
            "Ein Aufruf mit belegtem Empfänger- oder Teilnehmerfeld gilt als nicht "
            "prüfbar, auch wenn das Werkzeug statisch als strukturiert eingestuft ist."
        ),
        why=(
            "Ein Kalendereintrag mit eingeschmuggeltem Teilnehmer verschickt eine "
            "Einladung — das ist Versand, nicht Notiz."
        ),
        status=InvariantStatus.ENFORCED,
        component="contracts.tools",
    ),
    Invariant(
        id="payload-freeform-never-sanitizable",
        title="Freitext mit Außenwirkung wird nie saniert",
        statement="Payloads mit Freitext-Außenwirkung sind in kontaminierten Läufen gesperrt.",
        why=(
            "Eine um eine Ziffer veränderte IBAN im Fließtext übersieht auch ein "
            "aufmerksamer Leser; die Bestätigung wäre dort keine echte Prüfung."
        ),
        status=InvariantStatus.ENFORCED,
        component="contracts.tools",
    ),
    Invariant(
        id="payload-immutable-after-approval",
        title="Bestätigter Payload ist unveränderlich",
        statement=("Was ausgeführt wird, ist byte-identisch mit dem, was in der Vorschau stand."),
        why="Sonst bestätigt der Nutzer A und das System führt B aus.",
        status=InvariantStatus.ENFORCED,
        component="core.policy.approval",
    ),
    Invariant(
        id="approval-bound-to-payload-hash",
        title="Bestätigung ist an den Payload gebunden",
        statement=(
            "Eine Bestätigung gilt nur für den Payload, dessen Hash bei der Anfrage "
            "festgehalten wurde."
        ),
        why="Andernfalls ließe sich eine Bestätigung auf einen anderen Aufruf übertragen.",
        status=InvariantStatus.ENFORCED,
        component="core.policy.approval",
    ),
    Invariant(
        id="approval-toctou-protected",
        title="Kein Zeitfenster zwischen Prüfung und Ausführung",
        statement=(
            "Unmittelbar vor der Ausführung werden Payload-Hash und Policy erneut "
            "geprüft; zwischenzeitlich entzogene Rechte greifen sofort."
        ),
        why=(
            "Eine Bestätigung von 14:00 darf nicht um 04:00 ausgeführt werden, und ein "
            "entzogenes Recht muss ausstehende Bestätigungen entwerten."
        ),
        status=InvariantStatus.ENFORCED,
        component="core.policy.approval",
    ),
    Invariant(
        id="approval-nonce-single-use",
        title="Bestätigungen sind einmalig",
        statement="Eine Nonce lässt sich genau einmal einlösen, auch unter Nebenläufigkeit.",
        why="Sonst ließe sich eine einmal bestätigte Aktion beliebig oft ausführen.",
        status=InvariantStatus.ENFORCED,
        component="core.policy.approval",
    ),
    Invariant(
        id="execution-claim-single-use",
        title="Eine Bestätigung erwirkt höchstens einen Ausführungsanspruch",
        statement=(
            "Eine bestätigte Aktion erwirkt genau einen Ausführungsanspruch; jede weitere "
            "Autorisierung derselben Bestätigung wird abgewiesen, auch unter "
            "Nebenläufigkeit."
        ),
        why=(
            "Die Nonce sichert den Bestätigungsschritt, nicht die Ausführung. Ohne einen "
            "eigenen Anspruch ließ sich dieselbe Bestätigung beliebig oft einlösen: Drei "
            "Aufrufe von authorize_execution() ergaben drei Grants und drei versendete "
            "Mails — bei erteilter Zustimmung für genau eine. Ein externes Review hat das "
            "gefunden, während approval-nonce-single-use auf ENFORCED stand; die "
            "Einmaligkeit hing am falschen Schritt."
        ),
        status=InvariantStatus.ENFORCED,
        component="core.policy.approval",
    ),
    Invariant(
        id="grant-single-use",
        title="Ein ausgestellter Grant führt höchstens einmal aus",
        statement=(
            "Ein ExecutionGrant erlaubt genau einen Werkzeugaufruf; jede weitere Vorlage "
            "desselben Grants — auch als Kopie, aus einem anderen Prozess, nebenläufig "
            "oder nach einem Absturz vor dem Commit — erreicht den Handler nicht."
        ),
        why=(
            "Der Titel der Vorgänger-Invariante versprach mehr, als der Mechanismus hielt. "
            "claim_execution() sichert den Übergang von der Bestätigung zum Grant; die "
            "Registry prüft danach Herkunft, Hash, Lauf und Nutzer — allesamt Werte, die "
            "bei einer Wiedervorlage desselben Objekts unverändert gelten — und ruft den "
            "Handler. Nachgemessen: ein Grant, zweimal vorgelegt, ergab zwei "
            "Handler-Aufrufe; zehn nebenläufig vorgelegte ergaben zehn. Damit ist dies "
            "der dritte Replay-Pfad desselben Musters — die Einmaligkeit hing wieder "
            "einen Schritt zu früh. Geschlossen durch einen Verbrauch an der "
            "invocation_id, als letzter Schritt vor dem Handler. "
            "Die vierte Prüfrunde hat denselben Satz noch einmal enger gefasst: Der "
            "persistente Verbrauch lag in der offenen Request-Transaktion, in der danach "
            "der Handler nach außen wirkte. Atomar war er, dauerhaft nicht — ein "
            "Rollback nach dem Seiteneffekt gab consumed_at wieder frei und damit den "
            "Grant. Gegen echtes PostgreSQL reproduziert und geschlossen, indem der "
            "Anspruch in einer eigenen Transaktion committet, bevor der Handler beginnt."
        ),
        status=InvariantStatus.ENFORCED,
        component="core.tools.registry",
    ),
    Invariant(
        id="approval-not-forgeable-by-model",
        title="Ein Modell kann keine Bestätigung erzeugen",
        statement=(
            "Bestätigungen entstehen ausschließlich aus einer Nutzerinteraktion; "
            "Modellausgaben und Werkzeugargumente haben keinen Einfluss darauf."
        ),
        why="Andernfalls schriebe das Modell sich seine Freigaben selbst.",
        status=InvariantStatus.ENFORCED,
        component="core.policy.engine",
    ),
    Invariant(
        id="approval-channel-bound",
        title="Bestätigt wird dort, wo angezeigt wurde",
        statement=(
            "Eine Bestätigung ist an Nutzer, Sitzung und Anzeigekanal gebunden und "
            "lässt sich nicht über einen anderen Kanal oder eine andere Sitzung einlösen."
        ),
        why=(
            "Kein kryptografischer Schutz — den trägt die Nonce —, sondern die "
            "Absicherung informierter Zustimmung: Eine Geste aus vier Metern Entfernung, "
            "die einen ungelesenen Dialog freigibt, ist genau die Bestätigungsmüdigkeit "
            "aus Risiko R5. Die Sitzungsbindung begrenzt zusätzlich den Schaden eines "
            "gestohlenen Sitzungstokens."
        ),
        status=InvariantStatus.ENFORCED,
        component="core.policy.approval",
    ),
    Invariant(
        id="identity-derives-from-session",
        title="Identität entsteht an genau einer Stelle",
        statement=(
            "Kein HTTP-Endpunkt übernimmt user_id, session_id oder eine andere "
            "Identitätsangabe aus Body, Query, Header oder Pfad; sie stammt ausschließlich "
            "aus der verifizierten Sitzung."
        ),
        why=(
            "Ein Feld „user_id“ in einem Request-Body ist der kürzeste Angriffsweg des "
            "Systems: Es sieht harmlos aus, ist bequem — und führt über Policy und "
            "Approval geradewegs zu einem ExecutionGrant für ein fremdes Konto. Alles "
            "darunter ist gegen falsche Identitäten wirkungslos, weil es die falsche "
            "Identität nie erfährt."
        ),
        status=InvariantStatus.ENFORCED,
        component="api.http",
    ),
    Invariant(
        id="bootstrap-only-once",
        title="Die Erstinbetriebnahme gelingt genau einmal",
        statement=(
            "Der Bootstrap-Endpunkt legt einen Nutzer nur an, solange die Nutzertabelle "
            "leer ist; die Bedingung liegt im INSERT, nicht in einer Prüfung davor."
        ),
        why=(
            "Ein offener Registrierungsweg wäre bei einem Ein-Personen-System die Tür "
            "neben der Tür. Ein vorgelagertes SELECT wäre bei zwei gleichzeitigen "
            "Anfragen wertlos — und das Zeitfenster dieser Prüfung ist genau der Moment, "
            "in dem das System noch niemandem gehört."
        ),
        status=InvariantStatus.ENFORCED,
        component="api.http",
    ),
    Invariant(
        id="auth-endpoints-rate-limited",
        title="Der Anmeldeweg ist begrenzt — auch über viele Adressen",
        statement=(
            "Jeder ohne Anmeldung erreichbare Endpunkt zählt gegen zwei Grenzen: eine je "
            "Client und eine globale je Route. Registrierung, Anmeldung und "
            "Erstinbetriebnahme haben getrennte Zähler."
        ),
        why=(
            "Eine Grenze allein je Adresse ist wirkungslos: Ohne konfigurierten Proxy ist "
            "X-Forwarded-For ein frei erfundenes Feld, und ein IPv6-Präfix liefert mehr "
            "Adressen als ein Zähler je sieht. Die globale Stufe hält deshalb die Wirkung "
            "auf, unabhängig von der Zahl der Absender — sonst füllt ein Angreifer die "
            "Challenge-Tabelle, ohne je ein Limit zu berühren. Getrennte Zähler "
            "verhindern zugleich, dass er über den einen Weg den anderen sperrt."
        ),
        status=InvariantStatus.ENFORCED,
        component="api.http",
    ),
    Invariant(
        id="rate-limit-counting-is-atomic",
        title="Zählen und Fristsetzen sind unteilbar",
        statement=(
            "Der Zähler wird erhöht und seine Frist gesetzt in einem einzigen, atomaren "
            "Schritt; gleichzeitige Anfragen zählen vollständig."
        ),
        why=(
            "Ein Ablauf aus Erhöhen und anschließendem Fristsetzen hat zwei Löcher: Bricht "
            "der Prozess dazwischen ab, existiert ein Zähler ohne Ablauf und sperrt den "
            "Schlüssel für immer — ein selbst gebauter Denial of Service. Und zwei "
            "gleichzeitige Erstzugriffe verlängern das Fenster. Beides fällt erst unter "
            "Last auf, also genau dann, wenn das Limit gebraucht wird."
        ),
        status=InvariantStatus.ENFORCED,
        component="api.rate_limit",
    ),
    Invariant(
        id="session-token-rotation",
        title="Ein benutzter Sitzungstoken wird ersetzt",
        statement=(
            "Ein Sitzungstoken wird nach spätestens 15 Minuten Nutzung ersetzt; der alte "
            "gilt noch 60 Sekunden weiter und danach nicht mehr. Von zwei gleichzeitigen "
            "Anfragen rotiert genau eine, und keine wird abgemeldet."
        ),
        why=(
            "Ohne Rotation bleibt ein entwendeter Token bis zum Ablauf gültig, auch wenn "
            "der rechtmäßige Nutzer weiterarbeitet — das Zeitfenster für einen Replay ist "
            "die volle Sitzungsdauer. Der Aufschub hatte einen Grund, und er ist jetzt "
            "gelöst: Zwei gleichzeitige Anfragen mit demselben Token dürfen nicht dazu "
            "führen, dass eine davon abgemeldet wird. Die Einmaligkeit entsteht in der "
            "Anweisung, die auch schreibt (Vergleiche-und-setze), und ein "
            "Überlappungsfenster von 60 Sekunden trägt die Anfragen, die zum Zeitpunkt "
            "der Rotation schon unterwegs waren. Wer den ersetzten Token danach vorlegt, "
            "beendet die Sitzung (ADR-020)."
        ),
        status=InvariantStatus.ENFORCED,
        component="core.auth",
    ),
    Invariant(
        id="session-verified-before-approval",
        title="Eine Bestätigung verlangt eine echte Sitzung",
        statement=(
            "Eine Bestätigung wird nur eingelöst, wenn der vorgelegte Sitzungstoken zu "
            "genau dieser Sitzung dieses Nutzers gehört und die Sitzung weder abgelaufen "
            "noch widerrufen ist."
        ),
        why=(
            "Ohne diese Prüfung war die Sitzungsbindung aus approval-channel-bound ein "
            "Vergleich zweier UUIDs, die beide vom Aufrufer stammten. Erst die "
            "Verifikation macht daraus eine Zusicherung — und erst damit beendet ein "
            "Nutzer, der sein Gerät verloren hat, auch die offenen Bestätigungen."
        ),
        status=InvariantStatus.ENFORCED,
        component="core.auth",
    ),
    Invariant(
        id="passkey-challenge-single-use",
        title="Eine Challenge gilt einmal und für einen Zweck",
        statement=(
            "Eine WebAuthn-Challenge wird genau einmal eingelöst, verfällt nach kurzer "
            "Frist und schließt nur die Zeremonie ab, für die sie ausgestellt wurde."
        ),
        why=(
            "Ohne Einmaligkeit ist eine mitgeschnittene Zeremonie beliebig wiederholbar. "
            "Ohne Zweckbindung könnte ein Angreifer eine Registrierung anstoßen, um an "
            "eine gültige Challenge für die Anmeldung zu kommen."
        ),
        status=InvariantStatus.ENFORCED,
        component="core.auth",
    ),
    Invariant(
        id="passkey-clone-detection",
        title="Ein Signaturzähler, der nicht steigt, ist ein Klon",
        statement=(
            "Eine Anmeldung wird abgelehnt, wenn der vorgelegte Signaturzähler nicht über "
            "dem gespeicherten liegt — außer beide sind null."
        ),
        why=(
            "Ein gleichbleibender oder fallender Zähler bedeutet, dass derselbe Schlüssel "
            "an zwei Orten existiert. Die Ausnahme für zwei Nullen ist nötig, weil "
            "synchronisierte Passkeys gar keinen Zähler führen; ohne sie wäre die "
            "verbreitetste Bauart ausgesperrt."
        ),
        status=InvariantStatus.ENFORCED,
        component="core.auth",
    ),
    Invariant(
        id="approval-critical-ui-only",
        title="Irreversibles wird nur in der Oberfläche bestätigt",
        statement="CRITICAL-Aktionen akzeptieren keine Sprach- oder Gestenbestätigung.",
        why="Spracherkennung ist zu fehleranfällig — und aus einem anderen Raum auslösbar.",
        status=InvariantStatus.ENFORCED,
        component="contracts.permissions",
    ),
    # -- Berechtigungen und Agenten -------------------------------------
    Invariant(
        id="policy-single-entry-point",
        title="Die Policy Engine ist der einzige Weg",
        statement=(
            "Kein Werkzeug wird ohne Policy-Entscheidung ausgeführt: Die Registry gibt "
            "keinen Handler heraus und verlangt einen ExecutionGrant — nominal geprüft "
            "(type(auth) is ExecutionGrant), nicht strukturell."
        ),
        why=(
            "Ein zweiter Pfad wäre der Pfad, den niemand prüft. Das „nominal“ ist "
            "teuer erkauft: Eine frühere Fassung nahm ein Protocol entgegen und prüfte "
            "nur Attribute. Ein externes Review baute daraufhin ein SimpleNamespace mit "
            "passendem Hash und führte mail.send aus — ohne Policy, ohne Approval, ohne "
            "Grant. Die Invariante stand zu diesem Zeitpunkt auf ENFORCED und war es "
            "nicht. Strukturelle Typisierung fragt „sieht es so aus?“; Erlaubnis "
            "verlangt „kommt es von dort?“."
        ),
        status=InvariantStatus.ENFORCED,
        component="core.policy.engine",
    ),
    Invariant(
        id="grant-bound-to-run",
        title="Eine Erlaubnis gilt für einen Aufruf in einem Lauf",
        statement=(
            "Die Registry führt einen Grant nur aus, wenn Lauf und Nutzer des Grants dem "
            "Kontext entsprechen, in dem tatsächlich ausgeführt wird."
        ),
        why=(
            "Ohne diese Bindung wäre ein gültiger Grant aus Lauf A in Lauf B verwendbar — "
            "Werkzeugname und Argumente passen dort weiterhin, und der Hash stimmt. Die "
            "Bindung hinge dann allein daran, dass niemand einen Grant über eine "
            "Laufgrenze trägt; das ist eine Hoffnung, keine Zusicherung."
        ),
        status=InvariantStatus.ENFORCED,
        component="core.tools.registry",
    ),
    Invariant(
        id="data-class-monotonic-within-run",
        title="Die Datenklasse eines Laufs steigt nur",
        statement=(
            "Innerhalb eines Laufs wird die Datenklasse nie gesenkt, und die Obergrenze "
            "eines Aufrufs stammt aus der Routing-Entscheidung, nicht vom Aufrufer."
        ),
        why=(
            "Ein Lauf, der P2-Daten gesehen hat, hält sie im Kontext — eine harmlose "
            "Folgeaktion macht ihn nicht wieder öffentlich. Und ein Aufrufer, der seine "
            "eigene Obergrenze bestimmt, hat keine: Ein frei übergebenes "
            "allowed_data_class ließe P3-Werkzeuge in einem Lauf zu, der dafür nie "
            "geroutet wurde."
        ),
        status=InvariantStatus.ENFORCED,
        component="core.orchestrator",
    ),
    Invariant(
        id="policy-not-overridable-by-content",
        title="Inhalte ändern keine Policy",
        statement=(
            "Werkzeugargumente und Fremdinhalte beeinflussen die Entscheidung nicht — "
            "auch nicht bei Feldern wie „user_confirmed“."
        ),
        why="Sonst wäre jede eingehende Mail ein Berechtigungsantrag.",
        status=InvariantStatus.ENFORCED,
        component="core.policy.engine",
    ),
    Invariant(
        id="agent-no-capability-escalation",
        title="Delegation erzeugt keine Rechte",
        statement=(
            "Ein Sub-Agent erhält höchstens die Schnittmenge aus eigener Whitelist und "
            "Nutzerrechten; ein anderer Agent als Anfragender ändert daran nichts."
        ),
        why="Andernfalls wäre die Agentenkette der Umweg um jede Beschränkung.",
        status=InvariantStatus.ENFORCED,
        component="core.policy.engine",
    ),
    Invariant(
        id="tool-risk-not-self-declared",
        title="Werkzeuge stufen sich nicht selbst herab",
        statement="Ein Plugin kann seine Risikoklasse nicht senken; der Kern nimmt das Maximum.",
        why="Sonst hebelte ein einziges bösartiges Manifest die Klassifikation aus.",
        status=InvariantStatus.ENFORCED,
        component="contracts.tools",
    ),
    Invariant(
        id="tool-no-silent-override",
        title="Kein stiller Namenstausch",
        statement="Ein bereits registriertes Werkzeug lässt sich nicht überschreiben.",
        why="Ein Überschreiben tauschte die Berechtigungen hinter demselben Namen aus.",
        status=InvariantStatus.ENFORCED,
        component="core.tools.registry",
    ),
    Invariant(
        id="plan-step-claimed-before-effect",
        title="Ein Planschritt wird beansprucht, bevor er wirkt",
        statement=(
            "Ein fälliger Planschritt wird atomar und festgeschrieben beansprucht, bevor "
            "Modell oder Werkzeug laufen; ein zweiter Anspruch auf denselben Schritt "
            "scheitert vor jeder Wirkung."
        ),
        why=(
            "Ohne den Anspruch laden zwei Requests denselben Lauf, führen beide aus, und "
            "erst danach verliert einer am Compare-and-set. Gemessen: sechs parallele "
            "Aufrufe eines geplanten calendar.create ergaben sechs Termine — fünf "
            "Aufrufer bekamen „neu laden und wiederholen“, nachdem ihr Termin bereits "
            "im Kalender stand."
        ),
        status=InvariantStatus.ENFORCED,
        component="api.db.run_store",
    ),
    Invariant(
        id="plan-step-claim-is-fenced",
        title="Nur der Inhaber gibt seinen Anspruch frei und schreibt sein Ergebnis",
        statement=(
            "Freigabe und Fortschreiben eines beanspruchten Planschrittes gelten nur mit "
            "der Kennung, unter der er beansprucht wurde."
        ),
        why=(
            "``current_step`` sagt, *dass* ein Schritt beansprucht ist, nicht *von wem*. "
            "Sobald eine Wiederaufnahme hängende Läufe neu vergibt, gibt es zwei Anwärter "
            "auf denselben Schritt — und ein abgelaufener Arbeiter gäbe den fremden "
            "Anspruch frei oder überschriebe dessen Ergebnis. Der Statusvergleich fängt "
            "das nicht: Beide stehen in ``executing``."
        ),
        status=InvariantStatus.ENFORCED,
        component="api.db.run_store",
    ),
    Invariant(
        id="invocation-is-recovery-anchor",
        title="Das Werkzeugprotokoll beantwortet, was aus einem Schritt wurde",
        statement=(
            "Jeder Aufruf eines geplanten Schrittes ist über Lauf und Schrittnummer "
            "auffindbar und lesbar, und sein Zustand unterscheidet „ohne Wirkung "
            "gescheitert“ von „Wirkung unklar“."
        ),
        why=(
            "Ein Lauf mit belegtem Schritt ist entweder in Arbeit oder hängengeblieben — "
            "von außen nicht unterscheidbar. Eine Wiederaufnahme, die das nicht "
            "nachsehen kann, hat nur zwei Möglichkeiten: blind wiederholen (und damit "
            "den doppelten Seiteneffekt öffnen) oder gar nichts tun (und den Lauf "
            "dauerhaft blockieren)."
        ),
        status=InvariantStatus.ENFORCED,
        component="api.db.invocation_store",
    ),
    Invariant(
        id="hung-step-is-reassigned-only-when-provably-idle",
        title="Ein hängender Schritt wird nur neu vergeben, wenn er nachweislich nicht wirkte",
        statement=(
            "Ein beanspruchter Planschritt wird erst nach Ablauf einer Frist übernommen — "
            "gemessen an der Uhr der Datenbank — und nur, wenn das Werkzeugprotokoll eine "
            "Wirkung ausschließt oder das Werkzeug idempotent ist. Die Übernahme vergibt "
            "ein neues Fencing-Token und sperrt den Vorgänger vom Schreiben aus."
        ),
        why=(
            "Ein Lauf in ``executing`` mit belegtem Schritt ist entweder in Arbeit oder "
            "hängengeblieben, und von außen nicht unterscheidbar. Ohne Frist bleibt nur "
            "blind wiederholen (der doppelte Termin) oder gar nichts tun (der dauerhaft "
            "blockierte Lauf). Die Frist allein genügt nicht: Sie sperrt den alten "
            "Arbeiter vom Schreiben aus, nicht vom Wirken — deshalb entscheidet erst das "
            "Protokoll, ob überhaupt erneut gewirkt werden darf."
        ),
        status=InvariantStatus.ENFORCED,
        component="core.orchestrator.recovery",
    ),
    Invariant(
        id="unattended-step-has-no-approval-channel",
        title="Ein Schritt ohne Sitzung erzeugt keine Bestätigung",
        statement=(
            "Ein Werkzeugschritt, der ohne Sitzung ausgeführt wird, legt bei einer "
            "CONFIRM-Entscheidung **keine** Bestätigungsanfrage an. Er wird abgewiesen, "
            "der Lauf bleibt stehen, und der Protokolleintrag führt ihn als wiederholbar."
        ),
        why=(
            "Eine Bestätigung ist an die Sitzung gebunden, in der ihre Vorschau erschien "
            "(``ApprovalGateway.respond``). Eine ohne Sitzung könnte niemand einlösen: "
            "Sie stünde in der Übersicht des Nutzers, ließe sich nicht beantworten und "
            "den Lauf endgültig stehen — das Gegenteil dessen, wofür der Arbeiter gebaut "
            "ist, der hängende Läufe fortsetzt."
        ),
        status=InvariantStatus.ENFORCED,
        component="core.orchestrator.executor",
    ),
    Invariant(
        id="undo-is-bound-to-its-invocation",
        title="Eine Rücknahme trifft genau den Aufruf, zu dem sie gehört",
        statement=(
            "Zurückgenommen wird ausschließlich ein protokollierter, ausgeführter, "
            "eigener Aufruf innerhalb von ``UNDO_TTL`` — höchstens einmal, und an dem "
            "Rücknahmepunkt, den das Werkzeug selbst hinterlassen hat. Weder Token noch "
            "Zielobjekt kommen aus dem Request."
        ),
        why=(
            "Eine Rücknahme löscht. Käme der Rücknahmepunkt vom Aufrufer, wäre sie ein "
            "Löschrecht auf fremde Objekte hinter einem harmlos klingenden Namen — und "
            "zwar eines, das kein Nutzer je erteilt hat. Die Zulässigkeit hängt allein "
            "an der Verengung: eigener Aufruf, kurze Frist, einmal, und nur das, was "
            "dieser Aufruf bewirkt hat."
        ),
        status=InvariantStatus.ENFORCED,
        component="core.policy.undo",
    ),
    Invariant(
        id="undo-grant-single-use",
        title="Eine ausgestellte Rücknahme-Erlaubnis nimmt höchstens einmal zurück",
        statement=(
            "Ein ``UndoGrant`` erreicht den Undo-Handler genau einmal. Der Verbrauch "
            "liegt an der ``invocation_id``, ist atomar und committet, bevor der "
            "Handler läuft — unabhängig davon, wie oft dasselbe Objekt oder eine Kopie "
            "davon vorgelegt wird."
        ),
        why=(
            "Der Anspruch am Gate (``claim_undo``) sichert nur den Übergang *Aufruf → "
            "Erlaubnis*. Typ, Nutzer und Werkzeugname einer ausgestellten Erlaubnis "
            "gelten bei der zweiten Vorlage unverändert — dasselbe Muster, das beim "
            "Ausführungs-Grant bereits dreimal einen Schritt zu früh hing. Dass ein "
            "zweites Löschen desselben Termins folgenlos wäre, ist eine Eigenschaft von "
            "``calendar.create`` und keine des Weges; Undo ist generisch gebaut."
        ),
        status=InvariantStatus.ENFORCED,
        component="core.tools.registry",
    ),
    Invariant(
        id="permissions-change-only-at-the-edge",
        title="Rechte erteilt ein Mensch, kein Werkzeug",
        statement=(
            "Berechtigungen werden ausschließlich an der HTTP-Kante geschrieben — aus "
            "einer geprüften Sitzung, gegen den Scope-Katalog, mit scope-eigenen "
            "Einschränkungen. Kein Werkzeug trägt einen Berechtigungs-Scope, und kein "
            "Kernmodul ruft die schreibenden Methoden."
        ),
        why=(
            "Die gefährliche Richtung ist das Erteilen: Ein Scope auf ``allow`` nimmt "
            "jede künftige Bestätigung aus dem Weg — genau den Dialog, den ein Mensch "
            "liest, bevor etwas nach außen wirkt. Ein Werkzeug, das Berechtigungen "
            "schreibt, wäre der kürzeste Weg von „ein Modell hat Fremdinhalt gelesen“ "
            "zu „das Modell darf jetzt mehr“."
        ),
        status=InvariantStatus.ENFORCED,
        component="api.routes.permissions",
    ),
    Invariant(
        id="audit-chain-records-what-happened",
        title="Was geschieht, steht in der verketteten Spur",
        statement=(
            "Jede Werkzeugausführung, jede Bestätigung und jede Rechteänderung schreibt "
            "einen Eintrag in das hash-verkettete Audit-Log — serialisiert, append-only "
            "und mit einem Weg, die Kette nachzurechnen."
        ),
        why=(
            "Die Kette war vollständig gebaut und wurde nirgends benutzt: "
            "``ToolExecutor(audit=...)`` bekam in der ganzen Anwendung ``None``. Das ist "
            "die unangenehmste Sorte Lücke, weil sie nach außen wie Vollständigkeit "
            "aussieht — geprüft war die Mechanik, nicht ihr Betrieb. Und eine Spur, die "
            "niemand nachrechnen kann, ist eine Behauptung: Der Bruch wird nicht dadurch "
            "sichtbar, dass er existiert, sondern dadurch, dass jemand nachrechnet."
        ),
        status=InvariantStatus.ENFORCED,
        component="api.db.audit_store",
    ),
    Invariant(
        id="event-stream-is-scoped-and-contentless",
        title="Der Ereignisstrom trägt Hinweise, und zwar nur die eigenen",
        statement=(
            "Ein Ereignisstrom liefert ausschließlich Ereignisse des angemeldeten "
            "Nutzers, und er trägt keine Geheimnisse und keinen Fremdinhalt — weder "
            "Nonce noch Argumente noch Werkzeugergebnisse. Was gilt, holt die "
            "Oberfläche über die API."
        ),
        why=(
            "Ein Strom ist eine dauerhafte Leitung: Was einmal falsch verbunden ist, "
            "bleibt es, und eine Oberfläche mit fremden Ereignissen sieht aus wie eine, "
            "die funktioniert. Und eine ``PendingAction`` über einen nutzerweiten Kanal "
            "verteilte eine sitzungsgebundene Nonce an alle Geräte — genau das, was "
            "``GET /actions`` vermeidet."
        ),
        status=InvariantStatus.ENFORCED,
        component="api.events",
    ),
    Invariant(
        id="tool-result-model-view-is-declared",
        title="Ein Modell sieht von einem Ergebnis nur, was das Werkzeug erklärt hat",
        statement=(
            "Aus einem ``ToolResult`` erreicht ausschließlich das den Prompt, was "
            "``ToolSpec.model_visible_fields`` benennt — gekappt auf eine feste Grenze. "
            "Die Vorgabe ist leer."
        ),
        why=(
            "``ToolResult.data`` ist ein ``dict[str, Any]`` ohne Grenze. Ohne Deklaration "
            "entschiede jedes künftige Werkzeug stillschweigend mit, was in Prompts "
            "landet, und in keinem Diff wäre es zu sehen. Die Kappung ist die zweite "
            "Hälfte: Eine gelesene Datei fasst bis 256.000 Bytes und belegte sonst das "
            "halbe Kontextfenster — bei jedem Folgeschritt erneut."
        ),
        status=InvariantStatus.ENFORCED,
        component="contracts.tools",
    ),
    Invariant(
        id="tool-arguments-match-schema",
        title="Argumente werden gegen das Werkzeugschema geprüft",
        statement=(
            "Kein Argumentobjekt erreicht Policy-Entscheidung, Vorschau, Payload-Hash "
            "oder Handler, ohne gegen ``ToolSpec.parameters`` geprüft worden zu sein."
        ),
        why=(
            "Das Schema ist die Zusage, nach der ein Modell seine Argumente bildet. "
            "Ohne Gegenprüfung ist es eine Ansage nach außen ohne Kontrolle nach innen: "
            "Ein Modell, das eine kontaminierte Datei gelesen hat, kann beliebige Felder "
            "erfinden, und der Mensch liest sie in der Vorschau, als gehörten sie zur "
            "Aktion."
        ),
        status=InvariantStatus.ENFORCED,
        component="core.orchestrator.executor",
    ),
    Invariant(
        id="data-class-hard-filter",
        title="Datenklassifikation ist ein hartes Filter",
        statement="Ein Kontext, der eine Klasse nicht zulässt, führt kein Werkzeug dieser Klasse aus.",
        why="P3-Daten dürfen unter keinen Umständen an einen Cloud-Anbieter gelangen.",
        status=InvariantStatus.ENFORCED,
        component="core.policy.engine",
    ),
    Invariant(
        id="unattended-runs-are-stricter",
        title="Unbeaufsichtigte Läufe sind strenger",
        statement="Automationen bestätigen schreibende Aktionen, auch wenn das Recht erteilt ist.",
        why="Nachts ist keine Instanz anwesend, die eine Fehlentscheidung bemerkt.",
        status=InvariantStatus.ENFORCED,
        component="core.policy.engine",
    ),
    # -- Sprachmodelle --------------------------------------------------
    Invariant(
        id="model-never-sees-excess-data-class",
        title="Ein Anbieter sieht nie Daten oberhalb seiner Zulassung",
        statement=(
            "Eine Anfrage erreicht einen Anbieteradapter nur, wenn dessen Modell für die "
            "Datenklasse zugelassen ist; P3 erreicht ausschließlich lokale Modelle."
        ),
        why=(
            "Der Router filtert bei der Modellwahl, aber die Wahl fällt einmal pro Turn "
            "und der Aufruf geschieht danach — oft mehrfach, aus Agentenketten heraus, "
            "mit einem Kontext, der inzwischen P2 gesehen hat. Eine Prüfung nur bei der "
            "Wahl prüft den Zustand von vorhin. Und der Nachweis ist die Null: Der "
            "Adapter darf die Daten nicht einmal im Speicher haben, denn bei einem "
            "Netzwerkadapter wären sie damit bereits unterwegs."
        ),
        status=InvariantStatus.ENFORCED,
        component="core.providers.gateway",
    ),
    Invariant(
        id="cloud-limited-to-p1-with-zero-retention",
        title="Ein fremder Anbieter sieht höchstens P1 — und P1 nur ohne Vorhaltung",
        statement=(
            "Ein Modell, das nicht auf diesem Gerät läuft, erreicht P0 immer, P1 nur mit "
            "hinterlegter Zero-Retention-Zusage, P2 nur nach ausdrücklicher Freigabe und "
            "P3 nie. Geprüft wird beim Aufruf, nicht nur im Katalog."
        ),
        why=(
            "Bis zum ersten fremden Anbieter war die Tabelle aus docs/00-uebersicht.md §8 "
            "eine Absichtserklärung: zero_retention stand in ModelCapability und wurde von "
            "nichts gelesen — dasselbe Muster wie supports_undo vor dem Undo-Weg. Ein "
            "Katalog ist Konfiguration und kann falsch gesetzt sein; die Prüfung gehört "
            "deshalb an dieselbe Stelle wie die für P3. Für P2 sieht das Dokument eine "
            "Freigabe je Domäne vor, die es nicht gibt — solange sie fehlt, gilt die "
            "Vorgabe des Dokuments: standardmäßig lokal."
        ),
        status=InvariantStatus.ENFORCED,
        component="core.providers.gateway",
    ),
    Invariant(
        id="model-tool-calls-are-proposals",
        title="Ein Modell schlägt vor, es ordnet nicht an",
        statement=(
            "Werkzeugaufrufe aus einer Modellantwort tragen keine Erlaubnis: Der "
            "Vertragstyp führt weder Risiko noch Scope noch Bestätigung, und jeder "
            "Vorschlag durchläuft Policy Engine und Ausführungs-Gate wie jede andere "
            "Absicht."
        ),
        why=(
            "Die verbreitete Bauart nennt dieselbe Struktur „tool_call“ und behandelt "
            "sie als Anweisung. Von dort ist es ein kleiner Schritt zu einer Schleife, "
            "die Modellausgabe ausführt — und damit zur Fernsteuerung für jeden, der dem "
            "Modell Text unterschieben kann. Der Name ProposedToolCall ist deshalb Teil "
            "der Absicherung, nicht Kosmetik."
        ),
        status=InvariantStatus.ENFORCED,
        component="contracts.llm",
    ),
    # -- Orchestrierung (noch offen, Punkt 9) ---------------------------
    Invariant(
        id="orchestrator-consumes-decisions",
        title="Der Orchestrator entscheidet nichts über Sicherheit",
        statement=(
            "Der Orchestrator fragt die Policy Engine und das Ausführungs-Gate; er "
            "bildet keine eigene Meinung darüber, ob etwas erlaubt ist."
        ),
        why=(
            "Sobald der Orchestrator „das ist wahrscheinlich sicher“ oder „das wurde "
            "gerade bestätigt“ selbst beurteilt, gibt es zwei Wahrheiten über "
            "Berechtigungen — und die zweite prüft niemand. Er muss Konsument von "
            "Sicherheitsentscheidungen sein, nicht ihr Urheber."
        ),
        status=InvariantStatus.ENFORCED,
        component="core.orchestrator",
    ),
    Invariant(
        id="agent-chain-preserves-capability-binding",
        title="Delegationsketten erweitern keine Rechte",
        statement=(
            "Über beliebig viele Agentenstufen hinweg bleibt die Rechtemenge die "
            "Schnittmenge aller beteiligten Whitelists mit den Nutzerrechten."
        ),
        why=(
            "Die bisherige Prüfung deckt eine Stufe ab. Bei A → B → C darf C nicht "
            "die Fähigkeiten von B erben, nur weil B ihn aufgerufen hat — sonst ist "
            "die Kette der Umweg um jede Beschränkung."
        ),
        status=InvariantStatus.ENFORCED,
        component="core.agents",
    ),
    Invariant(
        id="agent-chain-propagates-taint",
        title="Kontamination wandert durch die ganze Kette",
        statement=(
            "Liest ein Agent auf beliebiger Stufe Fremdinhalt, gilt der gesamte "
            "übergeordnete Lauf als kontaminiert."
        ),
        why=(
            "Andernfalls genügte eine Zwischenstufe als Waschmaschine: Agent B liest "
            "die Mail, meldet ein „sauberes“ Ergebnis nach oben, und A sendet."
        ),
        status=InvariantStatus.ENFORCED,
        component="core.agents",
    ),
    # -- Geheimnisse ----------------------------------------------------
    Invariant(
        id="secrets-sealed-at-rest",
        title="Zugangsdaten liegen verschlüsselt und an ihren Platz gebunden",
        statement=(
            "OAuth-Tokens stehen ausschließlich als Geheimtext in der Datenbank; der "
            "Datenschlüssel liegt daneben, verpackt mit einem KEK, den der Prozess nicht "
            "herausgeben kann. Der Geheimtext ist an die Konto-ID gebunden und öffnet "
            "sich in keiner anderen Zeile."
        ),
        why=(
            "Tokens in einer Klartextspalte sind der häufigste Fehler in dieser Art "
            "Projekt: Ein Datenbank-Dump wäre damit Vollzugriff auf das Postfach. Die "
            "Bindung an die Konto-ID kommt dazu, weil Verschlüsselung allein das "
            "Verschieben nicht verhindert — wer die Datenbank erreicht, könnte sonst "
            "den Geheimtext eines fremden Kontos in die eigene Zeile kopieren und ihn "
            "vom System öffnen lassen (ADR-008)."
        ),
        status=InvariantStatus.ENFORCED,
        component="core.crypto.envelope",
    ),
    Invariant(
        id="kek-never-leaves-its-instance",
        title="Der KEK verlässt seine Instanz nicht",
        statement=(
            "Der Port entpackt Datenschlüssel, statt den KEK auszuliefern. Der "
            "Datei-Provider ist ausschließlich in der Entwicklung zulässig und wird in "
            "jeder anderen Umgebung beim Start abgewiesen."
        ),
        why=(
            "Läge der KEK im Speicher des Prozesses, der HTTP annimmt, gäbe eine "
            "Schwachstelle im Web-Layer alle Postfach-Tokens preis. Ein Port, der den "
            "Schlüssel herausgibt, wäre von Vault Transit gar nicht implementierbar — "
            "die Signatur trägt die Zusage deshalb selbst (ADR-008 V1.1). Die Prüfung "
            "steht beim Start und nicht beim ersten Zugriff: Eine Fehlkonfiguration "
            "soll auffallen, bevor jemand ihr Tokens anvertraut."
        ),
        status=InvariantStatus.ENFORCED,
        component="api.settings",
    ),
    # -- Audit ----------------------------------------------------------
    Invariant(
        id="audit-append-only",
        title="Das Audit-Log ist unveränderlich",
        statement="UPDATE und DELETE werden auf Datenbankebene abgelehnt.",
        why="Wer die Anwendung kompromittiert, soll seine Spuren nicht beseitigen können.",
        status=InvariantStatus.ENFORCED,
        component="db.audit_log",
    ),
    Invariant(
        id="audit-tamper-evident",
        title="Manipulation ist erkennbar",
        statement="Änderung, Löschung oder Umsortierung von Einträgen bricht die Hash-Kette.",
        why="Unveränderlichkeit ohne Nachweis wäre nur eine Behauptung.",
        status=InvariantStatus.ENFORCED,
        component="core.audit.chain",
    ),
    Invariant(
        id="audit-chain-break-is-detected",
        title="Ein Bruch wird gefunden, ohne dass jemand nachsieht",
        statement=(
            "Der Arbeiter rechnet die ganze Kette in eigenem Takt nach. Ein Bruch hält "
            "ihn an und steht danach als Eintrag in der Kette, die er betrifft."
        ),
        why=(
            "'Erkennbar' ist keine Erkennung. Die Nachrechnung stand, der Endpunkt stand "
            "— und sein einziger Aufrufer war niemand: Wer 'GET /audit/verify' nie "
            "aufruft, merkt eine Manipulation nie. Eine Prüfung ohne Folge wäre dieselbe "
            "Lücke eine Ebene weiter, deshalb hört der Arbeiter auf zu wirken. Ein Bruch "
            "heißt, dass jemand an der Anwendung vorbei an der Datenbank war; wer das "
            "kann, kann auch Berechtigungen setzen und Bestätigungen fälschen (ADR-018)."
        ),
        status=InvariantStatus.ENFORCED,
        component="core.audit.watch",
    ),
    Invariant(
        id="audit-survives-erasure",
        title="Löschpflicht und Kette schließen sich nicht aus",
        statement=(
            "Die Pseudonymisierung eines Nutzers lässt die Hash-Kette unversehrt, weil "
            "user_id nicht gehasht wird."
        ),
        why=(
            "Wären beide Anforderungen unvereinbar, müsste eine von ihnen aufgegeben "
            "werden — die Löschpflicht oder die Unveränderlichkeit."
        ),
        status=InvariantStatus.ENFORCED,
        component="core.audit.chain",
    ),
    # -- Schichtung -----------------------------------------------------
    Invariant(
        id="file-access-confined-to-roots",
        title="Ein Dateizugriff verlässt die freigegebenen Wurzeln nicht",
        statement=(
            "files.read gibt nur Inhalte heraus und files.list nur Namen, deren Pfad "
            "**nach Auflösung** unterhalb einer konfigurierten Wurzel liegt; eine "
            "Abweisung verrät nicht, wohin der Pfad zeigte, und eine Aufzählung löst "
            "die Verweise darin nicht auf."
        ),
        why=(
            "Zwei Grenzen, und sie beantworten verschiedene Fragen. Die Berechtigung "
            "(FilesConstraints.allowed_roots) prüft den Pfad als Zeichenkette — sie hat "
            "kein Dateisystem und kann einen Symlink grundsätzlich nicht sehen. Der "
            "Adapter löst auf und prüft danach; erst das beantwortet, wohin der Pfad "
            "wirklich zeigt. Beim Bau des ersten Dateiwerkzeugs fiel dabei ein Loch in "
            "der ersten Prüfung auf: relative_to() vergleicht Segmente und normalisiert "
            "nicht, weshalb '/wurzel/../../etc/passwd' als erlaubt galt. Der vorhandene "
            "Test prüfte die Präfix-Umgehung, an die jemand gedacht hatte, nicht die "
            "Traversierung daneben. Zusätzlich abgewiesen werden nicht-reguläre Dateien: "
            "Eine FIFO im freigegebenen Ordner hinge bis zum Timeout, /dev/zero füllte "
            "den Speicher."
        ),
        status=InvariantStatus.ENFORCED,
        component="integrations.localfs",
    ),
    Invariant(
        id="web-fetch-reaches-only-public-addresses",
        title="Ein Abruf erreicht nur, was aus dem Internet erreichbar ist",
        statement=(
            "web.fetch baut eine Verbindung ausschließlich zu öffentlich routbaren "
            "Adressen auf; geprüft wird die aufgelöste Adresse vor dem Verbindungsaufbau "
            "und nach jeder Weiterleitung erneut."
        ),
        why=(
            "Bei einem Werkzeug, dessen Argumente ein Modell formuliert, ist eine Adresse "
            "eine Anweisung an das Netzwerk, in dem der Server steht — und von dort ist "
            "mehr erreichbar als aus dem Internet: die eigene Datenbank, das Nachbarsystem "
            "hinter der Firewall, der Metadatendienst des Cloud-Anbieters unter "
            "169.254.169.254. Eine Sperrliste aus Zeichenketten genügt nicht, weil ein Name "
            "eine Behauptung ist; und eine Prüfung nur der ersten Adresse genügt nicht, weil "
            "ein Name mehrere führen kann. Die Weiterleitung ist der klassische Weg um jede "
            "Eingangsprüfung herum."
        ),
        status=InvariantStatus.ENFORCED,
        component="integrations.web",
    ),
    Invariant(
        id="oauth-callback-belongs-to-its-session",
        title="Ein Rückruf zählt nur für die Sitzung, die den Vorgang begonnen hat",
        statement=(
            "Der Autorisierungscode wird nur verarbeitet, wenn der mitgelieferte state zu "
            "einem Vorgang gehört, den derselbe angemeldete Nutzer begonnen hat; die "
            "Bedingung steht in derselben Anweisung, die den Vorgang verbraucht."
        ),
        why=(
            "Der bekannteste Angriff auf einen Zustimmungsablauf verschenkt ein Konto, "
            "statt eines zu stehlen: Der Angreifer beginnt bei sich, fängt seinen eigenen "
            "Rückruf ab und bringt dessen Adresse in den Browser des Opfers. Läuft dort "
            "eine Sitzung, wird sein Postfach an dessen Konto gehängt — und ab da liest "
            "er mit, ohne je ein Passwort gesehen zu haben. Der Schutz muss in der "
            "schreibenden Anweisung stehen und nicht in einer Prüfung davor: Wer erst "
            "liest und dann schreibt, hat dazwischen ein Fenster. Und die Ablehnung darf "
            "nicht sagen, welcher der vier Gründe zutraf — eine feinere Auskunft verriete "
            "dem Angreifer, ob sein Rückruf beim Opfer angekommen ist."
        ),
        status=InvariantStatus.ENFORCED,
        component="api.db.authorization_store",
    ),
    Invariant(
        id="oauth-state-is-consumed-before-the-exchange",
        title="Der Vorgang ist verbraucht, bevor der Code eingelöst wird",
        statement=(
            "Der state wird verbraucht, bevor der Autorisierungscode an den Anbieter "
            "geht; ein gescheiterter Tausch macht den Vorgang nicht wieder einlösbar."
        ),
        why=(
            "Die bequeme Reihenfolge wäre die umgekehrte — erst tauschen, dann "
            "verbrauchen —, weil ein fehlgeschlagener Tausch dann wiederholbar bliebe. "
            "Genau das ist die Lücke: Ein abgefangener Code hätte beliebig viele Versuche, "
            "und zwei gleichzeitige Rückrufe bekämen beide ihren Tausch. Dieselbe "
            "Überlegung wie beim Grant-Verbrauch, der ebenfalls vor der Wirkung nach "
            "außen steht und deshalb eine eigene Transaktion hat."
        ),
        status=InvariantStatus.ENFORCED,
        component="api.routes.accounts",
    ),
    Invariant(
        id="oauth-refresh-is-serialized-per-account",
        title="Ein Konto wird nicht zweimal gleichzeitig erneuert",
        statement=(
            "Zu einem Zeitpunkt läuft je Konto höchstens eine Token-Erneuerung; "
            "gleichzeitige Anfragen warten und finden danach den frischen Token vor, "
            "statt selbst einen zu holen."
        ),
        why=(
            "Der harmlose Fall ist Verschwendung. Der teure ist ein Anbieter, der den "
            "Erneuerungstoken rotiert: Dann entwertet die erste Antwort den Token, mit dem "
            "die zweite Anfrage gerade unterwegs ist — die zweite bekommt invalid_grant und "
            "erklärt das Konto für tot, obwohl die erste es soeben erneuert hat. Aus zwei "
            "erfolgreichen Absichten wird ein kaputtes Konto. Google rotiert heute nicht, "
            "OAuth 2.1 empfiehlt es; der Schaden entsteht also nicht bei einem "
            "Anbieterwechsel, sondern wenn der Anbieter seine Praxis ändert, ohne dass hier "
            "jemand etwas anfasst."
        ),
        status=InvariantStatus.ENFORCED,
        component="api.token_service",
    ),
    Invariant(
        id="oauth-account-dies-only-on-a-revoked-grant",
        title="Eine Netzstörung erklärt kein Konto für tot",
        statement=(
            "Der Status eines Kontos wird nur dann auf 'expired' gesetzt, wenn der "
            "Anbieter die Zustimmung ausdrücklich verweigert (invalid_grant); jeder andere "
            "Fehlschlag lässt den Status unverändert."
        ),
        why=(
            "Ein Refresh scheitert aus zwei Gründen, und sie führen zu entgegengesetzten "
            "Reaktionen. Bei einem Zeitlimit oder einem 500 ist über die Zustimmung nichts "
            "gesagt — wer das Konto dann abschreibt, macht aus einer Störung einen Verlust, "
            "und der Nutzer stimmt neu zu, obwohl nichts kaputt war. Auch ein 401 gehört "
            "hierher: Er heißt, dass unsere Client-Zugangsdaten nicht stimmen, und eine "
            "falsch eingetragene CLIENT_SECRET räumte sonst reihenweise gesunde "
            "Verbindungen ab."
        ),
        status=InvariantStatus.ENFORCED,
        component="api.token_service",
    ),
    Invariant(
        id="resource-ownership-checked-once",
        title="Eine Sitzung berechtigt an eigenen Objekten, nicht an beliebigen",
        statement=(
            "Jeder Endpunkt, der eine Ressourcenkennung entgegennimmt, prüft die "
            "Zugehörigkeit zum angemeldeten Nutzer über genau eine Funktion; ein fremdes "
            "Objekt ist von einem nicht existierenden nicht unterscheidbar."
        ),
        why=(
            "identity-derives-from-session sagt, wer fragt — nicht, ob das angefragte "
            "Objekt dem Fragenden gehört. Das ist der nächste kurze Angriff nach 'user_id "
            "im Body': eine gültige eigene Sitzung und eine fremde run_id. Die Prüfung an "
            "genau einer Stelle zu halten ist dieselbe Entscheidung wie bei "
            "current_session; ein zweiter Ladeweg hätte sie nicht. Die Antwort ist 404 "
            "und nicht 403, weil 403 die Existenz bestätigt und damit aufzählbar macht."
        ),
        status=InvariantStatus.ENFORCED,
        component="api.routes",
    ),
    Invariant(
        id="run-state-compare-and-set",
        title="Ein Lauf wird nur aus dem erwarteten Status fortgeschrieben",
        statement=(
            "save() schreibt nur, wenn der Lauf noch in dem Status steht, den der "
            "Schreiber vorzufinden erwartet; sonst wird abgewiesen und nichts geändert."
        ),
        why=(
            "load() … entscheiden … save() ist bei zwei Schreibern ein Überschreiben, und "
            "der interessante Fall ist genau dieser: Ein Schreiber, der den Lauf noch in "
            "'queued' wähnt, dürfte einen inzwischen abgebrochenen nicht wieder in Gang "
            "setzen. Ohne den Vergleich in der WHERE-Klausel gewinnen zehn nebenläufige "
            "Übergänge alle zehn — nachgemessen. Vierter Fall desselben Musters nach "
            "Nonce, Ausführungsanspruch und Grant-Verbrauch, diesmal von vornherein an "
            "der richtigen Stelle. Was er nicht leistet: Zwei Schreiber im selben Status "
            "überschreiben einander weiterhin in den übrigen Feldern; dagegen hülfe eine "
            "Version je Zeile."
        ),
        status=InvariantStatus.ENFORCED,
        component="api.db.run_store",
    ),
    Invariant(
        id="uncertain-effect-resolved-only-by-owner",
        title="Einen unklaren Schritt löst nur sein Eigentümer auf — gegen den aktuellen Anspruch",
        statement=(
            "Ein Schritt mit möglicher, aber unbestätigter Wirkung bleibt gesperrt, bis "
            "der Eigentümer des Laufs eine von genau drei benannten Entscheidungen "
            "trifft; sie gilt nur gegen das Fencing-Token des gehaltenen Anspruchs und "
            "wird in derselben Anweisung geprüft, die schreibt."
        ),
        why=(
            "Die Sperre verhindert den doppelten Seiteneffekt: Ist die Frist abgelaufen "
            "und schließt das Werkzeugprotokoll eine Wirkung nicht aus, darf kein Automat "
            "wiederholen. Wer sie aufhebt, hebt genau diesen Schutz auf — deshalb ist die "
            "Auflösung selbst eine Grenze und keine Schaltfläche. Ohne die Bindung an das "
            "aktuelle Token entschiede eine Browserseite mit veraltetem Zustand über einen "
            "Vorgang, den der nächste Wiederaufnahmedurchgang längst neu übernommen hat; "
            "ohne die Prüfung in der schreibenden Anweisung gewännen zwei gleichzeitige "
            "Entscheidungen beide. Ein allgemeines 'setze den Status auf X' wäre bequemer "
            "und die Abschaffung des Zustandsautomaten."
        ),
        status=InvariantStatus.ENFORCED,
        component="core.orchestrator.resolution",
    ),
    Invariant(
        id="layering-contracts-independent",
        title="Verträge hängen von nichts ab",
        statement="packages/contracts importiert nichts aus dem Projekt.",
        why="Ein Zyklus koppelte die Typgenerierung an Anwendungscode.",
        status=InvariantStatus.ENFORCED,
        component="repo",
    ),
    Invariant(
        id="layering-no-provider-sdk-in-core",
        title="Kein Provider-SDK im Kern",
        statement="Weder core noch contracts importieren Anbieter-SDKs oder Agenten-Frameworks.",
        why="Sonst wäre die Austauschbarkeit der Provider eine Absichtserklärung.",
        status=InvariantStatus.ENFORCED,
        component="repo",
    ),
)


def invariant_ids() -> frozenset[str]:
    return frozenset(i.id for i in INVARIANTS)


def _no_duplicates() -> None:
    ids = [i.id for i in INVARIANTS]
    if len(ids) != len(set(ids)):
        duplicates = sorted({i for i in ids if ids.count(i) > 1})
        raise RuntimeError(f"Doppelte Invarianten-Kennung: {duplicates}")


_no_duplicates()
