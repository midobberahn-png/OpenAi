"""Generierung der abgeleiteten Artefakte (ADR-006).

Pydantic-Modelle sind die einzige Quelle der Wahrheit. Aus ihnen entstehen:

* JSON-Schema aller Vertragsmodelle (Grundlage der TypeScript-Typen)
* die Ereignis-Schemata für den WebSocket-Kanal
* der Scope-Katalog als lesbare Dokumentation

Die OpenAPI-Ausgabe kommt hinzu, sobald die FastAPI-App existiert (Block 2);
das Skript erkennt das selbst und überspringt den Schritt bis dahin.

CI prüft anschließend mit ``git diff --exit-code``, ob die Artefakte aktuell
sind — handgepflegte Typen driften sonst garantiert ab.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

REPO = Path(__file__).resolve().parent.parent
WEB_LIB = REPO / "apps" / "web" / "lib" / "api" / "generated"
DOCS_GEN = REPO / "docs" / "generated"

BANNER = "// GENERIERT — nicht bearbeiten. Erzeugt von scripts/gen_contracts.py\n"


def _write(path: Path, content: str) -> bool:
    """Schreibt nur bei Änderung. Gibt zurück, ob sich etwas geändert hat."""
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists() and path.read_text(encoding="utf-8") == content:
        return False
    path.write_text(content, encoding="utf-8")
    return True


def generate_model_schemas() -> list[Path]:
    """JSON-Schema aller öffentlichen Vertragsmodelle."""
    from pydantic import BaseModel, TypeAdapter

    import jarvis_contracts as jc

    schemas: dict[str, Any] = {}
    for name in sorted(jc.__all__):
        obj = getattr(jc, name)
        if isinstance(obj, type) and issubclass(obj, BaseModel):
            schemas[name] = obj.model_json_schema(ref_template="#/$defs/{model}")

    # Die diskriminierten Unions der WebSocket-Nachrichten separat, damit die
    # Frontend-Seite den Discriminator sauber auswerten kann.
    for union_name in ("ClientMessage", "ServerMessage"):
        adapter = TypeAdapter(getattr(jc, union_name))
        schemas[union_name] = adapter.json_schema(ref_template="#/$defs/{model}")

    payload = {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "title": "JARVIS Contracts",
        "version": jc.__version__,
        "$defs": schemas,
    }
    out = json.dumps(payload, indent=2, ensure_ascii=False, sort_keys=True) + "\n"
    path = WEB_LIB / "contracts.schema.json"
    return [path] if _write(path, out) else []


def generate_enums_ts() -> list[Path]:
    """Handverwendbare TypeScript-Enums für die Werte, die die UI direkt braucht.

    Bewusst nur die Aufzählungen: Die vollständigen Objekttypen werden in
    Block 2 aus dem OpenAPI-Schema erzeugt, sobald es die App gibt.
    """
    import jarvis_contracts as jc

    lines = [BANNER, ""]
    enums = [
        ("DataClass", jc.DataClass),
        ("RiskLevel", jc.RiskLevel),
        ("PermissionMode", jc.PermissionMode),
        ("PolicyEffect", jc.PolicyEffect),
        ("RunStatus", jc.RunStatus),
        ("CoreState", jc.CoreState),
        ("MemoryKind", jc.MemoryKind),
        ("Intent", jc.Intent),
    ]
    for name, enum_cls in enums:
        values = " | ".join(f'"{m.value}"' for m in enum_cls)
        lines.append(f"export type {name} = {values};")
        lines.append(
            f"export const {name}Values = ["
            + ", ".join(f'"{m.value}"' for m in enum_cls)
            + "] as const;"
        )
        lines.append("")

    # Die Ordnung ist bedeutungstragend und darf im Frontend nicht neu
    # erfunden werden — lexikografisch wäre sie bei RiskLevel falsch.
    lines.append("export const dataClassLevel: Record<DataClass, number> = {")
    for member in jc.DataClass:
        lines.append(f'  "{member.value}": {member.level},')
    lines.append("};")
    lines.append("")
    lines.append("export const riskLevelOrder: Record<RiskLevel, number> = {")
    for member in jc.RiskLevel:
        lines.append(f'  "{member.value}": {member.level},')
    lines.append("};")
    lines.append("")

    path = WEB_LIB / "enums.ts"
    return [path] if _write(path, "\n".join(lines)) else []


def generate_scope_catalog() -> list[Path]:
    """Lesbarer Scope-Katalog — Grundlage jedes Sicherheitsreviews."""
    sys.path.insert(0, str(REPO / "scripts"))
    from seed import SCOPES

    by_domain: dict[str, list[tuple[str, str, str, str]]] = {}
    for entry in SCOPES:
        by_domain.setdefault(entry[0].split(".", 1)[0], []).append(entry)

    lines = [
        "# Scope-Katalog",
        "",
        "> GENERIERT aus `scripts/seed.py` — nicht von Hand bearbeiten.",
        "",
        "Standardbelegung nach Erstinstallation. Der Nutzer kann jeden Scope im",
        "Permission Center ändern; diese Tabelle zeigt den Auslieferungszustand.",
        "",
        f"**{len(SCOPES)} Scopes** in {len(by_domain)} Domänen.",
        "",
    ]
    symbols = {"allow": "erlauben", "confirm": "**bestätigen**", "deny": "**verweigern**"}
    for domain in sorted(by_domain):
        lines += [
            f"## `{domain}`",
            "",
            "| Scope | Beschreibung | Standard | Risiko |",
            "|---|---|---|---|",
        ]
        for name, desc, mode, risk in sorted(by_domain[domain]):
            lines.append(f"| `{name}` | {desc} | {symbols[mode]} | {risk} |")
        lines.append("")

    lines += [
        "## Bewusst nicht vorhanden",
        "",
        "Diese Grenzen sind keine Konfiguration, sondern Abwesenheit von",
        "Implementierung — die belastbarste Form der Zusicherung:",
        "",
        "- **Geldbewegungen** — kein `finance.transfer` o. ä. existiert.",
        "- **Vertragsabschlüsse** — keine Signatur- oder Bestell-Werkzeuge.",
        "- **Rechteerweiterung durch JARVIS selbst** — `permissions.*` ist für",
        "  Werkzeuge nicht erreichbar.",
        "",
    ]
    path = DOCS_GEN / "scopes.md"
    return [path] if _write(path, "\n".join(lines)) else []


def generate_openapi() -> list[Path]:
    """OpenAPI-Schema — sobald die FastAPI-App existiert (Block 2)."""
    try:
        from jarvis_api.main import app
    except ImportError:
        print("  · OpenAPI übersprungen (FastAPI-App noch nicht vorhanden)")
        return []

    out = json.dumps(app.openapi(), indent=2, ensure_ascii=False, sort_keys=True) + "\n"
    path = WEB_LIB / "openapi.json"
    return [path] if _write(path, out) else []


def main() -> int:
    print("Generiere abgeleitete Artefakte…")
    changed: list[Path] = []
    for step in (
        generate_model_schemas,
        generate_enums_ts,
        generate_scope_catalog,
        generate_openapi,
    ):
        changed += step()

    if changed:
        print(f"✓ {len(changed)} Datei(en) aktualisiert:")
        for path in changed:
            print(f"  · {path.relative_to(REPO)}")
    else:
        print("✓ Alles aktuell.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
