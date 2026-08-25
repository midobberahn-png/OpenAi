"""Hash-verkettetes Audit-Log."""

from .chain import (
    AUDIT_ADVISORY_LOCK_KEY,
    GENESIS_HASH,
    AuditEntry,
    AuditSink,
    ChainBreak,
    StoredAuditRow,
    canonical_payload,
    compute_entry_hash,
    verify_chain,
)
from .watch import (
    CHAIN_BREAK_ACTION,
    DEFAULT_AUDIT_INTERVAL,
    ChainInspector,
    ChainReport,
    ChainWatch,
)

__all__ = [
    "AUDIT_ADVISORY_LOCK_KEY",
    "CHAIN_BREAK_ACTION",
    "DEFAULT_AUDIT_INTERVAL",
    "GENESIS_HASH",
    "AuditEntry",
    "AuditSink",
    "ChainBreak",
    "ChainInspector",
    "ChainReport",
    "ChainWatch",
    "StoredAuditRow",
    "canonical_payload",
    "compute_entry_hash",
    "verify_chain",
]
