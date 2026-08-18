// GENERIERT — nicht bearbeiten. Erzeugt von scripts/gen_contracts.py


export type DataClass = "P0" | "P1" | "P2" | "P3";
export const DataClassValues = ["P0", "P1", "P2", "P3"] as const;

export type RiskLevel = "low" | "medium" | "high" | "critical";
export const RiskLevelValues = ["low", "medium", "high", "critical"] as const;

export type PermissionMode = "deny" | "confirm" | "allow";
export const PermissionModeValues = ["deny", "confirm", "allow"] as const;

export type PolicyEffect = "allow" | "confirm" | "deny";
export const PolicyEffectValues = ["allow", "confirm", "deny"] as const;

export type RunStatus = "queued" | "planning" | "executing" | "awaiting_confirmation" | "verifying" | "completed" | "failed" | "cancelled" | "interrupted" | "budget_exceeded";
export const RunStatusValues = ["queued", "planning", "executing", "awaiting_confirmation", "verifying", "completed", "failed", "cancelled", "interrupted", "budget_exceeded"] as const;

export type CoreState = "idle" | "listening" | "thinking" | "executing" | "awaiting" | "speaking" | "error" | "muted";
export const CoreStateValues = ["idle", "listening", "thinking", "executing", "awaiting", "speaking", "error", "muted"] as const;

export type MemoryKind = "semantic_fact" | "preference" | "episodic" | "entity" | "procedure";
export const MemoryKindValues = ["semantic_fact", "preference", "episodic", "entity", "procedure"] as const;

export type Intent = "chat" | "question" | "task" | "command" | "research" | "creative" | "code" | "clarification";
export const IntentValues = ["chat", "question", "task", "command", "research", "creative", "code", "clarification"] as const;

export const dataClassLevel: Record<DataClass, number> = {
  "P0": 0,
  "P1": 1,
  "P2": 2,
  "P3": 3,
};

export const riskLevelOrder: Record<RiskLevel, number> = {
  "low": 0,
  "medium": 1,
  "high": 2,
  "critical": 3,
};
