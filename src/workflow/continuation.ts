export type WorkflowState =
  | "running"
  | "ready-to-continue"
  | "blocked-user"
  | "blocked-safety"
  | "terminal"
  | "invariant-failure";

export interface ContinuationState {
  workflowState: WorkflowState;
  requiresUserInput: boolean;
  safeToAutoContinue: boolean;
  nextAction: string | null;
  activeProcessExpected: boolean;
  blocker: string | null;
}

function safeAction(value: string | null): string | null {
  if (value === null) return null;
  if (typeof value !== "string" || !/^[a-z0-9][a-z0-9._-]{0,127}$/u.test(value)) {
    throw new Error("continuation action must be a bounded, path-free identifier");
  }
  return value;
}

function safeBlocker(value: string | null): string | null {
  if (value === null) return null;
  if (typeof value !== "string" || Buffer.byteLength(value) > 1024 || /[\u0000-\u001f\u007f]/u.test(value)) {
    throw new Error("continuation blocker must be bounded text without control characters");
  }
  return value;
}

export function continuation(input: ContinuationState): ContinuationState {
  if (!["running", "ready-to-continue", "blocked-user", "blocked-safety", "terminal", "invariant-failure"].includes(input.workflowState)) {
    throw new Error("continuation workflow state is unsupported");
  }
  if (typeof input.requiresUserInput !== "boolean" || typeof input.safeToAutoContinue !== "boolean"
    || typeof input.activeProcessExpected !== "boolean") {
    throw new Error("continuation flags must be booleans");
  }
  const value = { ...input, nextAction: safeAction(input.nextAction), blocker: safeBlocker(input.blocker) };
  const active = value.workflowState === "running";
  const blocked = value.workflowState === "blocked-user" || value.workflowState === "blocked-safety" || value.workflowState === "invariant-failure";
  const terminal = value.workflowState === "terminal";
  const ready = value.workflowState === "ready-to-continue";
  if (value.activeProcessExpected !== active) throw new Error("only a running continuation may expect an active process");
  if (value.requiresUserInput !== (value.workflowState === "blocked-user")) {
    throw new Error("requiresUserInput must be true exactly for a user blocker");
  }
  if (value.safeToAutoContinue !== ready) throw new Error("safeToAutoContinue must be true exactly for a ready continuation");
  if ((active || ready) && value.nextAction === null) throw new Error("running and ready continuations require one next-action identifier");
  if ((blocked && value.blocker === null) || (!blocked && value.blocker !== null)) {
    throw new Error("only blocked or invariant-failure continuations may include a blocker");
  }
  if (terminal && value.nextAction !== null) throw new Error("terminal continuations cannot declare a next action");
  return value;
}

export function terminalContinuation(): ContinuationState {
  return continuation({
    workflowState: "terminal",
    requiresUserInput: false,
    safeToAutoContinue: false,
    nextAction: null,
    activeProcessExpected: false,
    blocker: null,
  });
}

export function readyContinuation(nextAction: string): ContinuationState {
  return continuation({
    workflowState: "ready-to-continue",
    requiresUserInput: false,
    safeToAutoContinue: true,
    nextAction,
    activeProcessExpected: false,
    blocker: null,
  });
}

export function runningContinuation(activeAction: string): ContinuationState {
  return continuation({
    workflowState: "running",
    requiresUserInput: false,
    safeToAutoContinue: false,
    nextAction: activeAction,
    activeProcessExpected: true,
    blocker: null,
  });
}

export function invariantFailureContinuation(blocker: string): ContinuationState {
  return continuation({
    workflowState: "invariant-failure",
    requiresUserInput: false,
    safeToAutoContinue: false,
    nextAction: null,
    activeProcessExpected: false,
    blocker,
  });
}

export function assertBeforeYieldInvariant(state: ContinuationState, activeProcessVerified: boolean): void {
  const validActive = state.workflowState === "running" && state.activeProcessExpected && activeProcessVerified;
  const validBlocked = ["blocked-user", "blocked-safety", "invariant-failure"].includes(state.workflowState) && state.blocker !== null;
  const validTerminal = state.workflowState === "terminal";
  const count = Number(validActive) + Number(validBlocked) + Number(validTerminal);
  if (count !== 1) throw new Error("before-yield invariant failed: workflow has neither a verified active operation, an exact blocker, nor terminal completion");
}

export function userBlockedContinuation(blocker: string, nextAction: string | null = null): ContinuationState {
  return continuation({
    workflowState: "blocked-user",
    requiresUserInput: true,
    safeToAutoContinue: false,
    nextAction,
    activeProcessExpected: false,
    blocker,
  });
}

export function safetyBlockedContinuation(blocker: string, nextAction: string | null = null): ContinuationState {
  return continuation({
    workflowState: "blocked-safety",
    requiresUserInput: false,
    safeToAutoContinue: false,
    nextAction,
    activeProcessExpected: false,
    blocker,
  });
}

export function withContinuation(value: unknown, state: ContinuationState): Record<string, unknown> {
  const result = typeof value === "object" && value !== null && !Array.isArray(value)
    ? value as Record<string, unknown>
    : { result: value };
  for (const key of ["workflowState", "requiresUserInput", "safeToAutoContinue", "nextAction", "activeProcessExpected", "blocker"] as const) {
    if (Object.hasOwn(result, key)) throw new Error("result already contains a reserved continuation field");
  }
  return { ...result, ...continuation(state) };
}
