/**
 * Shared by the per-screen v2 tests (ADR-0039): render as a VIEWER key, and
 * the colour audit as an assertion.
 */
import type { ReactElement } from "react";
import { expect } from "vitest";

import type { Principal } from "@/api/types";
import { AuthContext, type Auth } from "@/state/auth";
import { auditColour } from "./colour";

/** A screen as a VIEWER key sees it. Outside a provider the role is unknown, and offered. */
export function asViewer(ui: ReactElement): ReactElement {
  const viewer: Auth = {
    status: "ready",
    principal: { name: "viewer-key", role: "viewer" } as Principal,
    reason: null,
    session: 0,
    signIn: async () => {},
    signOut: () => {},
  };
  return <AuthContext.Provider value={viewer}>{ui}</AuthContext.Provider>;
}

/** No band colour without its band's name, and none inline; returns how many were checked. */
export function colourIsSeverityOnly(): number {
  const audit = auditColour();
  expect(audit.violations).toEqual([]);
  return audit.coloured;
}
