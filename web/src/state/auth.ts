/**
 * Who the console is signed in as (ADR-0035).
 *
 * The console holds a KEY, not a session: `GET /auth/whoami` says whose key it
 * is and what role it has. The SERVER decides whether a key is needed -- any
 * 401 flips the console to its sign-in gate, carrying the server's reason --
 * so nothing here guesses at the server's configuration.
 *
 * A stored key is checked BEFORE the console renders, so a viewer never sees,
 * let alone presses, a control only an admin may use.
 */
import { createContext, useCallback, useContext, useEffect, useState } from "react";

import { getToken, onUnauthorized, setToken, whoami } from "@/api/client";
import type { Principal } from "@/api/types";

/** `checking` a stored key; `ready` to show the console; sign-in `required`. */
export type AuthStatus = "checking" | "ready" | "required";

export interface Auth {
  status: AuthStatus;
  /** Whose key this is. `null` = not known: no key yet, or whoami failed. */
  principal: Principal | null;
  /** Why the server refused the console, in its own words. */
  reason: string | null;
  /** Bumps on every sign-in, so the console remounts and reloads with the key. */
  session: number;
  /** Check a key with the server, then keep it. Rejects -- storing nothing -- if refused. */
  signIn: (token: string) => Promise<void>;
  /** Forget the key in this browser. It stays valid until revoked on the server. */
  signOut: () => void;
}

/** Outside a provider (tests of one screen): nobody known, nothing to gate. */
const NOBODY: Auth = {
  status: "ready",
  principal: null,
  reason: null,
  session: 0,
  signIn: async () => {},
  signOut: () => {},
};

export const AuthContext = createContext<Auth>(NOBODY);

export function useAuth(): Auth {
  return useContext(AuthContext);
}

/**
 * Whether to OFFER an admin control. Only a key known to be a viewer is
 * refused; an unknown role is offered and the server has the last word.
 */
export function canAdmin(principal: Principal | null): boolean {
  return principal?.role !== "viewer";
}

/** The sentence a disabled admin control carries. */
export const NEEDS_ADMIN = "Needs an admin key: this key is a viewer (ADR-0035).";

export function useAuthState(): Auth {
  const [status, setStatus] = useState<AuthStatus>(() => (getToken() ? "checking" : "ready"));
  const [principal, setPrincipal] = useState<Principal | null>(null);
  const [reason, setReason] = useState<string | null>(null);
  const [session, setSession] = useState(0);

  useEffect(
    () =>
      onUnauthorized((detail) => {
        setPrincipal(null);
        setReason(detail);
        setStatus("required");
      }),
    [],
  );

  useEffect(() => {
    if (!getToken()) return;
    let live = true;
    whoami()
      .then((who) => {
        if (!live) return;
        setPrincipal(who);
        setStatus("ready");
      })
      .catch(() => {
        // A 401 already moved us to "required" through the listener. Any
        // other failure (a server that is down) is the console's to show.
        if (live) setStatus((current) => (current === "checking" ? "ready" : current));
      });
    return () => {
      live = false;
    };
  }, []);

  const signIn = useCallback(async (token: string) => {
    const who = await whoami(token);
    setToken(token);
    setPrincipal(who);
    setReason(null);
    setStatus("ready");
    setSession((count) => count + 1);
  }, []);

  const signOut = useCallback(() => {
    setToken(null);
    setPrincipal(null);
    setReason("Signed out. Enter an API key to continue.");
    setStatus("required");
  }, []);

  return { status, principal, reason, session, signIn, signOut };
}
