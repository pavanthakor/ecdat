/**
 * The sign-in gate (ADR-0035).
 *
 * Shown when -- and only when -- the server refuses the console. The server's
 * reason is shown as it gave it; a key is checked with `GET /auth/whoami`
 * before it is kept, and a refused key is never stored.
 */
import { KeyRound } from "lucide-react";
import { useState, type FormEvent } from "react";

import { ApiError } from "@/api/client";
import { Button } from "./Panel";

export function SignIn({
  reason,
  onSignIn,
}: {
  reason: string | null;
  onSignIn: (token: string) => Promise<void>;
}) {
  const [key, setKey] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function submit(event: FormEvent) {
    event.preventDefault();
    const candidate = key.trim();
    if (!candidate) return;
    setBusy(true);
    setError(null);
    try {
      await onSignIn(candidate);
      // Accepted: the gate unmounts, so no state is touched after this.
    } catch (cause) {
      setError(cause instanceof ApiError ? cause.detail : cause instanceof Error ? cause.message : String(cause));
      setBusy(false);
    }
  }

  return (
    <div className="flex h-full items-center justify-center bg-ground px-6 text-ink">
      <form
        onSubmit={submit}
        aria-labelledby="sign-in-title"
        className="w-full max-w-md rounded-lg border border-line bg-panel p-6"
      >
        <div className="flex items-center gap-2.5">
          <span className="flex h-8 w-8 items-center justify-center rounded-md border border-line text-ink-dim">
            <KeyRound className="h-4 w-4" aria-hidden />
          </span>
          <h1 id="sign-in-title" className="text-[17px] font-semibold">
            Sign in to ECDAT
          </h1>
        </div>

        {reason ? (
          <p data-testid="sign-in-reason" className="mt-4 border-l-2 border-line pl-3 text-[12px] leading-relaxed text-ink-dim">
            The server said: {reason}
          </p>
        ) : null}

        <label className="mt-4 block">
          <span className="eyebrow">API key</span>
          <input
            type="password"
            required
            autoComplete="off"
            spellCheck={false}
            value={key}
            onChange={(event) => setKey(event.target.value)}
            placeholder="ecdat_…"
            className="mt-1 h-9 w-full rounded-md border border-line bg-ground px-2.5 font-mono text-[13px] text-ink placeholder:text-ink-faint focus:border-ink-faint focus:outline-none"
          />
        </label>

        {error ? (
          <p role="alert" className="mt-2 border border-critical/40 bg-critical/10 px-2 py-1.5 text-2xs text-critical">
            {error}
          </p>
        ) : null}

        <div className="mt-4 flex justify-end">
          <Button type="submit" variant="primary" disabled={busy}>
            {busy ? "Checking…" : "Sign in"}
          </Button>
        </div>

        <p className="mt-5 border-t border-line pt-3 text-[11px] leading-relaxed text-ink-faint">
          Keys are issued on the server:{" "}
          <code className="font-mono text-ink-dim">ecdat api-key create --name &lt;who&gt; --role viewer|admin</code>.
          The server checks a key against its own key file, with no identity provider and no network call. This
          browser keeps the key in local storage until you sign out.
        </p>
      </form>
    </div>
  );
}
