/**
 * The sign-in gate and roles (ADR-0035), driven through the real <App />.
 *
 * The console asks for a key when -- and only when -- the SERVER refuses it:
 * the server is the one that decides, so the console never guesses. A key is
 * checked with `GET /auth/whoami` before it is stored, rides on every request
 * after, and "Sign out" forgets it. A viewer key is told plainly what it
 * cannot do rather than shown a button that 403s.
 */
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import z11Doc from "@/test/fixtures/cbom_z11.json";
import scansDoc from "@/test/fixtures/scans.json";

import App from "@/App";
import { TOKEN_STORAGE_KEY } from "@/api/client";

/** The server's key file, as far as this test is concerned. */
const KEYS: Record<string, { name: string; role: "viewer" | "admin" }> = {
  "good-admin-key": { name: "ops", role: "admin" },
  "good-viewer-key": { name: "auditor", role: "viewer" },
};

const json = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status });

let calls: { url: string; auth: string | null }[] = [];

function server() {
  calls = [];
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      const auth = new Headers(init?.headers).get("Authorization");
      calls.push({ url, auth });
      const who = KEYS[auth?.replace(/^Bearer /, "") ?? ""];
      if (!who) {
        return json(
          {
            detail: auth
              ? "invalid credential: no configured key matches"
              : "missing credential: send `Authorization: Bearer <api key>`",
          },
          401,
        );
      }
      const path = url.split("?")[0];
      if (path.endsWith("/api/auth/whoami")) return json(who);
      if (path.endsWith("/api/scans")) {
        return json({ items: scansDoc, total: scansDoc.length, limit: 50, offset: 0 });
      }
      if (path.endsWith("/cbom")) return json(z11Doc);
      if (path.endsWith("/api/scanners")) return json(["source"]);
      return json({}, 404);
    }),
  );
}

const OVERVIEW = { name: "Cryptographic Security Overview" };

beforeEach(() => {
  localStorage.clear();
  window.location.hash = "#/overview";
  server();
});

afterEach(() => {
  vi.unstubAllGlobals();
  localStorage.clear();
  window.location.hash = "";
});

describe("the sign-in gate", () => {
  it("with no key, the server's 401 brings up the sign-in form -- with the server's reason", async () => {
    render(<App />);

    expect(await screen.findByRole("heading", { name: /sign in/i })).toBeInTheDocument();
    expect(screen.getByText(/missing credential/i)).toBeInTheDocument();
    expect(screen.getByText(/ecdat api-key create/)).toBeInTheDocument();
  });

  it("a key is verified before it is stored, and the console then loads WITH it", async () => {
    render(<App />);

    await userEvent.type(await screen.findByLabelText(/api key/i), "good-admin-key");
    await userEvent.click(screen.getByRole("button", { name: /sign in/i }));

    expect(await screen.findByRole("heading", OVERVIEW)).toBeInTheDocument();
    expect(localStorage.getItem(TOKEN_STORAGE_KEY)).toBe("good-admin-key");
    const since = calls.slice(calls.findIndex((call) => call.url.endsWith("/api/auth/whoami")));
    expect(since.some((call) => call.url.split("?")[0].endsWith("/api/scans"))).toBe(true);
    expect(since.every((call) => call.auth === "Bearer good-admin-key")).toBe(true);
  });

  it("a wrong key is refused on the form and never stored", async () => {
    render(<App />);

    await userEvent.type(await screen.findByLabelText(/api key/i), "not-a-key");
    await userEvent.click(screen.getByRole("button", { name: /sign in/i }));

    expect(await screen.findByRole("alert")).toHaveTextContent(/invalid credential/i);
    expect(localStorage.getItem(TOKEN_STORAGE_KEY)).toBeNull();
    expect(screen.getByRole("heading", { name: /sign in/i })).toBeInTheDocument();
  });

  it("a stored key goes straight to the console, and the user menu names the key and its role", async () => {
    localStorage.setItem(TOKEN_STORAGE_KEY, "good-admin-key");
    render(<App />);

    expect(await screen.findByRole("heading", OVERVIEW)).toBeInTheDocument();
    const trigger = screen.getByRole("button", { name: /user menu/i });
    expect(trigger).toHaveTextContent("ops");
    expect(trigger).toHaveTextContent(/admin/i);
  });

  it("Sign out forgets the key and returns to the gate", async () => {
    localStorage.setItem(TOKEN_STORAGE_KEY, "good-admin-key");
    render(<App />);

    await userEvent.click(await screen.findByRole("button", { name: /user menu/i }));
    await userEvent.click(screen.getByRole("menuitem", { name: /sign out/i }));

    expect(await screen.findByRole("heading", { name: /sign in/i })).toBeInTheDocument();
    expect(localStorage.getItem(TOKEN_STORAGE_KEY)).toBeNull();
  });

  it("a stored key the server no longer accepts lands on the gate, not a broken console", async () => {
    localStorage.setItem(TOKEN_STORAGE_KEY, "revoked-key");
    render(<App />);

    expect(await screen.findByRole("heading", { name: /sign in/i })).toBeInTheDocument();
    expect(screen.getByText(/invalid credential/i)).toBeInTheDocument();
  });
});

describe("roles in the console", () => {
  it("a viewer cannot start a scan: New scan is disabled, and says it needs an admin key", async () => {
    localStorage.setItem(TOKEN_STORAGE_KEY, "good-viewer-key");
    window.location.hash = "#/scans";
    render(<App />);

    const button = await screen.findByRole("button", { name: /new scan/i });
    await waitFor(() => expect(button).toBeDisabled());
    expect(button.getAttribute("title")).toMatch(/admin key/i);
  });

  it("a viewer is told verified fixes need an admin key -- and the console does not ask for them", async () => {
    localStorage.setItem(TOKEN_STORAGE_KEY, "good-viewer-key");
    window.location.hash = "#/fixes";
    render(<App />);

    expect(await screen.findByText(/need an admin key/i)).toBeInTheDocument();
    expect(calls.some((call) => call.url.includes("/fixes"))).toBe(false);
  });

  it("an admin sees New scan enabled", async () => {
    localStorage.setItem(TOKEN_STORAGE_KEY, "good-admin-key");
    window.location.hash = "#/scans";
    render(<App />);

    expect(await screen.findByRole("button", { name: /new scan/i })).toBeEnabled();
  });
});
