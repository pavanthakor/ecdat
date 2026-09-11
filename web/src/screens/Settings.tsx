/**
 * SETTINGS -- what this console is connected to, and with which key.
 * Read-only: nothing here is configurable from the browser, and the screen
 * says so rather than offering controls that change nothing. (No design
 * screenshot exists for this screen; it uses the same card language as the
 * rest, ADR-0032.)
 */
import { API_BASE, TOKEN_STORAGE_KEY } from "@/api/client";
import type { Artefact, ScanSummary } from "@/api/types";
import { Panel, ScreenHeader, Tag } from "@/components/Panel";
import { useAuth } from "@/state/auth";
import { engineLine } from "@/state/presentation";

function Row({ label, value }: { label: string; value: React.ReactNode }) {
  return (
    <div className="grid grid-cols-[10rem_1fr] gap-3 border-t border-line py-2 first:border-t-0">
      <dt className="text-[10px] font-semibold uppercase tracking-wider text-ink-faint">{label}</dt>
      <dd className="text-[12.5px] text-ink-dim">{value}</dd>
    </div>
  );
}

const ROLE_MEANS: Record<string, string> = {
  admin: "admin — reads everything, runs scans and fix passes, reads verified patches",
  viewer: "viewer — reads everything except verified patches; scans and fixes need an admin key",
};

export function SettingsScreen({ scan, artefacts }: { scan: ScanSummary | null; artefacts: Artefact[] }) {
  const { principal } = useAuth();
  const engine = scan ? engineLine(scan, artefacts) : null;
  return (
    <div>
      <ScreenHeader
        title="Settings"
        subtitle="What this console is connected to, with which key, and how it was built. Nothing here is editable from the browser."
      />
      <div className="grid gap-4 px-6 pb-6 xl:grid-cols-2">
        <Panel eyebrow="Build" title="Console" bodyClassName="pt-2">
          <dl>
            <Row label="API" value={<code className="font-mono">{API_BASE}</code>} />
            <Row label="Origin" value="same-origin only — no configurable base URL" />
            <Row label="Build" value="static bundle served by FastAPI from web/dist; no Node at runtime" />
            <Row label="Fonts" value="Inter + JetBrains Mono, self-hosted; no CDN" />
            <Row label="Routing" value="hash routes (#/…), so no path can collide with the API" />
          </dl>
        </Panel>
        <Panel eyebrow="Access" title="Authentication" bodyClassName="pt-2">
          <dl>
            <Row label="Scheme" value={<Tag variant="verified">API key · bearer (ADR-0035)</Tag>} />
            <Row label="Key" value={principal ? principal.name : "not known — the server has not said whose key this is"} />
            <Row label="Role" value={principal ? (ROLE_MEANS[principal.role] ?? principal.role) : "not known"} />
            <Row
              label="Check"
              value="on the server, against its key file: the SHA-256 digest of the key is compared with each issued one. No identity provider, no network call."
            />
            <Row
              label="Kept"
              value={
                <>
                  in this browser's local storage (<code className="font-mono">{TOKEN_STORAGE_KEY}</code>) until you
                  sign out; revoking it is <code className="font-mono">ecdat api-key revoke</code> on the server
                </>
              }
            />
          </dl>
        </Panel>
        <Panel eyebrow="Selected scan" title="Scoring context" bodyClassName="pt-2">
          {scan ? (
            <dl>
              <Row label="Scan" value={<code className="font-mono">{scan.id}</code>} />
              <Row label="Sector" value={scan.sector ?? "not recorded"} />
              <Row label="Exposure" value={scan.exposure ?? "not recorded"} />
              <Row label="Data class" value={scan.target.data_class ?? "not recorded"} />
              <Row label="Stored horizon" value={scan.z_years === null ? "not recorded" : `${scan.z_years} years`} />
            </dl>
          ) : (
            <p className="text-[12px] text-ink-faint">No scan selected.</p>
          )}
        </Panel>
        <Panel eyebrow="Provenance" title="Engines" bodyClassName="pt-2">
          {engine ? (
            <dl>
              {engine.parts.map((part) => (
                <Row key={part} label="·" value={<code className="font-mono">{part}</code>} />
              ))}
              {engine.warning ? <Row label="Warning" value={engine.warning} /> : null}
            </dl>
          ) : (
            <p className="text-[12px] text-ink-faint">No scan selected.</p>
          )}
        </Panel>
      </div>
    </div>
  );
}
