/**
 * SETTINGS -- what this console is connected to. Read-only: nothing here is
 * configurable from the browser yet, and the screen says so rather than
 * offering controls that change nothing. (No design screenshot exists for this
 * screen; it uses the same card language as the rest, ADR-0032.)
 */
import { API_BASE } from "@/api/client";
import type { Artefact, ScanSummary } from "@/api/types";
import { Panel, ScreenHeader, Tag } from "@/components/Panel";
import { engineLine } from "@/state/presentation";

function Row({ label, value }: { label: string; value: React.ReactNode }) {
  return (
    <div className="grid grid-cols-[10rem_1fr] gap-3 border-t border-line py-2 first:border-t-0">
      <dt className="text-[10px] font-semibold uppercase tracking-wider text-ink-faint">{label}</dt>
      <dd className="text-[12.5px] text-ink-dim">{value}</dd>
    </div>
  );
}

export function SettingsScreen({ scan, artefacts }: { scan: ScanSummary | null; artefacts: Artefact[] }) {
  const engine = scan ? engineLine(scan, artefacts) : null;
  return (
    <div>
      <ScreenHeader
        title="Settings"
        subtitle="What this console is connected to and how it was built. Nothing here is editable from the browser yet."
      />
      <div className="grid gap-4 px-6 pb-6 xl:grid-cols-2">
        <Panel eyebrow="Build" title="Console" bodyClassName="pt-2">
          <dl>
            <Row label="API" value={<code className="font-mono">{API_BASE}</code>} />
            <Row label="Origin" value="same-origin only — no configurable base URL" />
            <Row label="Build" value="static bundle served by FastAPI from web/dist; no Node at runtime" />
            <Row label="Fonts" value="Space Grotesk + JetBrains Mono, self-hosted; no CDN" />
            <Row label="Routing" value="hash routes (#/…), so no path can collide with the API" />
          </dl>
        </Panel>
        <Panel eyebrow="Access" title="Authentication" bodyClassName="pt-2">
          <dl>
            <Row label="Status" value={<Tag variant="provisional">Not configured</Tag>} />
            <Row label="User menu" value="cosmetic until the Tier-3 authentication work lands; every entry is disabled" />
            <Row
              label="Exposure"
              value="the API serves this inventory and its verified fix diffs unauthenticated on localhost (PUNCHLIST)"
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
