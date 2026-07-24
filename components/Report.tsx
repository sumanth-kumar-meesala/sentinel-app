"use client";
import { Report, Finding, Severity } from "@/lib/types";

const SEV_ORDER: Severity[] = ["critical", "high", "medium", "low", "info", "clean"];
const SEV_VAR: Record<Severity, string> = {
  critical: "var(--sev-critical)",
  high: "var(--sev-high)",
  medium: "var(--sev-medium)",
  low: "var(--sev-low)",
  info: "var(--sev-info)",
  clean: "var(--sev-clean)",
};
const rank = (f: Finding) => SEV_ORDER.indexOf(f.severity);

// Deterministic UTC format — locale/timezone-independent so SSR and client match
// (toLocaleString() differs by environment and causes hydration mismatches).
function fmtDate(iso: string): string {
  const d = new Date(iso);
  const p = (n: number) => String(n).padStart(2, "0");
  return `${d.getUTCFullYear()}-${p(d.getUTCMonth() + 1)}-${p(d.getUTCDate())} ${p(d.getUTCHours())}:${p(d.getUTCMinutes())} UTC`;
}

function riskProfile(findings: Finding[]) {
  const actionable = findings.filter((f) => !["clean", "info"].includes(f.severity));
  const worst = actionable.sort((a, b) => rank(a) - rank(b))[0]?.severity ?? "clean";
  const map: Record<string, { pct: number; label: string; sev: Severity }> = {
    critical: { pct: 96, label: "Critical", sev: "critical" },
    high: { pct: 82, label: "High", sev: "high" },
    medium: { pct: 56, label: "Medium", sev: "medium" },
    low: { pct: 32, label: "Low", sev: "low" },
    clean: { pct: 10, label: "Minimal", sev: "clean" },
  };
  return map[worst] ?? map.clean;
}

function exportPdf(runId: string) {
  const theme = document.documentElement.getAttribute("data-theme") || "sentinel";
  const a = document.createElement("a");
  a.href = `/api/report/${runId}/pdf?theme=${encodeURIComponent(theme)}`;
  a.rel = "noopener";
  a.click();
}

export default function ReportView({ report, printMode = false }: { report: Report; printMode?: boolean }) {
  const findings = [...report.findings].sort((a, b) => rank(a) - rank(b));
  const risk = riskProfile(findings);
  const counts = SEV_ORDER.map((s) => ({ s, n: findings.filter((f) => f.severity === s).length })).filter((c) => c.n > 0);

  const tiles = [
    { label: "Stealer records", value: report.stats.stealerRecords ?? 0, accent: Number(report.stats.stealerRecords) > 0 },
    { label: "Live hosts", value: report.stats.liveHosts ?? "—", sub: `${report.stats.subdomains ?? report.subdomains.length} found` },
    { label: "Typosquats", value: report.stats.lookalikeDomains ?? "—", accent: Number(report.stats.lookalikeDomains) > 0 },
    { label: "Open buckets", value: report.stats.openBuckets ?? "—", accent: Number(report.stats.openBuckets) > 0 },
    { label: "Emails exposed", value: report.stats.emailsExposed ?? report.emails.length },
    { label: "Vulns (active)", value: report.verified ? report.stats.vulnFindings ?? 0 : "—", accent: Number(report.stats.vulnFindings) > 0 },
  ];

  return (
    <div className={`print-area panel overflow-hidden ${printMode ? "" : "rise"}`}>
      {/* header */}
      <div className="flex items-start justify-between flex-wrap gap-3 px-6 pt-6">
        <div>
          <p className="eyebrow">Exposure report</p>
          <h2 className="text-2xl font-semibold tracking-tight mt-1 mono">{report.domain}</h2>
          <p className="text-xs opacity-60 mt-1 font-mono">
            {fmtDate(report.startedAt)} · {report.verified ? "verified" : "unverified · passive"} · {report.runId}
          </p>
        </div>
        {!printMode && (
          <div className="flex gap-2">
            <button
              className="btn btn-sm border-0 gap-1.5 bg-[color:var(--color-primary)] text-[color:var(--color-primary-content)] hover:brightness-110"
              onClick={() => exportPdf(report.runId)}
            >
              <DownloadIcon /> PDF
            </button>
            <a className="btn btn-sm gap-1.5 border hairline bg-transparent hover:bg-base-content/5 text-[color:var(--color-base-content)]" href={`/api/evidence/${report.runId}`}>
              <ArchiveIcon /> Evidence
            </a>
          </div>
        )}
      </div>

      {/* risk banner */}
      <div className="px-6 py-6 mt-4 flex items-center gap-6 flex-wrap border-y hairline" style={{ background: "color-mix(in oklab, var(--color-base-200) 60%, transparent)" }}>
        <div className="relative w-28 h-28 shrink-0">
          <div className="risk-ring w-full h-full" style={{ ["--pct" as string]: risk.pct, ["--sev" as string]: SEV_VAR[risk.sev] }} />
          <div className="absolute inset-0 flex flex-col items-center justify-center">
            <span className="text-2xl font-semibold" style={{ color: SEV_VAR[risk.sev] }}>{risk.label}</span>
            <span className="eyebrow mt-0.5">risk</span>
          </div>
        </div>
        <div className="flex-1 min-w-[16rem]">
          <p className="text-lg font-medium leading-snug">
            {report.stats.stealerRecords
              ? <>{report.stats.stealerRecords} credential set(s) stolen by infostealer malware — the dominant risk.</>
              : <>No stolen credentials found for this domain.</>}
          </p>
          <div className="flex gap-2 mt-3 flex-wrap">
            {counts.map((c) => (
              <span key={c.s} className="sev-chip" style={{ ["--sev" as string]: SEV_VAR[c.s] }}>{c.n} {c.s}</span>
            ))}
          </div>
        </div>
      </div>

      {/* KPI tiles */}
      <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 border-b hairline">
        {tiles.map((t, i) => (
          <div key={t.label} className={`px-5 py-4 border-hairline ${i % 2 === 0 ? "border-r" : "lg:border-r"} ${i < 3 ? "border-b lg:border-b-0" : ""}`} style={{ borderColor: "var(--hairline)" }}>
            <div className="text-2xl font-semibold tracking-tight" style={{ color: t.accent ? "var(--sev-high)" : "var(--color-base-content)" }}>{t.value}</div>
            <div className="eyebrow mt-1" style={{ letterSpacing: "0.1em" }}>{t.label}</div>
            {t.sub && <div className="text-[0.62rem] text-[color:var(--color-secondary)] mono mt-0.5">{t.sub}</div>}
          </div>
        ))}
      </div>

      {/* findings */}
      <div className="px-6 py-6">
        <p className="eyebrow mb-3">Findings · {findings.length}</p>
        <div className="flex flex-col gap-2.5">
          {findings.map((f) => (
            <div key={f.id} className={`finding-card sev-${f.severity} p-4`}>
              <div className="flex items-start gap-3">
                <span className="sev-chip mt-0.5">{f.severity}</span>
                <div className="flex-1 min-w-0">
                  <div className="font-medium">{f.title}</div>
                  <p className="text-sm opacity-75 mt-1 leading-relaxed">{f.detail}</p>
                  {f.evidence && (
                    <pre className={`evidence mono text-[0.7rem] mt-2 p-3 rounded whitespace-pre-wrap text-[color:var(--color-base-content)]/85 ${printMode ? "" : "max-h-56 overflow-auto"}`}>
                      {f.evidence}
                    </pre>
                  )}
                </div>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* data appendices — full, expanded, stacked (no accordions, no scroll clipping) */}
      {report.subdomains.length > 0 && <DataSection title="Subdomains" count={report.subdomains.length} items={report.subdomains} />}
      {report.emails.length > 0 && <DataSection title="Exposed emails" count={report.emails.length} items={report.emails} />}

      {/* footer: tools + evidence */}
      <div className="px-6 py-5 border-t hairline grid sm:grid-cols-2 gap-5" style={{ background: "color-mix(in oklab, var(--color-base-200) 50%, transparent)" }}>
        <div>
          <p className="eyebrow mb-2">Tools</p>
          <div className="flex flex-wrap gap-1.5">
            {report.toolStatus.map((t) => (
              <span key={t.tool} className="font-mono text-[0.68rem] px-2 py-0.5 rounded border hairline flex items-center gap-1.5"
                style={{ color: t.available ? "var(--color-base-content)" : "var(--color-secondary)" }}>
                <span className="w-1.5 h-1.5 rounded-full" style={{ background: t.available ? "var(--color-success)" : "var(--color-secondary)" }} />
                {t.tool}
              </span>
            ))}
          </div>
        </div>
        <div>
          <p className="eyebrow mb-2">Evidence files</p>
          <div className="font-mono text-[0.68rem] text-[color:var(--color-secondary)] flex flex-wrap gap-x-3 gap-y-0.5">
            {report.evidenceFiles.map((e) => <span key={e}>{e}</span>)}
          </div>
        </div>
      </div>
      <p className="px-6 py-3 text-[0.68rem] text-[color:var(--color-secondary)] border-t hairline">
        Passive OSINT{report.verified ? " + authorized active scan" : ""}. Point-in-time snapshot; not a penetration test. Raw output in the evidence archive.
      </p>
    </div>
  );
}

function DataSection({ title, count, items }: { title: string; count: number; items: string[] }) {
  return (
    <div className="px-6 py-5 border-t hairline">
      <p className="eyebrow mb-3">{title} · {count}</p>
      <div className="mono text-[0.7rem] leading-relaxed columns-2 sm:columns-3 lg:columns-4 gap-x-6 text-[color:var(--color-base-content)]/80">
        {items.map((s) => (
          <div key={s} className="break-all py-px" style={{ breakInside: "avoid" }}>{s}</div>
        ))}
      </div>
    </div>
  );
}

function DownloadIcon() {
  return (
    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" aria-hidden>
      <path d="M12 3v12m0 0l-4-4m4 4l4-4M4 17v2a2 2 0 002 2h12a2 2 0 002-2v-2" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  );
}
function ArchiveIcon() {
  return (
    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" aria-hidden>
      <path d="M3 7l1.5-2.5A2 2 0 016.2 3.5h11.6a2 2 0 011.7 1L21 7M4 7h16v11a2 2 0 01-2 2H6a2 2 0 01-2-2V7zM9.5 11h5" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  );
}
