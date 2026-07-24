import { Report, Finding, Severity } from "@/lib/types";

/* A print-first report DOCUMENT (not the UI). Themed via data-theme, paginated
   with real page breaks, charts + metrics + narrative + recommendations. */

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

function fmtDate(iso: string): string {
  const d = new Date(iso);
  const p = (n: number) => String(n).padStart(2, "0");
  return `${d.getUTCFullYear()}-${p(d.getUTCMonth() + 1)}-${p(d.getUTCDate())} ${p(d.getUTCHours())}:${p(d.getUTCMinutes())} UTC`;
}

function riskProfile(findings: Finding[]) {
  const actionable = findings.filter((f) => !["clean", "info"].includes(f.severity));
  const worst = actionable.sort((a, b) => rank(a) - rank(b))[0]?.severity ?? "clean";
  const map: Record<string, { pct: number; label: string; sev: Severity; blurb: string }> = {
    critical: { pct: 96, label: "Critical", sev: "critical", blurb: "Immediate action required." },
    high: { pct: 82, label: "High", sev: "high", blurb: "Urgent remediation recommended." },
    medium: { pct: 56, label: "Medium", sev: "medium", blurb: "Address in the near term." },
    low: { pct: 32, label: "Low", sev: "low", blurb: "Monitor and harden." },
    clean: { pct: 12, label: "Minimal", sev: "clean", blurb: "No material exposure found." },
  };
  return map[worst] ?? map.clean;
}

// Heuristic subdomain buckets for the attack-surface chart.
function categorize(subs: string[]) {
  const c: Record<string, number> = { "App / web": 0, "Staging / dev": 0, "Admin / internal": 0, "Ad-tech / tags": 0, "CDN / infra": 0 };
  for (const h of subs) {
    if (/(^|[.-])(staging|stage|beta|test|uat|demo|dev)([.-]|$)/.test(h)) c["Staging / dev"]++;
    else if (/(adpatch|adevent|admin|\boms\b|\bcrm\b|auth|central|publisher|internal|jenkins|vpn|hr|reports)/.test(h)) c["Admin / internal"]++;
    else if (/(tags|-pl\b|\bpl\b|rtb|push|\btig\b|\btr\b|cmt|cmr|pixel)/.test(h)) c["Ad-tech / tags"]++;
    else if (/(cdn|serv\d|ssl|\baws\b|ftp|ns\d|imap|smtp|mx)/.test(h)) c["CDN / infra"]++;
    else c["App / web"]++;
  }
  return Object.entries(c).filter(([, n]) => n > 0).sort((a, b) => b[1] - a[1]);
}

function recommendations(report: Report): { sev: Severity; text: string }[] {
  const r: { sev: Severity; text: string }[] = [];
  const s = report.stats;
  if (Number(s.stealerRecords) > 0)
    r.push({ sev: "high", text: `Force-reset passwords and enforce MFA on every exposed login; treat all ${s.stealerRecords} malware-stolen credential sets as compromised. Retrieve the plaintext by verifying domain ownership with Hudson Rock or HaveIBeenPwned.` });
  if (report.findings.some((f) => /VERIFIED live secret/i.test(f.title)))
    r.push({ sev: "critical", text: "Rotate the live secrets found in public code immediately, then invalidate any derived tokens." });
  if (Number(s.openBuckets) > 0)
    r.push({ sev: "high", text: `Lock down the ${s.openBuckets} publicly-listable cloud bucket(s); review ACLs and remove anything not intended to be public.` });
  if (Number(s.vulnFindings) > 0)
    r.push({ sev: "medium", text: `Remediate the ${s.vulnFindings} issue(s) surfaced by the active vulnerability scan, prioritising by severity.` });
  if (Number(s.lookalikeDomains) > 0)
    r.push({ sev: "medium", text: `Monitor and pursue takedown of the ${s.lookalikeDomains} registered look-alike domain(s); brief staff and customers on phishing from these.` });
  if (report.findings.some((f) => /dangling|takeover/i.test(f.title)))
    r.push({ sev: "medium", text: "Reclaim or delete dangling DNS records pointing at unclaimed third-party services before they can be taken over." });
  if (report.subdomains.length > 30)
    r.push({ sev: "low", text: `Reduce the ${report.subdomains.length}-host attack surface — retire stale staging/dev subdomains and decommission unused services.` });
  r.push({ sev: "low", text: "Establish continuous monitoring (secret scanning, breach lookups, subdomain enumeration) so new exposure is caught early." });
  return r;
}

export default function ReportDoc({ report }: { report: Report }) {
  const findings = [...report.findings].sort((a, b) => rank(a) - rank(b));
  const risk = riskProfile(findings);
  const sevCounts = SEV_ORDER.map((s) => ({ s, n: findings.filter((f) => f.severity === s).length })).filter((c) => c.n > 0);
  const cats = categorize(report.subdomains);
  const live = Number(report.stats.liveHosts) || 0;
  const total = report.subdomains.length;
  const recs = recommendations(report);

  const tiles = [
    { label: "Stealer records", value: report.stats.stealerRecords ?? 0, sev: Number(report.stats.stealerRecords) > 0 ? "high" : "clean" },
    { label: "Live hosts", value: live || "—", sub: `${total} discovered` },
    { label: "Typosquats", value: report.stats.lookalikeDomains ?? "—", sev: Number(report.stats.lookalikeDomains) > 0 ? "medium" : "clean" },
    { label: "Open buckets", value: report.stats.openBuckets ?? "—", sev: Number(report.stats.openBuckets) > 0 ? "high" : "clean" },
    { label: "Emails exposed", value: report.stats.emailsExposed ?? report.emails.length },
    { label: "Active vulns", value: report.verified ? report.stats.vulnFindings ?? 0 : "n/a", sev: Number(report.stats.vulnFindings) > 0 ? "high" : "clean" },
  ] as { label: string; value: number | string; sub?: string; sev?: string }[];

  const avoid = { breakInside: "avoid" as const };

  return (
    <div className="doc" style={{ color: "var(--color-base-content)" }}>
      {/* ============ COVER / EXECUTIVE SUMMARY ============ */}
      <header style={{ ...avoid }} className="pb-5 mb-6 border-b" >
        <div className="flex items-center gap-2 mb-4">
          <ShieldGlyph />
          <span className="mono text-sm font-semibold tracking-tight">SENTINEL</span>
          <span className="eyebrow ml-1">Exposure Engine</span>
        </div>
        <p className="eyebrow">Domain exposure assessment</p>
        <h1 className="mono text-4xl font-bold tracking-tight mt-1">{report.domain}</h1>
        <p className="text-sm mt-2 opacity-60 mono">
          {fmtDate(report.startedAt)} &nbsp;·&nbsp; {report.verified ? "domain-verified" : "unverified · passive OSINT"} &nbsp;·&nbsp; run {report.runId}
        </p>
      </header>

      <section className="grid grid-cols-[auto_1fr] gap-8 items-center mb-7" style={avoid}>
        <RiskGauge pct={risk.pct} label={risk.label} color={SEV_VAR[risk.sev]} />
        <div>
          <p className="eyebrow mb-1">Overall risk</p>
          <p className="text-xl font-semibold leading-snug">
            {report.stats.stealerRecords
              ? <>{report.stats.stealerRecords} credential sets stolen by infostealer malware — the dominant risk.</>
              : <>No stolen credentials found for this domain.</>}
          </p>
          <p className="text-sm opacity-70 mt-1">{risk.blurb} {findings.length} findings across {report.toolStatus.filter((t) => t.available).length} tools.</p>
          <div className="flex gap-2 mt-3 flex-wrap">
            {sevCounts.map((c) => (
              <span key={c.s} className="sev-chip" style={{ ["--sev" as string]: SEV_VAR[c.s] }}>{c.n} {c.s}</span>
            ))}
          </div>
        </div>
      </section>

      {/* metrics */}
      <section className="grid grid-cols-3 gap-px mb-7 rounded overflow-hidden" style={{ ...avoid, background: "var(--hairline)" }}>
        {tiles.map((t) => (
          <div key={t.label} className="p-4" style={{ background: "var(--color-base-100)" }}>
            <div className="text-2xl font-semibold" style={{ color: t.sev && t.sev !== "clean" ? SEV_VAR[t.sev as Severity] : "var(--color-base-content)" }}>{t.value}</div>
            <div className="eyebrow mt-1">{t.label}</div>
            {t.sub && <div className="text-[0.62rem] opacity-50 mono mt-0.5">{t.sub}</div>}
          </div>
        ))}
      </section>

      {/* charts */}
      <section className="grid grid-cols-2 gap-8 mb-2" style={avoid}>
        <div>
          <p className="eyebrow mb-3">Findings by severity</p>
          <BarList rows={sevCounts.map((c) => ({ label: c.s, value: c.n, color: SEV_VAR[c.s] }))} />
        </div>
        <div>
          <p className="eyebrow mb-3">Attack surface · {total} subdomains</p>
          {cats.length ? (
            <BarList rows={cats.map(([label, n]) => ({ label, value: n, color: "var(--color-primary)" }))} />
          ) : (
            <p className="text-sm opacity-60">No subdomains enumerated.</p>
          )}
          {total > 0 && (
            <div className="mt-4">
              <div className="flex justify-between text-[0.7rem] opacity-70 mb-1"><span>Live hosts</span><span>{live} / {total}</span></div>
              <div className="h-2.5 rounded-full overflow-hidden" style={{ background: "color-mix(in oklab, var(--color-base-content) 8%, transparent)" }}>
                <div className="h-full rounded-full" style={{ width: `${total ? (live / total) * 100 : 0}%`, background: "var(--color-primary)" }} />
              </div>
            </div>
          )}
        </div>
      </section>

      {/* ============ FINDINGS ============ */}
      <section style={{ breakBefore: "page" }}>
        <h2 className="text-lg font-semibold mb-1">Findings</h2>
        <p className="text-sm opacity-60 mb-4">Ranked by severity. Each includes supporting evidence captured during the scan.</p>
        <div className="flex flex-col gap-3">
          {findings.map((f) => (
            <div key={f.id} className={`finding-card sev-${f.severity} p-4`} style={avoid}>
              <div className="flex items-start gap-3">
                <span className="sev-chip mt-0.5">{f.severity}</span>
                <div className="flex-1 min-w-0">
                  <div className="font-semibold">{f.title}</div>
                  <p className="text-sm opacity-75 mt-1 leading-relaxed">{f.detail}</p>
                  {f.evidence && (
                    <pre className="evidence mono text-[0.68rem] mt-2 p-3 rounded whitespace-pre-wrap" style={{ color: "color-mix(in oklab, var(--color-base-content) 85%, transparent)" }}>
                      {f.evidence}
                    </pre>
                  )}
                </div>
              </div>
            </div>
          ))}
        </div>
      </section>

      {/* ============ RECOMMENDATIONS ============ */}
      <section style={{ breakBefore: "page" }}>
        <h2 className="text-lg font-semibold mb-1">Recommendations</h2>
        <p className="text-sm opacity-60 mb-4">Prioritised remediation steps derived from the findings above.</p>
        <ol className="flex flex-col gap-2.5">
          {recs.map((rec, i) => (
            <li key={i} className="flex items-start gap-3 p-3 rounded border" style={{ ...avoid, borderColor: "var(--hairline)", background: "var(--color-base-100)" }}>
              <span className="sev-chip mt-0.5 self-start" style={{ ["--sev" as string]: SEV_VAR[rec.sev] }}>{rec.sev}</span>
              <span className="text-sm leading-relaxed flex-1">{rec.text}</span>
            </li>
          ))}
        </ol>
      </section>

      {/* ============ APPENDICES ============ */}
      {report.subdomains.length > 0 && (
        <section style={{ breakBefore: "page" }}>
          <h2 className="text-lg font-semibold mb-3">Appendix A · Subdomains ({report.subdomains.length})</h2>
          <ColumnList items={report.subdomains} />
        </section>
      )}
      {report.emails.length > 0 && (
        <section className="mt-6" style={avoid}>
          <h2 className="text-lg font-semibold mb-3">Appendix B · Exposed emails ({report.emails.length})</h2>
          <ColumnList items={report.emails} />
        </section>
      )}

      {/* tools */}
      <section className="mt-8 pt-4 border-t" style={{ ...avoid, borderColor: "var(--hairline)" }}>
        <p className="eyebrow mb-2">Tools & evidence</p>
        <div className="flex flex-wrap gap-1.5 mb-3">
          {report.toolStatus.map((t) => (
            <span key={t.tool} className="mono text-[0.66rem] px-2 py-0.5 rounded border flex items-center gap-1.5" style={{ borderColor: "var(--hairline)", opacity: t.available ? 1 : 0.5 }}>
              <span className="w-1.5 h-1.5 rounded-full" style={{ background: t.available ? "var(--sev-clean)" : "var(--sev-info)" }} />
              {t.tool}
            </span>
          ))}
        </div>
        <p className="text-[0.66rem] opacity-55 leading-relaxed">
          Evidence archive: {report.evidenceFiles.join(" · ") || "—"}. Passive OSINT{report.verified ? " + authorized active scan" : ""}; point-in-time snapshot as of {fmtDate(report.startedAt)}. Not a penetration test.
        </p>
      </section>
    </div>
  );
}

/* ---------- chart primitives (static SVG/CSS, theme-aware) ---------- */

function RiskGauge({ pct, label, color }: { pct: number; label: string; color: string }) {
  const R = 52, C = 2 * Math.PI * R;
  return (
    <svg viewBox="0 0 120 120" width="128" height="128" aria-hidden>
      <circle cx="60" cy="60" r={R} fill="none" strokeWidth="11" style={{ stroke: "color-mix(in oklab, var(--color-base-content) 10%, transparent)" }} />
      <circle cx="60" cy="60" r={R} fill="none" strokeWidth="11" strokeLinecap="round" transform="rotate(-90 60 60)"
        style={{ stroke: color, strokeDasharray: `${(pct / 100) * C} ${C}` }} />
      <text x="60" y="56" textAnchor="middle" style={{ fill: color, fontSize: "20px", fontWeight: 700 }}>{label}</text>
      <text x="60" y="74" textAnchor="middle" className="mono" style={{ fill: "var(--color-base-content)", opacity: 0.5, fontSize: "8px", letterSpacing: "2px" }}>RISK</text>
    </svg>
  );
}

// Horizontal magnitude bars — 10px thick, 4px rounded data-end at the baseline.
function BarList({ rows }: { rows: { label: string; value: number; color: string }[] }) {
  const max = Math.max(1, ...rows.map((r) => r.value));
  return (
    <div className="flex flex-col gap-2.5">
      {rows.map((r) => (
        <div key={r.label}>
          <div className="flex justify-between text-[0.72rem] mb-1">
            <span className="capitalize opacity-80">{r.label}</span>
            <span className="mono opacity-90">{r.value}</span>
          </div>
          <div className="h-2.5 rounded-full" style={{ background: "color-mix(in oklab, var(--color-base-content) 8%, transparent)" }}>
            <div className="h-full" style={{ width: `${(r.value / max) * 100}%`, minWidth: "3px", background: r.color, borderRadius: "999px" }} />
          </div>
        </div>
      ))}
    </div>
  );
}

function ColumnList({ items }: { items: string[] }) {
  return (
    <div className="mono text-[0.68rem] leading-relaxed" style={{ columnCount: 3, columnGap: "1.5rem", color: "color-mix(in oklab, var(--color-base-content) 80%, transparent)" }}>
      {items.map((s) => (
        <div key={s} className="break-all" style={{ breakInside: "avoid" }}>{s}</div>
      ))}
    </div>
  );
}

function ShieldGlyph() {
  return (
    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" aria-hidden>
      <path d="M12 2l7 3v6c0 4.5-3 8.3-7 9-4-0.7-7-4.5-7-9V5l7-3z" stroke="var(--color-primary)" strokeWidth="1.6" strokeLinejoin="round" />
      <path d="M9 12l2 2 4-4" stroke="var(--color-primary)" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  );
}
