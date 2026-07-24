import { readdir, readFile } from "node:fs/promises";
import path from "node:path";
import type {
  Report, Severity, DimensionScore, Analytics, Correlation,
  Trend, PriorityItem, GraphNode, GraphEdge, Finding,
} from "./types";

// ponytail: inlined from tools.ts (one hardcoded line, no config) so this module has no
// runtime cross-.ts import — `node --test` can't resolve extensionless "./tools". Re-import if RUNS_DIR ever becomes configurable.
const RUNS_DIR = path.join(process.cwd(), "runs");

export const clamp01 = (n: number) => Math.max(0, Math.min(100, n));

export function gradeFor(score: number): Analytics["grade"] {
  if (score >= 90) return "A";
  if (score >= 80) return "B";
  if (score >= 70) return "C";
  if (score >= 60) return "D";
  return "F";
}

export function riskFor(grade: Analytics["grade"]): Severity {
  return grade === "A" || grade === "B" ? "low"
    : grade === "C" ? "medium"
    : grade === "D" ? "high"
    : "critical";
}

// Read normalized signals from the assembled report.
function signals(r: Report) {
  const n = (k: string) => Number(r.stats[k]) || 0;
  const titleHas = (re: RegExp) => r.findings.some((f) => re.test(f.title));
  const anyHas = (re: RegExp) => r.findings.some((f) => re.test(f.title) || re.test(f.detail));
  return {
    stealer: n("stealerRecords"),
    stealerInternal: anyHas(/INTERNAL/i) && titleHas(/infostealer|credential sets stolen/i),
    subdomains: n("subdomains") || r.subdomains.length,
    exposedPanels: n("exposedServices"),
    dangling: titleHas(/dangling|takeover/i),
    openBuckets: n("openBuckets"),
    verifiedSecrets: titleHas(/VERIFIED live secret/i),
    codeHits: n("codeSearchHits"),
    emails: n("emailsExposed") || r.emails.length,
    tlsExpired: titleHas(/certificate expired|expired cert/i),
    tlsExpiring: titleHas(/certificate expiring|expiring/i),
    tlsWeakProto: titleHas(/weak TLS|TLS 1\.[01]/i),
    tlsHeaders: titleHas(/security header|HSTS/i),
    dns: r.dns,
  };
}

interface Dim { key: string; label: string; weight: number; compute: (s: ReturnType<typeof signals>) => { penalty: number; reasons: string[] } }

const DIMENSIONS: Dim[] = [
  { key: "breach", label: "Breach & credential exposure", weight: 30, compute: (s) => {
      const reasons: string[] = []; let p = 0;
      if (s.stealer > 20) { p += 80; reasons.push(`${s.stealer} infostealer credential sets (-80)`); }
      else if (s.stealer > 5) { p += 60; reasons.push(`${s.stealer} infostealer credential sets (-60)`); }
      else if (s.stealer > 0) { p += 40; reasons.push(`${s.stealer} infostealer credential sets (-40)`); }
      if (s.stealerInternal) { p += 15; reasons.push("internal (HR/admin) systems among stolen logins (-15)"); }
      return { penalty: p, reasons };
    } },
  { key: "surface", label: "Attack surface", weight: 20, compute: (s) => {
      const reasons: string[] = []; let p = 0;
      if (s.subdomains > 80) { p += 20; reasons.push(`${s.subdomains} subdomains (-20)`); }
      else if (s.subdomains > 40) { p += 10; reasons.push(`${s.subdomains} subdomains (-10)`); }
      if (s.exposedPanels > 0) { const d = Math.min(40, s.exposedPanels * 10); p += d; reasons.push(`${s.exposedPanels} exposed admin/non-standard-port service(s) (-${d})`); }
      if (s.dangling) { p += 15; reasons.push("dangling-DNS / subdomain-takeover candidate (-15)"); }
      return { penalty: p, reasons };
    } },
  { key: "dnsEmail", label: "DNS & email security", weight: 20, compute: (s) => {
      const reasons: string[] = []; let p = 0; const d = s.dns;
      if (!d) return { penalty: 0, reasons: ["DNS phase did not run"] };
      if (!d.spf) { p += 25; reasons.push("no SPF record (-25)"); }
      else if (!d.spfStrict) { p += 10; reasons.push("permissive SPF (-10)"); }
      if (d.dmarc === "missing") { p += 30; reasons.push("no DMARC record (-30)"); }
      else if (d.dmarc === "none") { p += 15; reasons.push("DMARC p=none, not enforcing (-15)"); }
      if (!d.dnssec) { p += 10; reasons.push("DNSSEC not enabled (-10)"); }
      return { penalty: p, reasons };
    } },
  { key: "tls", label: "TLS & HTTP security", weight: 15, compute: (s) => {
      const reasons: string[] = []; let p = 0;
      if (s.tlsExpired) { p += 40; reasons.push("expired TLS certificate (-40)"); }
      else if (s.tlsExpiring) { p += 20; reasons.push("certificate expiring soon (-20)"); }
      if (s.tlsWeakProto) { p += 20; reasons.push("weak TLS protocol (1.0/1.1) (-20)"); }
      if (s.tlsHeaders) { p += 10; reasons.push("missing security headers (HSTS/CSP) (-10)"); }
      return { penalty: p, reasons };
    } },
  { key: "secrets", label: "Secrets & code exposure", weight: 15, compute: (s) => {
      const reasons: string[] = []; let p = 0;
      if (s.verifiedSecrets) { p += 100; reasons.push("verified live secret in public code (-100)"); }
      if (s.codeHits > 0) { p += 10; reasons.push(`${s.codeHits} secret-keyword code hit(s) (-10)`); }
      if (s.emails > 0) { p += 5; reasons.push(`${s.emails} company email(s) exposed (-5)`); }
      return { penalty: p, reasons };
    } },
];

export function scoreReport(report: Report) {
  const s = signals(report);
  const dimensions: DimensionScore[] = DIMENSIONS.map((d) => {
    const { penalty, reasons } = d.compute(s);
    return { key: d.key, label: d.label, weight: d.weight, score: clamp01(100 - penalty), reasons };
  });
  const score = Math.round(dimensions.reduce((a, d) => a + d.score * d.weight, 0) / 100);
  const grade = gradeFor(score);
  return { score, grade, riskLevel: riskFor(grade), dimensions };
}

const hostOf = (urlOrHost: string): string => {
  try { return new URL(urlOrHost).hostname.toLowerCase(); }
  catch { return urlOrHost.replace(/^https?:\/\//, "").split("/")[0].split(":")[0].toLowerCase(); }
};

export function correlate(report: Report): Correlation[] {
  const out: Correlation[] = [];
  const live = new Set(report.liveHosts.map((h) => hostOf(h)));
  let i = 0;
  const id = () => `c${++i}`;

  // 1. Stolen credential URL whose host is also live → attacker has both a working
  //    credential and a reachable login.
  const stolenLive = report.stealerUrls.filter((u) => live.has(hostOf(u)));
  if (stolenLive.length) {
    out.push({ id: id(), severity: "critical",
      title: "Stolen credentials target a live login host",
      rule: "infostealer-url ∩ live-host",
      evidence: stolenLive.slice(0, 10) });
  }

  // 2. Exposed internal panel while email spoofing is possible (DMARC not enforced).
  const exposed = Number(report.stats.exposedServices) || 0;
  if (exposed > 0 && report.dns && report.dns.dmarc !== "enforced") {
    out.push({ id: id(), severity: "high",
      title: "Exposed admin panel with unenforced DMARC — phishing-to-takeover path",
      rule: "exposed-service ∩ weak-dmarc",
      evidence: [`${exposed} exposed service(s)`, `DMARC: ${report.dns.dmarc}`] });
  }

  // 3. Registered typosquat with live MX = phishing infrastructure armed, not parked.
  const armed = report.typosquats.filter((t) => t.mx);
  if (armed.length) {
    out.push({ id: id(), severity: "high",
      title: "Registered look-alike domain has live mail (MX) — armed for phishing",
      rule: "typosquat ∩ mx",
      evidence: armed.slice(0, 10).map((t) => t.domain) });
  }

  // 4. Verified live secret in public code (elevate to top).
  const secret = report.findings.find((f) => /VERIFIED live secret/i.test(f.title));
  if (secret) {
    out.push({ id: id(), severity: "critical",
      title: "Verified live secret in public code",
      rule: "verified-secret",
      evidence: [secret.title] });
  }
  return out;
}

const SEV_IMPACT: Record<Severity, number> = { critical: 5, high: 4, medium: 3, low: 2, info: 1, clean: 0 };
const PHASE_EFFORT: Record<string, PriorityItem["effort"]> = {
  breach: "high", secrets: "medium", subdomains: "medium", cloud: "medium",
  dns: "low", tls: "low", phishing: "medium", assets: "low", active: "high", recon: "low", emails: "low",
};

export async function findPriorRun(domain: string, currentRunId: string): Promise<Report | null> {
  let entries: string[] = [];
  try { entries = await readdir(RUNS_DIR); } catch { return null; }
  const candidates: Report[] = [];
  for (const e of entries) {
    if (e === currentRunId || e.endsWith(".zip")) continue;
    try {
      const j = JSON.parse(await readFile(path.join(RUNS_DIR, e, "report.json"), "utf8")) as Report;
      if (j.domain === domain && j.finishedAt) candidates.push(j);
    } catch { /* skip unreadable run */ }
  }
  candidates.sort((a, b) => b.finishedAt.localeCompare(a.finishedAt));
  return candidates[0] ?? null;
}

export function buildTrend(current: Report, prior: Report, currentScore: number): Trend {
  const priorScore = prior.analytics?.score ?? 0;
  const curTitles = new Set(current.findings.map((f) => f.title));
  const priorTitles = new Set(prior.findings.map((f) => f.title));
  const curSubs = new Set(current.subdomains);
  const priorSubs = new Set(prior.subdomains);
  return {
    scoreDelta: currentScore - priorScore,
    newFindings: [...curTitles].filter((t) => !priorTitles.has(t)),
    resolvedFindings: [...priorTitles].filter((t) => !curTitles.has(t)),
    subdomainsAdded: [...curSubs].filter((s) => !priorSubs.has(s)),
    subdomainsRemoved: [...priorSubs].filter((s) => !curSubs.has(s)),
    priorRunId: prior.runId,
    priorScore,
    priorDate: prior.finishedAt,
  };
}

export function prioritize(report: Report): PriorityItem[] {
  return report.findings
    .filter((f) => !["clean", "info"].includes(f.severity))
    .map((f) => ({
      findingId: f.id, title: f.title, severity: f.severity,
      impact: SEV_IMPACT[f.severity], effort: PHASE_EFFORT[f.phase] ?? "medium",
      action: f.detail.split(/(?<=\.)\s/)[0] || f.title,
    }))
    .sort((a, b) => b.impact - a.impact ||
      ({ low: 0, medium: 1, high: 2 }[a.effort] - { low: 0, medium: 1, high: 2 }[b.effort]))
    .slice(0, 10);
}

export function buildGraph(report: Report, correlations: Correlation[]) {
  const nodes: GraphNode[] = [];
  const edges: GraphEdge[] = [];
  const add = (n: GraphNode) => { if (!nodes.some((x) => x.id === n.id)) nodes.push(n); };

  const domainId = `domain:${report.domain}`;
  add({ id: domainId, label: report.domain, kind: "domain" });

  for (const a of report.relatedAssets) {
    const ipId = `ip:${a.ip}`;
    add({ id: ipId, label: a.ip, kind: "ip" });
    edges.push({ from: domainId, to: ipId });
    if (a.asn) { const asnId = `asn:${a.asn}`; add({ id: asnId, label: `${a.asn} ${a.org ?? ""}`.trim(), kind: "asn" }); edges.push({ from: ipId, to: asnId }); }
  }
  for (const ip of report.apexIps) { const ipId = `ip:${ip}`; add({ id: ipId, label: ip, kind: "ip" }); edges.push({ from: domainId, to: ipId }); }

  for (const h of report.liveHosts.slice(0, 25)) {
    const hostId = `host:${h}`;
    add({ id: hostId, label: h, kind: "host" });
    edges.push({ from: domainId, to: hostId });
  }
  for (const c of correlations) {
    const cId = `finding:${c.id}`;
    add({ id: cId, label: c.title, kind: "finding", severity: c.severity });
    edges.push({ from: domainId, to: cId });
  }
  return { nodes, edges };
}

export function toCsv(findings: Finding[]): string {
  const esc = (v: string) => /[",\n]/.test(v) ? `"${v.replace(/"/g, '""')}"` : v;
  const rows = findings.map((f) => [f.id, f.phase, f.severity, f.title, f.detail].map((x) => esc(String(x))).join(","));
  return ["id,phase,severity,title,detail", ...rows].join("\n");
}

export function computeAnalytics(report: Report, prior: Report | null = null): Analytics {
  const { score, grade, riskLevel, dimensions } = scoreReport(report);
  const correlations = correlate(report);
  return {
    score, grade, riskLevel, dimensions,
    correlations,
    priorities: prioritize(report),
    graph: buildGraph(report, correlations),
    trend: prior ? buildTrend(report, prior, score) : null,
  };
}
