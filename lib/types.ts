export type Severity = "critical" | "high" | "medium" | "low" | "info" | "clean";

export interface Finding {
  id: string;
  phase: string;
  severity: Severity;
  title: string;
  detail: string;
  evidence?: string; // short inline evidence snippet
}

export interface DnsFacts {
  spf: boolean;
  spfStrict: boolean;            // has -all / ~all rather than +all / none
  dmarc: "missing" | "none" | "enforced";
  dnssec: boolean;
  dkimSelectors: string[];       // selectors that resolved
}

export interface RelatedAsset {
  ip: string;
  asn?: string;                  // e.g. "AS12345"
  org?: string;
  prefix?: string;               // announced CIDR
  ptr: string[];                 // reverse-DNS names
}

export interface Typosquat {
  domain: string;
  mx: boolean;                   // has MX records = armed for phishing
}

export interface DimensionScore {
  key: string;
  label: string;
  score: number;                 // 0-100, higher = better
  weight: number;                // percent, dimensions sum to 100
  reasons: string[];             // human-readable penalties = methodology
}

export interface Trend {
  scoreDelta: number;
  newFindings: string[];
  resolvedFindings: string[];
  subdomainsAdded: string[];
  subdomainsRemoved: string[];
  priorRunId: string;
  priorScore: number;
  priorDate: string;
}

export interface PriorityItem {
  findingId: string;
  title: string;
  severity: Severity;
  impact: number;                // 1-5 from severity
  effort: "low" | "medium" | "high";
  action: string;
}

export interface Correlation {
  id: string;
  severity: Severity;
  title: string;
  rule: string;
  evidence: string[];
}

export interface GraphNode {
  id: string;
  label: string;
  kind: "domain" | "ip" | "asn" | "host" | "finding";
  severity?: Severity;
}

export interface GraphEdge {
  from: string;
  to: string;
}

export interface Analytics {
  score: number;
  grade: "A" | "B" | "C" | "D" | "F";
  riskLevel: Severity;
  dimensions: DimensionScore[];
  trend: Trend | null;
  priorities: PriorityItem[];
  correlations: Correlation[];
  graph: { nodes: GraphNode[]; edges: GraphEdge[] };
}

export interface PhaseState {
  id: string;
  title: string;
  status: "pending" | "running" | "done" | "skipped";
  note?: string;
}

// Events streamed over SSE
export type ScanEvent =
  | { type: "meta"; runId: string; domain: string; verified: boolean; phases: PhaseState[] }
  | { type: "phase"; id: string; status: PhaseState["status"]; note?: string }
  | { type: "log"; phase: string; message: string }
  | { type: "finding"; finding: Finding }
  | { type: "stat"; key: string; value: number | string }
  | { type: "evidence"; file: string }
  | { type: "done"; report: Report }
  | { type: "error"; message: string };

export interface Report {
  runId: string;
  domain: string;
  verified: boolean;
  startedAt: string;
  finishedAt: string;
  stats: Record<string, number | string>;
  findings: Finding[];
  subdomains: string[];
  emails: string[];
  liveHosts: string[];           // hostnames probed live by httpx (or resolved core prefixes)
  stealerUrls: string[];         // infostealer login URLs from breach phase
  apexIps: string[];
  relatedAssets: RelatedAsset[];
  typosquats: Typosquat[];
  dns?: DnsFacts;
  analytics?: Analytics;
  evidenceFiles: string[];
  toolStatus: { tool: string; available: boolean; note: string }[];
}

export const PHASES: PhaseState[] = [
  { id: "recon", title: "Domain recon & DNS", status: "pending" },
  { id: "breach", title: "Breach & infostealer intel", status: "pending" },
  { id: "dns", title: "DNS & email security", status: "pending" },
  { id: "subdomains", title: "Subdomain enumeration & liveness", status: "pending" },
  { id: "assets", title: "Related-asset discovery", status: "pending" },
  { id: "phishing", title: "Phishing & typosquat domains", status: "pending" },
  { id: "cloud", title: "Exposed cloud storage", status: "pending" },
  { id: "secrets", title: "Public code & secret leaks", status: "pending" },
  { id: "emails", title: "Employee email exposure", status: "pending" },
  { id: "tls", title: "TLS & HTTP security", status: "pending" },
  { id: "active", title: "Active vuln scan (verified only)", status: "pending" },
];
