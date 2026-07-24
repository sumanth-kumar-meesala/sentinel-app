export type Severity = "critical" | "high" | "medium" | "low" | "info" | "clean";

export interface Finding {
  id: string;
  phase: string;
  severity: Severity;
  title: string;
  detail: string;
  evidence?: string; // short inline evidence snippet
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
  evidenceFiles: string[];
  toolStatus: { tool: string; available: boolean; note: string }[];
}

export const PHASES: PhaseState[] = [
  { id: "recon", title: "Domain recon & DNS", status: "pending" },
  { id: "breach", title: "Breach & infostealer intel", status: "pending" },
  { id: "subdomains", title: "Subdomain enumeration & liveness", status: "pending" },
  { id: "phishing", title: "Phishing & typosquat domains", status: "pending" },
  { id: "cloud", title: "Exposed cloud storage", status: "pending" },
  { id: "secrets", title: "Public code & secret leaks", status: "pending" },
  { id: "emails", title: "Employee email exposure", status: "pending" },
  { id: "active", title: "Active vuln scan (verified only)", status: "pending" },
];
