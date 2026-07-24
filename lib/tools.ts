import { spawn } from "node:child_process";
import { mkdir, writeFile } from "node:fs/promises";
import path from "node:path";

// Local scratch dir for CLI tool I/O and run assembly. Override with RUNS_DIR
// (e.g. a writable path on the host). Persisted artifacts are additionally
// mirrored to GCS by lib/storage.ts when GCS_BUCKET is set.
export const RUNS_DIR = process.env.RUNS_DIR || path.join(process.cwd(), "runs");

// Augmented PATH: prefer go-installed bins (~/go/bin) so projectdiscovery httpx
// wins over the Python "httpx" in /opt/homebrew/bin; include pipx (~/.local/bin).
const HOME = process.env.HOME || "";
const TOOL_PATH = [
  `${HOME}/go/bin`,
  "/opt/homebrew/bin",
  `${HOME}/.local/bin`,
  process.env.PATH || "",
].filter(Boolean).join(":");
const TOOL_ENV = { ...process.env, PATH: TOOL_PATH };

export interface RunResult {
  code: number | null;
  stdout: string;
  stderr: string;
  timedOut: boolean;
}

// Low-level spawn — bin must be a name or absolute path. Never throws.
function rawRun(bin: string, args: string[], opts: { timeoutMs?: number } = {}): Promise<RunResult> {
  const timeoutMs = opts.timeoutMs ?? 120_000;
  return new Promise((resolve) => {
    let stdout = "";
    let stderr = "";
    let timedOut = false;
    let child;
    try {
      // stdin: "ignore" gives the child a closed stdin. Without it, projectdiscovery
      // tools (httpx/dnsx) block waiting on the piped stdin and ignore -l/-u.
      child = spawn(bin, args, { env: TOOL_ENV, stdio: ["ignore", "pipe", "pipe"] });
    } catch {
      resolve({ code: 127, stdout: "", stderr: "spawn failed", timedOut: false });
      return;
    }
    const timer = setTimeout(() => {
      timedOut = true;
      child.kill("SIGKILL");
    }, timeoutMs);
    child.stdout.on("data", (d) => (stdout += d.toString()));
    child.stderr.on("data", (d) => (stderr += d.toString()));
    child.on("error", () => {
      clearTimeout(timer);
      resolve({ code: 127, stdout, stderr: stderr || "spawn error", timedOut });
    });
    child.on("close", (code) => {
      clearTimeout(timer);
      resolve({ code, stdout, stderr, timedOut });
    });
  });
}

// Resolve a tool name to an ABSOLUTE path under our augmented PATH, cached.
// Critical: Node's spawn resolves bare names against the parent PATH, not
// options.env.PATH — so a bare "httpx" could hit the Python httpx in
// /opt/homebrew/bin instead of projectdiscovery's in ~/go/bin. Always spawn the
// resolved absolute path.
const resolveCache = new Map<string, string | null>();
export async function resolveBin(bin: string): Promise<string | null> {
  if (bin.includes("/")) return bin;
  if (resolveCache.has(bin)) return resolveCache.get(bin)!;
  const r = await rawRun("/usr/bin/which", [bin], { timeoutMs: 5000 });
  const p = r.code === 0 && r.stdout.trim() ? r.stdout.trim().split("\n")[0] : null;
  resolveCache.set(bin, p);
  return p;
}

// Run a tool by name — resolves to its absolute path first. Never throws.
export async function run(bin: string, args: string[], opts: { timeoutMs?: number } = {}): Promise<RunResult> {
  const resolved = (await resolveBin(bin)) ?? bin;
  return rawRun(resolved, args, opts);
}

export async function have(bin: string): Promise<boolean> {
  return (await resolveBin(bin)) !== null;
}

export async function ensureRunDir(runId: string): Promise<string> {
  const dir = path.join(RUNS_DIR, runId);
  await mkdir(dir, { recursive: true });
  return dir;
}

export async function saveEvidence(dir: string, name: string, content: string): Promise<string> {
  const safe = name.replace(/[^a-zA-Z0-9._-]/g, "_");
  await writeFile(path.join(dir, safe), content);
  return safe;
}

// Simple fetch-with-timeout returning text (never throws)
export async function fetchText(url: string, timeoutMs = 45_000): Promise<string | null> {
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), timeoutMs);
  try {
    const res = await fetch(url, { signal: ctrl.signal, headers: { "User-Agent": "dxs-scanner" } });
    if (!res.ok) return null;
    return await res.text();
  } catch {
    return null;
  } finally {
    clearTimeout(t);
  }
}

// Basic domain validation — reject anything that isn't a plain hostname.
export function validDomain(d: string): boolean {
  return /^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$/i.test(d.trim());
}
