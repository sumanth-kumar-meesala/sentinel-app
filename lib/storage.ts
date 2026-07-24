import { readFile, writeFile, mkdir, readdir } from "node:fs/promises";
import path from "node:path";
import { run, RUNS_DIR } from "./tools";
import type { Report } from "./types";

// Shared run storage. On Cloud Run the container filesystem is per-instance and
// ephemeral, so scan artifacts written on the scanning instance are invisible to
// the instance that later serves a download → "works for me, 404 for others".
// When GCS_BUCKET is set we mirror every persisted artifact to a bucket and read
// it back from there; otherwise we fall back to the local runs/ dir (dev).
//
// Object layout mirrors the on-disk layout: "<runId>/report.json",
// "<runId>/findings.csv", "<runId>.zip". A local path.join maps names 1:1.
const BUCKET = process.env.GCS_BUCKET || "";
export const usingGcs = !!BUCKET;

// --- GCS auth: the Cloud Run runtime service-account token from the metadata
// server (no SDK/dep). The SA needs objectAdmin on the bucket. ---
let tokenCache: { token: string; exp: number } | null = null;
async function accessToken(): Promise<string> {
  const now = Date.now();
  if (tokenCache && tokenCache.exp > now + 60_000) return tokenCache.token;
  const res = await fetch(
    "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
    { headers: { "Metadata-Flavor": "Google" } }
  );
  if (!res.ok) throw new Error(`metadata token: ${res.status}`);
  const j = (await res.json()) as { access_token: string; expires_in?: number };
  tokenCache = { token: j.access_token, exp: now + (j.expires_in ?? 3600) * 1000 };
  return tokenCache.token;
}

const enc = encodeURIComponent;

export async function putObject(name: string, body: string | Buffer, contentType: string): Promise<void> {
  if (!BUCKET) {
    const p = path.join(RUNS_DIR, name);
    await mkdir(path.dirname(p), { recursive: true });
    await writeFile(p, body);
    return;
  }
  const token = await accessToken();
  const res = await fetch(
    `https://storage.googleapis.com/upload/storage/v1/b/${enc(BUCKET)}/o?uploadType=media&name=${enc(name)}`,
    {
      method: "POST",
      headers: { Authorization: `Bearer ${token}`, "Content-Type": contentType },
      body: typeof body === "string" ? body : new Uint8Array(body),
    }
  );
  if (!res.ok) throw new Error(`gcs put ${name}: ${res.status} ${await res.text().catch(() => "")}`);
}

export async function getObject(name: string): Promise<Buffer | null> {
  if (!BUCKET) {
    return readFile(path.join(RUNS_DIR, name)).catch(() => null);
  }
  const token = await accessToken();
  const res = await fetch(
    `https://storage.googleapis.com/storage/v1/b/${enc(BUCKET)}/o/${enc(name)}?alt=media`,
    { headers: { Authorization: `Bearer ${token}` } }
  );
  if (!res.ok) return null;
  return Buffer.from(await res.arrayBuffer());
}

// Run ids = top-level "directories". ponytail: one page (1000 objects); paginate
// via nextPageToken if run history ever outgrows that.
async function listRunIds(): Promise<string[]> {
  if (!BUCKET) {
    const es = await readdir(RUNS_DIR).catch(() => [] as string[]);
    return es.filter((e) => !e.endsWith(".zip"));
  }
  const token = await accessToken();
  const res = await fetch(
    `https://storage.googleapis.com/storage/v1/b/${enc(BUCKET)}/o?delimiter=%2F`,
    { headers: { Authorization: `Bearer ${token}` } }
  );
  if (!res.ok) return [];
  const j = (await res.json()) as { prefixes?: string[] };
  return (j.prefixes ?? []).map((p) => p.replace(/\/$/, ""));
}

// Zip the local run dir into RUNS_DIR/<id>.zip (files exist on the scanning
// instance). Kept as a single artifact so downloads are one object read.
async function makeZip(runId: string): Promise<Buffer | null> {
  const r = await run(
    "bash",
    ["-c", `cd ${JSON.stringify(RUNS_DIR)} && rm -f ${JSON.stringify(runId + ".zip")} && zip -r -q ${JSON.stringify(runId + ".zip")} ${JSON.stringify(runId)}`],
    { timeoutMs: 30000 }
  );
  if (r.code !== 0) return null;
  return readFile(path.join(RUNS_DIR, `${runId}.zip`)).catch(() => null);
}

// Called at scan finalize on the scanning instance, where all local files exist.
// Builds the evidence zip (local, so dev downloads work too) and — when GCS is
// configured — uploads report.json, findings.csv and the zip to the bucket.
export async function persistRun(runId: string): Promise<void> {
  const zip = await makeZip(runId);
  if (!BUCKET) return;
  const dir = path.join(RUNS_DIR, runId);
  const report = await readFile(path.join(dir, "report.json")).catch(() => null);
  if (report) await putObject(`${runId}/report.json`, report, "application/json");
  const csv = await readFile(path.join(dir, "findings.csv")).catch(() => null);
  if (csv) await putObject(`${runId}/findings.csv`, csv, "text/csv");
  if (zip) await putObject(`${runId}.zip`, zip, "application/zip");
}

// Most-recent prior run for the same domain (for trend diffing). Reads from the
// shared store so trends are consistent across instances.
export async function findPriorRun(domain: string, currentRunId: string): Promise<Report | null> {
  const ids = await listRunIds();
  const candidates: Report[] = [];
  for (const id of ids) {
    if (id === currentRunId) continue;
    const buf = await getObject(`${id}/report.json`);
    if (!buf) continue;
    try {
      const j = JSON.parse(buf.toString("utf8")) as Report;
      if (j.domain === domain && j.finishedAt) candidates.push(j);
    } catch {
      /* skip unreadable run */
    }
  }
  candidates.sort((a, b) => b.finishedAt.localeCompare(a.finishedAt));
  return candidates[0] ?? null;
}
