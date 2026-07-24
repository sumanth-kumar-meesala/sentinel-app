import { readFile } from "node:fs/promises";
import path from "node:path";
import { RUNS_DIR } from "@/lib/tools";
import PrintReport from "./PrintReport";
import type { Report } from "@/lib/types";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

// Standalone, print-optimized render of a stored report — used by the PDF route
// (puppeteer navigates here) and directly shareable.
export default async function PrintPage({
  params,
  searchParams,
}: {
  params: Promise<{ id: string }>;
  searchParams: Promise<{ theme?: string }>;
}) {
  const { id } = await params;
  const { theme } = await searchParams;
  let report: Report | null = null;
  if (/^[a-zA-Z0-9._-]+$/.test(id)) {
    try {
      report = JSON.parse(await readFile(path.join(RUNS_DIR, id, "report.json"), "utf8"));
    } catch {}
  }
  if (!report) return <div className="p-10 mono">Report not found.</div>;
  return <PrintReport report={report} theme={theme || "sentinel"} />;
}
