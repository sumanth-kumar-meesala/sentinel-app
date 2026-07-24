import { readFile } from "node:fs/promises";
import path from "node:path";
import { RUNS_DIR } from "@/lib/tools";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

// GET /api/report/<runId>/csv → findings.csv for the run
export async function GET(_req: Request, ctx: { params: Promise<{ id: string }> }) {
  const { id } = await ctx.params;
  if (!/^[a-zA-Z0-9._-]+$/.test(id)) return new Response("bad id", { status: 400 });
  try {
    const csv = await readFile(path.join(RUNS_DIR, id, "findings.csv"), "utf8");
    return new Response(csv, {
      headers: {
        "Content-Type": "text/csv; charset=utf-8",
        "Content-Disposition": `attachment; filename="${id}-findings.csv"`,
      },
    });
  } catch {
    return new Response("not found", { status: 404 });
  }
}
