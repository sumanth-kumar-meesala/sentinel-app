import { readFile, stat, rm } from "node:fs/promises";
import path from "node:path";
import { run, RUNS_DIR } from "@/lib/tools";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

// GET /api/evidence/<runId>  → zip of the run's raw evidence files
export async function GET(_req: Request, ctx: RouteContext<"/api/evidence/[id]">) {
  const { id } = await ctx.params;
  if (!/^[a-zA-Z0-9._-]+$/.test(id)) return new Response("bad id", { status: 400 });

  const runDir = path.join(RUNS_DIR, id);
  try {
    const s = await stat(runDir);
    if (!s.isDirectory()) throw new Error();
  } catch {
    return new Response("not found", { status: 404 });
  }

  const zipPath = path.join(RUNS_DIR, `${id}.zip`);
  await rm(zipPath, { force: true });
  // zip from within RUNS_DIR so the archive contains the run folder, not absolute paths.
  const r = await run(
    "bash",
    ["-c", `cd ${JSON.stringify(RUNS_DIR)} && zip -r -q ${JSON.stringify(id + ".zip")} ${JSON.stringify(id)}`],
    { timeoutMs: 30000 }
  );
  if (r.code !== 0) return new Response("zip failed", { status: 500 });

  try {
    const buf = await readFile(zipPath);
    return new Response(new Uint8Array(buf), {
      headers: {
        "Content-Type": "application/zip",
        "Content-Disposition": `attachment; filename="${id}-evidence.zip"`,
      },
    });
  } catch {
    return new Response("read failed", { status: 500 });
  }
}
