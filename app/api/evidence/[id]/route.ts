import { getObject } from "@/lib/storage";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

// GET /api/evidence/<runId> → zip of the run's raw evidence files.
// The archive is built once at scan finalize and stored alongside the report,
// so any instance can serve it (Cloud Run disks are per-instance/ephemeral).
export async function GET(_req: Request, ctx: RouteContext<"/api/evidence/[id]">) {
  const { id } = await ctx.params;
  if (!/^[a-zA-Z0-9._-]+$/.test(id)) return new Response("bad id", { status: 400 });
  const buf = await getObject(`${id}.zip`);
  if (!buf) return new Response("not found", { status: 404 });
  return new Response(new Uint8Array(buf), {
    headers: {
      "Content-Type": "application/zip",
      "Content-Disposition": `attachment; filename="${id}-evidence.zip"`,
    },
  });
}
