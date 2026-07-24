import { runScan } from "@/lib/scan";
import { validDomain } from "@/lib/tools";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

// GET /api/scan?domain=example.com&verified=1  → Server-Sent Events stream
export async function GET(req: Request) {
  const { searchParams } = new URL(req.url);
  const domain = (searchParams.get("domain") || "").trim().toLowerCase();
  const verified = searchParams.get("verified") === "1";
  const phasesParam = searchParams.get("phases");
  const phases = phasesParam ? phasesParam.split(",").filter(Boolean) : undefined;

  if (!validDomain(domain)) {
    return new Response("event: error\ndata: {\"message\":\"invalid domain\"}\n\n", {
      status: 400,
      headers: { "Content-Type": "text/event-stream" },
    });
  }

  const encoder = new TextEncoder();
  const stream = new ReadableStream({
    async start(controller) {
      const send = (obj: unknown) =>
        controller.enqueue(encoder.encode(`data: ${JSON.stringify(obj)}\n\n`));
      try {
        for await (const ev of runScan(domain, { verified, phases })) {
          send(ev);
        }
      } catch (e) {
        send({ type: "error", message: e instanceof Error ? e.message : "scan failed" });
      } finally {
        controller.close();
      }
    },
  });

  return new Response(stream, {
    headers: {
      "Content-Type": "text/event-stream; charset=utf-8",
      "Cache-Control": "no-cache, no-transform",
      Connection: "keep-alive",
    },
  });
}
