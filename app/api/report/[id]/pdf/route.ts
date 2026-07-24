import puppeteer from "puppeteer";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";
export const maxDuration = 60;

// GET /api/report/<runId>/pdf?theme=<theme>
// Renders the themed /print/<runId> page in headless Chrome and returns a real PDF.
export async function GET(req: Request, ctx: { params: Promise<{ id: string }> }) {
  const { id } = await ctx.params;
  if (!/^[a-zA-Z0-9._-]+$/.test(id)) return new Response("bad id", { status: 400 });

  const url = new URL(req.url);
  const theme = (url.searchParams.get("theme") || "sentinel").replace(/[^a-z0-9-]/gi, "");
  const target = `${url.origin}/print/${id}?theme=${encodeURIComponent(theme)}`;

  let browser;
  try {
    browser = await puppeteer.launch({ headless: true, args: ["--no-sandbox", "--disable-setuid-sandbox"] });
    const page = await browser.newPage();
    // Render the themed SCREEN styles, not print media — page.pdf() defaults to
    // print emulation, which would drop the theme's dark backgrounds.
    await page.emulateMediaType("screen");
    await page.goto(target, { waitUntil: "networkidle0", timeout: 30000 });
    await new Promise((r) => setTimeout(r, 350)); // let fonts/theme settle
    // margin 0 → the themed page background is full-bleed; the document supplies
    // its own padding, and CSS break-* rules handle pagination.
    const pdf = await page.pdf({
      format: "A4",
      printBackground: true,
      margin: { top: "0", bottom: "0", left: "0", right: "0" },
    });
    return new Response(new Uint8Array(pdf), {
      headers: {
        "Content-Type": "application/pdf",
        "Content-Disposition": `attachment; filename="${id}.pdf"`,
      },
    });
  } catch (e) {
    return new Response("pdf failed: " + (e instanceof Error ? e.message : "unknown"), { status: 500 });
  } finally {
    await browser?.close();
  }
}
