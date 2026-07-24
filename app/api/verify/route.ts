import { createHash } from "node:crypto";
import dns from "node:dns/promises";
import { validDomain } from "@/lib/tools";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

// Deterministic token — no storage needed. Reproducible from the domain alone.
function tokenFor(domain: string): string {
  return "dxs-verify=" + createHash("sha256").update(`dxs:${domain}`).digest("hex").slice(0, 24);
}

// GET /api/verify?domain=example.com            → instructions + token
// GET /api/verify?domain=example.com&check=1    → performs the DNS TXT check
export async function GET(req: Request) {
  const { searchParams } = new URL(req.url);
  const domain = (searchParams.get("domain") || "").trim().toLowerCase();
  if (!validDomain(domain)) return Response.json({ error: "invalid domain" }, { status: 400 });

  const token = tokenFor(domain);
  const recordName = `_dxs-verify.${domain}`;

  if (searchParams.get("check") !== "1") {
    return Response.json({
      token,
      recordName,
      instructions: `Add a DNS TXT record at "${recordName}" (or at the apex "${domain}") with value: ${token}`,
    });
  }

  // Check both the dedicated subdomain and the apex.
  const names = [recordName, domain];
  for (const name of names) {
    try {
      const records = await dns.resolveTxt(name);
      const flat = records.map((r) => r.join("")).join(" ");
      if (flat.includes(token)) return Response.json({ verified: true, matchedAt: name });
    } catch {
      /* NXDOMAIN / no TXT — try next */
    }
  }
  return Response.json({ verified: false, token, recordName });
}
