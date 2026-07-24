import dns from "node:dns/promises";
import tls from "node:tls";
import path from "node:path";
import { readFile } from "node:fs/promises";
import { ScanEvent, Report, Finding, Severity, PHASES } from "./types";
import { run, have, ensureRunDir, saveEvidence, fetchText } from "./tools";
import { computeAnalytics, toCsv } from "./score";
import { findPriorRun, persistRun } from "./storage";

let counter = 0;
const fid = () => `f${++counter}`;

function finding(
  phase: string,
  severity: Severity,
  title: string,
  detail: string,
  evidence?: string
): Extract<ScanEvent, { type: "finding" }> {
  return { type: "finding", finding: { id: fid(), phase, severity, title, detail, evidence } };
}

const CORE_PREFIXES = ["", "www.", "auth.", "app.", "api.", "admin.", "mail."];

export interface ScanOpts {
  verified: boolean;
  phases?: string[]; // if set, only these phase ids run; others are skipped
}

// The orchestrator. Yields SSE events; also assembles the final Report.
export async function* runScan(domain: string, opts: ScanOpts): AsyncGenerator<ScanEvent> {
  const runId = `${domain.replace(/[^a-z0-9.]/gi, "_")}-${Date.now()}`;
  const dir = await ensureRunDir(runId);
  const startedAt = new Date().toISOString();

  const report: Report = {
    runId,
    domain,
    verified: opts.verified,
    startedAt,
    finishedAt: "",
    stats: {},
    findings: [],
    subdomains: [],
    emails: [],
    liveHosts: [],
    stealerUrls: [],
    apexIps: [],
    relatedAssets: [],
    typosquats: [],
    evidenceFiles: [],
    toolStatus: [],
  };

  const push = (ev: ScanEvent): ScanEvent => {
    if (ev.type === "finding") report.findings.push(ev.finding);
    if (ev.type === "stat") report.stats[ev.key] = ev.value;
    if (ev.type === "evidence") report.evidenceFiles.push(ev.file);
    return ev;
  };

  // Tool availability up front
  for (const t of ["subfinder", "httpx", "dnstwist", "cloud_enum", "trufflehog", "gitleaks", "nuclei", "gh"]) {
    report.toolStatus.push({ tool: t, available: await have(t), note: "" });
  }

  yield {
    type: "meta",
    runId,
    domain,
    verified: opts.verified,
    phases: PHASES,
  };

  const label = domain.split(".")[0];
  const on = (id: string) => !opts.phases || opts.phases.includes(id);

  // ---------- Phase 1: recon ----------
  if (!on("recon")) {
    yield { type: "phase", id: "recon", status: "skipped", note: "disabled" };
  } else {
  yield { type: "phase", id: "recon", status: "running" };
  try {
    let apexIps: string[] = [];
    try {
      apexIps = await dns.resolve4(domain);
    } catch {}
    yield { type: "log", phase: "recon", message: `apex ${domain} → ${apexIps.join(", ") || "no A record"}` };
    yield push({ type: "stat", key: "apexIPs", value: apexIps.length });
    report.apexIps = apexIps;

    // GitHub org presence (public API, no auth)
    const orgRaw = await fetchText(`https://api.github.com/orgs/${encodeURIComponent(label)}`, 15000);
    if (orgRaw) {
      try {
        const org = JSON.parse(orgRaw);
        if (org.login) {
          yield { type: "log", phase: "recon", message: `GitHub org "${org.login}" (${org.name || "?"}) — ${org.public_repos} public repos` };
          if (org.public_repos > 0) {
            yield push(
              finding(
                "recon",
                "info",
                `Public GitHub organization "${org.login}"`,
                `${org.public_repos} public repositories under an org matching your domain label — a candidate for secret leaks.`,
                org.html_url
              )
            );
          }
        }
      } catch {}
    }
    yield { type: "phase", id: "recon", status: "done" };
  } catch {
    yield { type: "phase", id: "recon", status: "done", note: "partial" };
  }
  }

  // ---------- Phase 2: breach / infostealer ----------
  if (!on("breach")) {
    yield { type: "phase", id: "breach", status: "skipped", note: "disabled" };
  } else {
    const raw = await fetchText(
      `https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-domain?domain=${encodeURIComponent(domain)}`
    );
    if (!raw) {
      yield { type: "log", phase: "breach", message: "Hudson Rock infostealer API unreachable — skipping" };
    } else {
      const ev = await saveEvidence(dir, "hudsonrock-domain.json", raw);
      yield push({ type: "evidence", file: ev });
      try {
        const d = JSON.parse(raw);
        const total: number = d.total ?? 0;
        yield push({ type: "stat", key: "stealerRecords", value: total });
        const urls: { url: string; type: string; occurrence: number }[] = d?.data?.all_urls ?? [];
        yield { type: "log", phase: "breach", message: `${total} infostealer credential record(s); ${urls.length} distinct login URL(s)` };
        if (total > 0) {
          const top = urls
            .sort((a, b) => b.occurrence - a.occurrence)
            .slice(0, 8)
            .map((u) => `${u.url} (${u.occurrence})`)
            .join("\n");
          report.stealerUrls = urls.map((u) => u.url);
          const internal = urls.filter((u) => /orangehrm|admin|adpatch|adevent|internal|jenkins|vpn|hr/i.test(u.url));
          const sev: Severity = internal.length > 0 ? "high" : total > 0 ? "high" : "info";
          yield push(
            finding(
              "breach",
              sev,
              `${total} credential sets stolen by infostealer malware`,
              `Machines infected with password-stealing malware had saved logins for this domain exfiltrated.${
                internal.length ? " Includes INTERNAL systems (HR/admin), implying staff machines were infected." : ""
              } Plaintext is redacted in the free tier — verify domain ownership with Hudson Rock / HaveIBeenPwned to retrieve it.`,
              top
            )
          );
        } else {
          yield push(finding("breach", "clean", "No infostealer records found", "No credentials for this domain appear in the infostealer database.", undefined));
        }
      } catch {
        yield { type: "log", phase: "breach", message: "could not parse breach response" };
      }
    }

    // ---- ProxyNova COMB: supplementary PLAINTEXT credential pairs from the
    // public 2021 "Compilation of Many Breaches". Older aggregated breach data,
    // NOT fresh infostealer logs — free, no key. Authorized domains only. ----
    const combRaw = await fetchText(`https://api.proxynova.com/comb?query=${encodeURIComponent(domain)}&limit=100`, 20000);
    if (combRaw) {
      try {
        const cj = JSON.parse(combRaw) as { count?: number; lines?: string[] };
        const lines = (cj.lines ?? []).filter((l) => l.toLowerCase().includes(`@${domain.toLowerCase()}`));
        yield push({ type: "stat", key: "combRecords", value: lines.length });
        yield { type: "log", phase: "breach", message: `ProxyNova COMB → ${lines.length} plaintext pair(s)${cj.count ? ` (of ~${cj.count} raw matches)` : ""}` };
        if (lines.length) {
          const cev = await saveEvidence(dir, "proxynova-comb.txt", lines.join("\n"));
          yield push({ type: "evidence", file: cev });
          yield push(
            finding(
              "breach",
              "medium",
              `${lines.length} plaintext credential pair(s) in the COMB breach compilation`,
              "Email:password pairs for this domain found in the public 'Compilation of Many Breaches' (COMB, ~2021) — aggregated from older breaches, NOT fresh infostealer logs like the Hudson Rock result above. Shown in plaintext because this data is already public. Treat any still-valid password as compromised and force a reset. Full set in the proxynova-comb.txt evidence file.",
              lines.slice(0, 20).join("\n")
            )
          );
        }
      } catch {
        yield { type: "log", phase: "breach", message: "could not parse ProxyNova COMB response" };
      }
    }

    yield { type: "phase", id: "breach", status: "done" };
  }

  // ---------- Phase 2b: DNS & email security ----------
  if (!on("dns")) {
    yield { type: "phase", id: "dns", status: "skipped", note: "disabled" };
  } else {
    yield { type: "phase", id: "dns", status: "running" };
    const txt = async (name: string): Promise<string[]> => {
      try { return (await dns.resolveTxt(name)).map((r) => r.join("")); } catch { return []; }
    };
    const apexTxt = await txt(domain);
    const spfRec = apexTxt.find((t) => /v=spf1/i.test(t));
    const spf = !!spfRec;
    const spfStrict = !!spfRec && /[-~]all\b/i.test(spfRec);

    const dmarcTxt = (await txt(`_dmarc.${domain}`)).find((t) => /v=DMARC1/i.test(t));
    const dmarc: "missing" | "none" | "enforced" =
      !dmarcTxt ? "missing" : /p=none/i.test(dmarcTxt) ? "none" : "enforced";

    const dkimSelectors: string[] = [];
    for (const sel of ["default", "google", "selector1", "selector2", "k1", "dkim", "mail"]) {
      if ((await txt(`${sel}._domainkey.${domain}`)).some((t) => /v=DKIM1|p=/i.test(t))) dkimSelectors.push(sel);
    }

    // DNSSEC via DoH (node:dns has no DNSKEY rrtype). AD flag / DNSKEY presence.
    let dnssec = false;
    const doh = await fetchText(`https://dns.google/resolve?name=${encodeURIComponent(domain)}&type=DNSKEY`, 15000);
    if (doh) { try { const j = JSON.parse(doh); dnssec = j.AD === true || (Array.isArray(j.Answer) && j.Answer.length > 0); } catch {} }

    report.dns = { spf, spfStrict, dmarc, dnssec, dkimSelectors };
    yield { type: "log", phase: "dns", message: `SPF ${spf ? "present" : "MISSING"} · DMARC ${dmarc} · DNSSEC ${dnssec ? "on" : "off"} · DKIM [${dkimSelectors.join(",") || "none found"}]` };

    let issues = 0;
    const emit = (sev: Severity, title: string, detail: string) => { issues++; return push(finding("dns", sev, title, detail)); };
    if (!spf) yield emit("medium", "No SPF record", "Domain has no SPF record — anyone can send mail spoofing this domain envelope.");
    else if (!spfStrict) yield emit("low", "Permissive SPF policy", "SPF exists but does not end in -all/~all, weakening spoofing protection.");
    if (dmarc === "missing") yield emit("medium", "No DMARC record", "Without DMARC, receivers cannot reject spoofed mail claiming to be from this domain.");
    else if (dmarc === "none") yield emit("low", "DMARC not enforcing (p=none)", "DMARC is monitor-only; move to p=quarantine or p=reject to actually block spoofing.");
    if (!dnssec) yield emit("low", "DNSSEC not enabled", "DNS responses are not cryptographically signed — susceptible to cache-poisoning / spoofing.");
    yield push({ type: "stat", key: "emailAuthIssues", value: issues });
    yield { type: "phase", id: "dns", status: "done" };
  }

  // ---------- Phase 3: subdomains ----------
  if (!on("subdomains")) {
    yield { type: "phase", id: "subdomains", status: "skipped", note: "disabled" };
  } else {
    const subs = new Set<string>();
    // crt.sh (certificate transparency)
    const crt = await fetchText(`https://crt.sh/?q=%25.${encodeURIComponent(domain)}&output=json`, 60000);
    if (crt) {
      try {
        for (const row of JSON.parse(crt)) {
          for (const n of String(row.name_value || "").split("\n")) {
            const h = n.trim().replace(/^\*\./, "").toLowerCase();
            if (h.endsWith(domain)) subs.add(h);
          }
        }
        yield { type: "log", phase: "subdomains", message: `crt.sh → ${subs.size} host(s)` };
      } catch {}
    }
    // subfinder
    if (await have("subfinder")) {
      const r = await run("subfinder", ["-d", domain, "-silent"], { timeoutMs: 120000 });
      const before = subs.size;
      r.stdout.split("\n").forEach((l) => {
        const h = l.trim().toLowerCase();
        if (h.endsWith(domain)) subs.add(h);
      });
      yield { type: "log", phase: "subdomains", message: `subfinder → +${subs.size - before} new host(s)` };
    } else {
      yield { type: "log", phase: "subdomains", message: "subfinder not installed — using crt.sh only" };
    }

    const list = [...subs].sort();
    report.subdomains = list;
    if (list.length) {
      const ev = await saveEvidence(dir, "subdomains.txt", list.join("\n"));
      yield push({ type: "evidence", file: ev });
    }
    yield push({ type: "stat", key: "subdomains", value: list.length });

    const staging = list.filter((h) => /(^|\.)(staging|stage|dev|beta|test|uat|demo)\b|-staging|-dev/.test(h));
    const sev: Severity = list.length > 40 ? "medium" : list.length > 0 ? "low" : "info";
    yield push(
      finding(
        "subdomains",
        sev,
        `${list.length} live subdomains discovered`,
        `Public subdomain footprint mapped via certificate transparency${(await have("subfinder")) ? " + subfinder" : ""}.${
          staging.length ? ` ${staging.length} appear to be staging/dev hosts (often weakly secured).` : ""
        }`,
        list.slice(0, 30).join("\n")
      )
    );

    // httpx: probe which hosts are live + tech + dangling-DNS/takeover candidates.
    // Cap + high concurrency + short timeout keeps this to ~10-20s even on dead-host-heavy lists.
    const HTTPX_CAP = 80;
    if (list.length && (await have("httpx"))) {
      const probeFile = await saveEvidence(dir, "httpx_targets.txt", list.slice(0, HTTPX_CAP).join("\n"));
      const r = await run(
        "httpx",
        ["-l", path.join(dir, probeFile), "-silent", "-json", "-status-code", "-title", "-tech-detect", "-cname", "-threads", "100", "-timeout", "4", "-retries", "0", "-no-color"],
        { timeoutMs: 90000 }
      );
      const rows = r.stdout.split("\n").filter(Boolean).map((l) => { try { return JSON.parse(l); } catch { return null; } }).filter(Boolean) as Record<string, unknown>[];
      if (r.stdout.trim()) await saveEvidence(dir, "httpx.jsonl", r.stdout);
      const live = rows.filter((x) => x.status_code);
      report.liveHosts = live.map((x) => String(x.input || x.host || x.url || "")).filter(Boolean);
      const tech = new Set<string>();
      rows.forEach((x) => (x.tech as string[] | undefined)?.forEach((t) => tech.add(t)));
      const TAKEOVER = /s3[.-]|s3\.amazonaws|github\.io|herokuapp|herokudns|azurewebsites|cloudfront|trafficmanager|fastly|netlify|surge\.sh|wpengine|zendesk|myshopify|readme\.io|ghost\.io|bitbucket\.io|shoffr/i;
      const dangling = rows.filter((x) => typeof x.cname === "string" && TAKEOVER.test(x.cname as string));
      yield push({ type: "stat", key: "liveHosts", value: live.length });
      yield { type: "log", phase: "subdomains", message: `httpx → ${live.length} live host(s), ${tech.size} technologies` };
      if (live.length) {
        const probed = Math.min(list.length, HTTPX_CAP);
        yield push(finding("subdomains", "info", `${live.length} of ${probed} probed subdomains are live`, `Probed with httpx${list.length > HTTPX_CAP ? ` (first ${HTTPX_CAP} of ${list.length})` : ""}. Technologies seen: ${[...tech].slice(0, 12).join(", ") || "n/a"}.`, live.slice(0, 15).map((x) => `${x.url} [${x.status_code}] ${x.title || ""}`).join("\n")));
      }
      if (dangling.length) {
        yield push(finding("subdomains", "medium", `${dangling.length} dangling-DNS / subdomain-takeover candidate(s)`, `These hosts point (via CNAME) at third-party services that may be unclaimed — an attacker could take them over and serve content from your domain. Verify each target is still yours.`, dangling.map((x) => `${x.input || x.host} → ${x.cname}`).join("\n")));
      }
      const PORT_RE = /:(?!80\b|443\b)\d+/;
      const ADMIN_RE = /admin|login|jenkins|grafana|kibana|phpmyadmin|orangehrm|\.do\b|config|dashboard|manager/i;
      const exposed = live.filter((x) => {
        const url = String(x.url || "");
        return PORT_RE.test(url) || ADMIN_RE.test(url) || ADMIN_RE.test(String(x.title || ""));
      });
      yield push({ type: "stat", key: "exposedServices", value: exposed.length });
      if (exposed.length) {
        yield push(finding("subdomains", exposed.some((x) => PORT_RE.test(String(x.url))) ? "medium" : "low",
          `${exposed.length} exposed admin / non-standard-port service(s)`,
          "Live hosts that expose an administrative interface or listen on a non-standard port — high-value targets that should not be internet-facing.",
          exposed.slice(0, 15).map((x) => `${x.url} [${x.status_code}] ${x.title || ""}`).join("\n")));
      }
    } else if (list.length) {
      yield { type: "log", phase: "subdomains", message: "httpx not installed — skipping liveness probe" };
    }
    yield { type: "phase", id: "subdomains", status: "done" };
  }

  // ---------- Phase 3a: related-asset discovery ----------
  if (!on("assets")) {
    yield { type: "phase", id: "assets", status: "skipped", note: "disabled" };
  } else {
    yield { type: "phase", id: "assets", status: "running" };
    const assets: import("./types").RelatedAsset[] = [];
    for (const ip of report.apexIps.slice(0, 8)) {
      const ptr = await dns.reverse(ip).catch(() => [] as string[]);
      // Team Cymru IP-to-ASN over DNS TXT: <reversed-octets>.origin.asn.cymru.com
      const rev = ip.split(".").reverse().join(".");
      let asn: string | undefined, org: string | undefined, prefix: string | undefined;
      try {
        const t = (await dns.resolveTxt(`${rev}.origin.asn.cymru.com`)).map((r) => r.join(""))[0];
        if (t) { const [as, pfx] = t.split("|").map((x) => x.trim()); asn = as ? `AS${as.split(" ")[0]}` : undefined; prefix = pfx; }
        if (asn) {
          const nameT = (await dns.resolveTxt(`${asn.replace(/^AS/, "AS")}.asn.cymru.com`)).map((r) => r.join(""))[0];
          if (nameT) org = nameT.split("|").pop()?.trim();
        }
      } catch {}
      assets.push({ ip, asn, org, prefix, ptr });
    }
    report.relatedAssets = assets;
    yield push({ type: "stat", key: "relatedAssets", value: assets.length });
    if (assets.length) {
      yield { type: "log", phase: "assets", message: assets.map((a) => `${a.ip} → ${a.asn ?? "?"} ${a.org ?? ""}`).join(" · ") };
      yield push(finding("assets", "info", `${assets.length} apex IP(s) mapped to ASN / network owner`,
        "Reverse-DNS + ASN ownership for the apex A records — establishes which network(s) host you and surfaces PTR names outside the apex domain.",
        assets.map((a) => `${a.ip}  ${a.asn ?? ""} ${a.org ?? ""} ${a.prefix ?? ""}${a.ptr.length ? "  PTR: " + a.ptr.join(",") : ""}`).join("\n")));
    }
    yield { type: "phase", id: "assets", status: "done" };
  }

  // ---------- Phase 3b: phishing / typosquat (dnstwist) ----------
  if (!on("phishing")) {
    yield { type: "phase", id: "phishing", status: "skipped", note: "disabled" };
  } else if (!(await have("dnstwist"))) {
    yield { type: "phase", id: "phishing", status: "skipped", note: "dnstwist not installed" };
  } else {
    yield { type: "phase", id: "phishing", status: "running" };
    yield { type: "log", phase: "phishing", message: "generating domain permutations & checking registration…" };
    const r = await run("dnstwist", ["--format", "json", "--registered", domain], { timeoutMs: 180000 });
    let rows: Record<string, unknown>[] = [];
    try { rows = JSON.parse(r.stdout); } catch {}
    if (r.stdout.trim()) await saveEvidence(dir, "dnstwist.json", r.stdout);
    // exclude the domain itself
    const looks = rows.filter((x) => (x.domain as string) && (x.domain as string) !== domain);
    report.typosquats = looks.map((x) => ({
      domain: String(x.domain),
      mx: Array.isArray((x as { dns_mx?: unknown }).dns_mx) && ((x as { dns_mx?: unknown[] }).dns_mx as unknown[]).length > 0,
    }));
    yield push({ type: "stat", key: "lookalikeDomains", value: looks.length });
    yield { type: "log", phase: "phishing", message: `${looks.length} registered look-alike domain(s)` };
    yield push(
      finding(
        "phishing",
        looks.length > 0 ? "medium" : "clean",
        looks.length > 0 ? `${looks.length} registered look-alike / typosquat domain(s)` : "No typosquat domains registered",
        looks.length > 0
          ? "Domains that visually resemble yours and are already registered — prime infrastructure for phishing your users or staff. Review and consider takedown/monitoring."
          : "No confusingly-similar domains found registered.",
        looks.slice(0, 20).map((x) => `${x.domain}${x.dns_a ? "  → " + (x.dns_a as string[]).join(",") : ""}`).join("\n")
      )
    );
    yield { type: "phase", id: "phishing", status: "done" };
  }

  // ---------- Phase 3c: exposed cloud storage (cloud_enum) ----------
  if (!on("cloud")) {
    yield { type: "phase", id: "cloud", status: "skipped", note: "disabled" };
  } else if (!(await have("cloud_enum"))) {
    yield { type: "phase", id: "cloud", status: "skipped", note: "cloud_enum not installed" };
  } else {
    yield { type: "phase", id: "cloud", status: "running" };
    yield { type: "log", phase: "cloud", message: `enumerating AWS/Azure/GCP buckets for "${label}"…` };
    const logFile = path.join(dir, "cloud_enum.log");
    const r = await run("cloud_enum", ["-k", label, "-l", logFile, "--disable-azure", "--disable-gcp", "-qs"], { timeoutMs: 240000 });
    const out = (r.stdout || "") + "\n" + (await readFile(logFile, "utf8").catch(() => ""));
    if (out.trim()) await saveEvidence(dir, "cloud_enum.log", out);
    // cloud_enum marks public/open resources with "OPEN" / "PUBLIC"
    const openHits = out.split("\n").filter((l) => /OPEN|Public|PUBLIC/.test(l) && /http/.test(l));
    yield push({ type: "stat", key: "openBuckets", value: openHits.length });
    yield { type: "log", phase: "cloud", message: `${openHits.length} publicly-accessible cloud resource(s)` };
    yield push(
      finding(
        "cloud",
        openHits.length > 0 ? "high" : "clean",
        openHits.length > 0 ? `${openHits.length} publicly-exposed cloud storage resource(s)` : "No exposed cloud buckets found",
        openHits.length > 0
          ? "Public cloud storage matching your name may leak files. Review ACLs and lock down anything not meant to be public."
          : `Checked AWS S3 name permutations for "${label}" — nothing publicly listable found.`,
        openHits.slice(0, 15).join("\n")
      )
    );
    yield { type: "phase", id: "cloud", status: "done" };
  }

  // ---------- Phase 4: public code & secrets ----------
  if (!on("secrets")) {
    yield { type: "phase", id: "secrets", status: "skipped", note: "disabled" };
  } else {
    const ghOk = await have("gh");
    if (!ghOk) {
      yield { type: "phase", id: "secrets", status: "skipped", note: "GitHub CLI (gh) not installed/authed" };
    } else {
      // dork count for domain + secret keywords
      let hits = 0;
      for (const kw of ["password", "secret", "api_key", "aws_secret_access_key"]) {
        const r = await run(
          "gh",
          ["api", "-X", "GET", "/search/code", "-f", `q="${domain}" ${kw}`, "--jq", ".total_count"],
          { timeoutMs: 30000 }
        );
        const n = parseInt(r.stdout.trim() || "0", 10);
        if (!isNaN(n)) hits += n;
        yield { type: "log", phase: "secrets", message: `"${domain}" ${kw} → ${isNaN(n) ? "?" : n} code hits` };
      }
      yield push({ type: "stat", key: "codeSearchHits", value: hits });

      // trufflehog on the org repo if both exist
      if (await have("trufflehog")) {
        const repoRaw = await fetchText(`https://api.github.com/orgs/${encodeURIComponent(label)}/repos?per_page=5`, 15000);
        let scanned = 0;
        let verified = 0;
        let glLeaks = 0;
        const glOn = await have("gitleaks");
        if (repoRaw) {
          try {
            const repos = JSON.parse(repoRaw);
            for (const repo of Array.isArray(repos) ? repos.slice(0, 2) : []) {
              yield { type: "log", phase: "secrets", message: `trufflehog scanning ${repo.full_name}…` };
              const r = await run("trufflehog", ["github", `--repo=${repo.html_url}`, "--json"], { timeoutMs: 90000 });
              scanned++;
              for (const line of r.stdout.split("\n")) {
                if (!line.trim()) continue;
                try {
                  const j = JSON.parse(line);
                  if (j.Verified) verified++;
                } catch {}
              }
              if (r.stdout.trim()) await saveEvidence(dir, `trufflehog_${repo.name}.jsonl`, r.stdout);

              // gitleaks: second, independent scanner on a shallow clone (cross-validation)
              if (glOn) {
                const cloneDir = path.join(dir, `clone_${repo.name}`);
                const cl = await run("git", ["clone", "--depth", "1", "--quiet", repo.clone_url || repo.html_url, cloneDir], { timeoutMs: 60000 });
                if (cl.code === 0) {
                  const rep = path.join(dir, `gitleaks_${repo.name}.json`);
                  await run("gitleaks", ["detect", "--source", cloneDir, "--report-format", "json", "--report-path", rep, "--no-banner"], { timeoutMs: 90000 });
                  try { glLeaks += (JSON.parse(await readFile(rep, "utf8")) as unknown[]).length; } catch {}
                  await run("rm", ["-rf", cloneDir], { timeoutMs: 15000 }); // ponytail: clone is disposable
                }
              }
            }
          } catch {}
        }
        yield { type: "log", phase: "secrets", message: `trufflehog: ${verified} verified secret(s)${glOn ? ` · gitleaks: ${glLeaks} raw match(es)` : ""} across ${scanned} repo(s)` };
        yield push(
          finding(
            "secrets",
            verified > 0 ? "critical" : "clean",
            verified > 0 ? `${verified} VERIFIED live secret(s) in public code` : "No verified secrets in scanned public repos",
            verified > 0
              ? "TruffleHog verified live, working credentials committed to public GitHub. Rotate immediately."
              : `Scanned ${scanned} public repo(s) with two scanners (TruffleHog + ${glOn ? "Gitleaks" : "—"}); no live secrets found${glOn ? ` (Gitleaks flagged ${glLeaks} raw match(es), typically false positives)` : ""}. GitHub code search returned ${hits} keyword hit(s) (usually noise for tracker domains).`,
            undefined
          )
        );
      }
      yield { type: "phase", id: "secrets", status: "done" };
    }
  }

  // ---------- Phase 5: emails ----------
  if (!on("emails")) {
    yield { type: "phase", id: "emails", status: "skipped", note: "disabled" };
  } else {
    if (!(await have("gh"))) {
      yield { type: "phase", id: "emails", status: "skipped", note: "needs GitHub CLI (gh)" };
    } else {
      const emails = new Set<string>();
      const r = await run("gh", ["api", "-X", "GET", "/search/code", "-f", `q="@${domain}"`, "--jq", ".items[].url"], {
        timeoutMs: 30000,
      });
      const urls = r.stdout.split("\n").filter(Boolean).slice(0, 15);
      for (const u of urls) {
        const c = await run("gh", ["api", u, "--jq", ".content"], { timeoutMs: 15000 });
        try {
          const text = Buffer.from(c.stdout.trim(), "base64").toString("utf8");
          const re = new RegExp(`[a-z0-9._%+-]+@${domain.replace(/\./g, "\\.")}`, "gi");
          for (const m of text.match(re) || []) emails.add(m.toLowerCase());
        } catch {}
      }
      report.emails = [...emails].sort();
      yield push({ type: "stat", key: "emailsExposed", value: report.emails.length });
      if (report.emails.length) {
        const ev = await saveEvidence(dir, "emails.txt", report.emails.join("\n"));
        yield push({ type: "evidence", file: ev });
      }
      yield { type: "log", phase: "emails", message: `${report.emails.length} company email(s) exposed in public code` };
      yield push(
        finding(
          "emails",
          report.emails.length > 0 ? "info" : "clean",
          `${report.emails.length} company email(s) exposed publicly`,
          "Recovered from public GitHub code. Useful inputs for phishing; not a direct credential leak.",
          report.emails.slice(0, 20).join("\n")
        )
      );
      yield { type: "phase", id: "emails", status: "done" };
    }
  }

  // ---------- Phase 5b: TLS & HTTP security ----------
  if (!on("tls")) {
    yield { type: "phase", id: "tls", status: "skipped", note: "disabled" };
  } else {
    yield { type: "phase", id: "tls", status: "running" };
    // Reuse live hosts from httpx; fall back to core prefixes that resolve.
    let hosts = report.liveHosts.map((h) => h.replace(/^https?:\/\//, "").split("/")[0].split(":")[0]);
    if (!hosts.length) {
      for (const p of CORE_PREFIXES) {
        const host = `${p}${domain}`;
        try { await dns.resolve4(host); hosts.push(host); } catch {}
      }
    }
    hosts = [...new Set(hosts)].slice(0, 15);

    const inspect = (host: string) => new Promise<{ host: string; expired?: boolean; expiringDays?: number; proto?: string; selfSigned?: boolean } | null>((resolve) => {
      const socket = tls.connect({ host, port: 443, servername: host, timeout: 5000, rejectUnauthorized: false }, () => {
        const cert = socket.getPeerCertificate();
        const proto = socket.getProtocol() || undefined;
        const authErr = (socket as unknown as { authorizationError?: string }).authorizationError;
        const validTo = cert?.valid_to ? new Date(cert.valid_to).getTime() : NaN;
        const days = isNaN(validTo) ? undefined : Math.round((validTo - Date.now()) / 86400000);
        resolve({ host, expired: days !== undefined && days < 0, expiringDays: days, proto, selfSigned: !!authErr && /self.signed/i.test(authErr) });
        socket.end();
      });
      socket.on("error", () => resolve(null));
      socket.on("timeout", () => { socket.destroy(); resolve(null); });
    });

    const results = (await Promise.all(hosts.map(inspect))).filter(Boolean) as NonNullable<Awaited<ReturnType<typeof inspect>>>[];
    const expired = results.filter((r) => r.expired);
    const expiring = results.filter((r) => !r.expired && r.expiringDays !== undefined && r.expiringDays <= 30);
    const weak = results.filter((r) => r.proto === "TLSv1" || r.proto === "TLSv1.1");

    // Security headers on the apex (one representative check).
    let missingHeaders: string[] = [];
    try {
      const res = await fetch(`https://${domain}`, { redirect: "manual", signal: AbortSignal.timeout(8000) });
      const h = res.headers;
      if (!h.get("strict-transport-security")) missingHeaders.push("HSTS");
      if (!h.get("content-security-policy")) missingHeaders.push("CSP");
      if (!h.get("x-frame-options")) missingHeaders.push("X-Frame-Options");
      if (!h.get("x-content-type-options")) missingHeaders.push("X-Content-Type-Options");
    } catch {}

    let issues = 0;
    if (expired.length) { issues++; yield push(finding("tls", "high", "Expired TLS certificate", `${expired.length} host(s) serve an expired certificate.`, expired.map((r) => r.host).join("\n"))); }
    if (expiring.length) { issues++; yield push(finding("tls", "medium", "TLS certificate expiring soon", `${expiring.length} host(s) have a certificate expiring within 30 days.`, expiring.map((r) => `${r.host} (${r.expiringDays}d)`).join("\n"))); }
    if (weak.length) { issues++; yield push(finding("tls", "medium", "Weak TLS protocol (1.0/1.1)", `${weak.length} host(s) negotiate a deprecated TLS version.`, weak.map((r) => `${r.host} [${r.proto}]`).join("\n"))); }
    if (missingHeaders.length) { issues++; yield push(finding("tls", "low", "Missing HTTP security headers", `Apex response is missing: ${missingHeaders.join(", ")}. Add HSTS/CSP to harden against downgrade and injection.`, missingHeaders.join("\n"))); }
    yield push({ type: "stat", key: "tlsIssues", value: issues });
    yield { type: "log", phase: "tls", message: `probed ${results.length}/${hosts.length} host(s) · ${issues} issue class(es)` };
    yield { type: "phase", id: "tls", status: "done" };
  }

  // ---------- Phase 6: active scan (verified only) ----------
  if (!on("active")) {
    yield { type: "phase", id: "active", status: "skipped", note: "disabled" };
  } else {
  yield { type: "phase", id: "active", status: "running" };
  if (!opts.verified) {
    yield { type: "phase", id: "active", status: "skipped", note: "requires domain verification" };
  } else if (!(await have("nuclei"))) {
    yield { type: "phase", id: "active", status: "skipped", note: "nuclei not installed" };
  } else {
    // Build target list: apex + core prefixes that resolve
    const targets: string[] = [];
    for (const p of CORE_PREFIXES) {
      const host = `${p}${domain}`;
      try {
        await dns.resolve4(host);
        targets.push(`https://${host}`);
      } catch {}
    }
    const tf = await saveEvidence(dir, "targets.txt", targets.join("\n"));
    yield push({ type: "evidence", file: tf });
    yield { type: "log", phase: "active", message: `nuclei scanning ${targets.length} resolved host(s)…` };
    const outFile = path.join(dir, "nuclei.json");
    const r = await run(
      "nuclei",
      [
        "-l", path.join(dir, tf),
        "-tags", "cve,exposure,misconfiguration,default-login,takeover",
        "-severity", "low,medium,high,critical",
        "-rate-limit", "300", "-c", "50", "-timeout", "10", "-retries", "1",
        "-json-export", outFile, "-no-color", "-silent",
      ],
      { timeoutMs: 300000 }
    );
    let findings: { severity: string; name: string; host: string }[] = [];
    try {
      const j = JSON.parse(await readFile(outFile, "utf8"));
      findings = (Array.isArray(j) ? j : []).map((x: { info?: { severity?: string; name?: string }; host?: string }) => ({
        severity: x.info?.severity || "info",
        name: x.info?.name || "",
        host: x.host || "",
      }));
      yield push({ type: "evidence", file: "nuclei.json" });
    } catch {}
    const bySev = (s: string) => findings.filter((f) => f.severity === s).length;
    const exploitable = findings.filter((f) => ["low", "medium", "high", "critical"].includes(f.severity));
    yield push({ type: "stat", key: "vulnFindings", value: exploitable.length });
    yield { type: "log", phase: "active", message: `nuclei: ${findings.length} match(es), ${exploitable.length} actionable` };
    const worst: Severity = bySev("critical") ? "critical" : bySev("high") ? "high" : bySev("medium") ? "medium" : bySev("low") ? "low" : "clean";
    yield push(
      finding(
        "active",
        worst,
        exploitable.length ? `${exploitable.length} finding(s) from active scan` : "No exploitable vulnerabilities found",
        exploitable.length
          ? exploitable.slice(0, 12).map((f) => `[${f.severity}] ${f.name} — ${f.host}`).join("\n")
          : `Ran nuclei against ${targets.length} host(s); no low/medium/high/critical issues detected.`,
        undefined
      )
    );
    yield { type: "phase", id: "active", status: "done" };
  }
  }

  // ---------- finalize ----------
  report.finishedAt = new Date().toISOString();
  const prior = await findPriorRun(domain, runId);
  report.analytics = computeAnalytics(report, prior);
  await saveEvidence(dir, "findings.csv", toCsv(report.findings));
  report.evidenceFiles.push("findings.csv");
  await saveEvidence(dir, "report.json", JSON.stringify(report, null, 2));
  // Mirror artifacts to shared storage (GCS on Cloud Run) so any instance can
  // serve the report / CSV / evidence downloads. No-op past the local zip in dev.
  await persistRun(runId);
  yield { type: "done", report };
}
