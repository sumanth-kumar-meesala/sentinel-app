"use client";
import { useEffect, useRef, useState } from "react";
import { ScanEvent, PhaseState, Finding, Report } from "@/lib/types";
import ReportView from "@/components/Report";
import ThemeSwitcher from "@/components/ThemeSwitcher";

type VerifyInfo = { token: string; recordName: string; instructions: string };

const PHASE_LABELS: { id: string; title: string; desc: string; gated?: boolean }[] = [
  { id: "recon", title: "Recon & DNS", desc: "DNS records + GitHub org discovery" },
  { id: "breach", title: "Breach & infostealer intel", desc: "Hudson Rock stolen-credential database" },
  { id: "subdomains", title: "Subdomains & liveness", desc: "crt.sh + subfinder + httpx (live/tech/takeover)" },
  { id: "phishing", title: "Phishing & typosquats", desc: "dnstwist — registered look-alike domains" },
  { id: "cloud", title: "Exposed cloud storage", desc: "cloud_enum — public S3/Azure/GCS buckets" },
  { id: "secrets", title: "Public code & secrets", desc: "GitHub dorks + TruffleHog + Gitleaks" },
  { id: "emails", title: "Employee email exposure", desc: "emails leaked in public code" },
  { id: "active", title: "Active vuln scan", desc: "nuclei — requires domain verification", gated: true },
];

export default function Home() {
  const [domain, setDomain] = useState("");
  const [phases, setPhases] = useState<PhaseState[]>([]);
  const [logs, setLogs] = useState<string[]>([]);
  const [liveFindings, setLiveFindings] = useState<Finding[]>([]);
  const [stats, setStats] = useState<Record<string, number | string>>({});
  const [report, setReport] = useState<Report | null>(null);
  const [scanning, setScanning] = useState(false);
  const [error, setError] = useState("");

  // scan module selection — all on by default
  const [selected, setSelected] = useState<Set<string>>(new Set(PHASE_LABELS.map((p) => p.id)));
  const allOn = selected.size === PHASE_LABELS.length;
  const toggle = (id: string) =>
    setSelected((s) => { const n = new Set(s); n.has(id) ? n.delete(id) : n.add(id); return n; });
  const toggleAll = () =>
    setSelected(allOn ? new Set() : new Set(PHASE_LABELS.map((p) => p.id)));

  const [verified, setVerified] = useState(false);
  const [verifyOpen, setVerifyOpen] = useState(false);
  const [verifyInfo, setVerifyInfo] = useState<VerifyInfo | null>(null);
  const [verifyMsg, setVerifyMsg] = useState("");
  const [checking, setChecking] = useState(false);
  const esRef = useRef<EventSource | null>(null);
  const progressRef = useRef<HTMLElement | null>(null);
  const scrolledRef = useRef(false);

  // Scroll the progress panel into view once the pipeline first renders (it's below the fold).
  useEffect(() => {
    if (!scanning) {
      scrolledRef.current = false;
      return;
    }
    if (phases.length > 0 && !scrolledRef.current) {
      scrolledRef.current = true;
      setTimeout(() => progressRef.current?.scrollIntoView({ behavior: "smooth", block: "start" }), 80);
    }
  }, [scanning, phases.length]);

  const validDomain = /^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$/i.test(domain.trim());

  // Restore a prior report on load from ?run=<runId> (survives refresh / shareable link).
  useEffect(() => {
    const params = new URLSearchParams(window.location.search);
    const run = params.get("run");
    const dParam = params.get("domain");
    if (dParam) setDomain(dParam);
    if (run) {
      fetch(`/api/report/${run}`)
        .then((r) => (r.ok ? r.json() : null))
        .then((rep: Report | null) => {
          if (rep) {
            setReport(rep);
            setDomain(rep.domain);
          }
        })
        .catch(() => {});
    }
  }, []);

  async function getToken() {
    setVerifyMsg("");
    const r = await fetch(`/api/verify?domain=${encodeURIComponent(domain.trim())}`);
    if (r.ok) setVerifyInfo(await r.json());
  }
  async function checkVerify() {
    setChecking(true);
    setVerifyMsg("Resolving TXT record…");
    const r = await fetch(`/api/verify?domain=${encodeURIComponent(domain.trim())}&check=1`);
    const j = await r.json();
    setChecking(false);
    if (j.verified) {
      setVerified(true);
      setVerifyMsg(`Verified via ${j.matchedAt}. Active scan unlocked.`);
    } else {
      setVerifyMsg("TXT record not found yet — DNS can take a few minutes to propagate.");
    }
  }

  function startScan() {
    if (!validDomain || scanning || selected.size === 0) return;
    setScanning(true);
    setError("");
    setReport(null);
    setPhases([]);
    setLogs([]);
    setLiveFindings([]);
    setStats({});
    esRef.current?.close();

    const phases = PHASE_LABELS.map((p) => p.id).filter((id) => selected.has(id)).join(",");
    const es = new EventSource(
      `/api/scan?domain=${encodeURIComponent(domain.trim())}&verified=${verified ? "1" : "0"}&phases=${phases}`
    );
    esRef.current = es;
    es.onmessage = (e) => {
      const ev = JSON.parse(e.data) as ScanEvent;
      switch (ev.type) {
        case "meta": setPhases(ev.phases); break;
        case "phase": setPhases((p) => p.map((x) => (x.id === ev.id ? { ...x, status: ev.status, note: ev.note } : x))); break;
        case "log": setLogs((l) => [...l, `[${ev.phase}] ${ev.message}`]); break;
        case "finding": setLiveFindings((f) => [...f, ev.finding]); break;
        case "stat": setStats((s) => ({ ...s, [ev.key]: ev.value })); break;
        case "done":
          setReport(ev.report);
          setScanning(false);
          es.close();
          // persist in the URL so a refresh restores this report
          window.history.replaceState(null, "", `?run=${encodeURIComponent(ev.report.runId)}`);
          break;
        case "error": setError(ev.message); setScanning(false); es.close(); break;
      }
    };
    es.onerror = () => { setError((p) => p || "Connection to scan stream lost."); setScanning(false); es.close(); };
  }

  const phaseStatus = (id: string) => phases.find((p) => p.id === id)?.status ?? "pending";

  return (
    <div className="min-h-full">
      {/* top bar */}
      <header className="no-print border-b hairline">
        <div className="max-w-5xl mx-auto px-5 h-14 flex items-center justify-between">
          <div className="flex items-center gap-2.5">
            <ShieldGlyph />
            <span className="font-mono text-sm font-semibold tracking-tight">SENTINEL</span>
            <span className="eyebrow hidden sm:block ml-1">Exposure Engine</span>
          </div>
          <div className="flex items-center gap-3">
            <ThemeSwitcher />
          </div>
        </div>
      </header>

      <main className="max-w-5xl mx-auto px-5 pb-24">
        {/* hero + console */}
        {!report && (
          <section className="pt-6 sm:pt-10">
            <p className="eyebrow rise" style={{ animationDelay: "0ms" }}>OSINT exposure assessment</p>
            <h1 className="text-2xl sm:text-3xl font-semibold tracking-tight mt-2 rise" style={{ animationDelay: "60ms" }}>
              Is your domain <span className="text-[color:var(--color-primary)]">leaking credentials?</span>
            </h1>
            <p className="mt-3 text-sm text-[color:var(--color-secondary)] max-w-xl rise" style={{ animationDelay: "120ms" }}>
              Enter a domain. Sentinel checks breach dumps, infostealer logs, public code, and your live attack surface — using only open-source tools — and hands you an exportable report.
            </p>

            {/* scan console */}
            <div className="panel mt-9 p-1.5 rise" style={{ animationDelay: "180ms" }}>
              <div className="flex flex-col sm:flex-row gap-1.5">
                <div className="flex items-center flex-1 gap-3 px-4 py-3">
                  <span className="font-mono text-[color:var(--color-secondary)] select-none">scan</span>
                  <span className="text-[color:var(--color-secondary)]/50">›</span>
                  <input
                    className="mono bg-transparent outline-none flex-1 text-lg placeholder:text-[color:var(--color-secondary)]/40"
                    placeholder="example.com"
                    value={domain}
                    autoFocus
                    spellCheck={false}
                    onChange={(e) => { setDomain(e.target.value); setVerified(false); setVerifyInfo(null); setVerifyMsg(""); }}
                    onKeyDown={(e) => e.key === "Enter" && startScan()}
                    disabled={scanning}
                  />
                </div>
                <button
                  className="btn border-0 text-base font-medium px-6 h-auto py-3 bg-[color:var(--color-primary)] text-[color:var(--color-primary-content)] hover:brightness-110 disabled:opacity-40 rounded-[var(--radius-field)]"
                  onClick={startScan}
                  disabled={!validDomain || scanning}
                >
                  {scanning ? <span className="loading loading-spinner loading-sm" /> : <>Run scan <span className="ml-1">→</span></>}
                </button>
              </div>
            </div>
            {domain && !validDomain && <p className="text-[color:var(--sev-high)] text-sm mt-2 font-mono">✗ not a valid domain</p>}

            {/* scan modules checklist */}
            <div className="panel mt-6 p-5 rise" style={{ animationDelay: "240ms" }}>
              <div className="flex items-center justify-between mb-3">
                <span className="eyebrow">Scan modules</span>
                <label className="flex items-center gap-2 cursor-pointer select-none text-xs font-mono text-[color:var(--color-secondary)]">
                  <input type="checkbox" className="checkbox checkbox-xs checkbox-primary" checked={allOn} onChange={toggleAll} />
                  select all
                </label>
              </div>
              <div className="grid sm:grid-cols-2 gap-2">
                {PHASE_LABELS.map((p) => {
                  const active = selected.has(p.id);
                  return (
                    <label
                      key={p.id}
                      className="flex items-start gap-3 p-3 rounded-[var(--radius-field)] border cursor-pointer transition"
                      style={{
                        borderColor: active ? "color-mix(in oklab, var(--color-primary) 35%, transparent)" : "var(--hairline)",
                        background: active ? "color-mix(in oklab, var(--color-primary) 7%, transparent)" : "transparent",
                      }}
                    >
                      <input type="checkbox" className="checkbox checkbox-sm checkbox-primary mt-0.5" checked={active} onChange={() => toggle(p.id)} />
                      <div className="min-w-0">
                        <div className="text-sm font-medium flex items-center gap-1.5">
                          {p.title}
                          {p.gated && !verified && <span className="text-[color:var(--color-secondary)]"><LockGlyph /></span>}
                        </div>
                        <div className="text-[0.72rem] text-[color:var(--color-secondary)] truncate">{p.desc}</div>
                      </div>
                    </label>
                  );
                })}
              </div>
              <div className="mt-3 flex items-center justify-between flex-wrap gap-2">
                <span className="text-[0.72rem] font-mono text-[color:var(--color-secondary)]">
                  {selected.size} of {PHASE_LABELS.length} modules · {verified ? "verified" : "passive only"}
                </span>
                <button
                  className="font-mono text-[0.72rem] px-3 py-1.5 rounded-[var(--radius-field)] border transition"
                  style={{
                    borderColor: verified ? "color-mix(in oklab, var(--color-success) 45%, transparent)" : "var(--hairline)",
                    color: verified ? "var(--color-success)" : "var(--color-secondary)",
                  }}
                  onClick={() => { setVerifyOpen((v) => !v); if (!verifyInfo) getToken(); }}
                >
                  {verified ? "✓ domain verified" : "+ verify domain (unlock active scan)"}
                </button>
              </div>
            </div>

            {/* verification panel */}
            {verifyOpen && !verified && (
              <div className="panel mt-4 p-5 fadein">
                <p className="text-sm text-[color:var(--color-secondary)]">
                  Active scanning touches live servers, so it is gated behind proof of ownership. Add this DNS <span className="mono">TXT</span> record, then check.
                </p>
                {verifyInfo && (
                  <div className="console mt-4">
                    <div className="console-bar px-3 py-2 flex items-center gap-2">
                      <Dot color="var(--sev-medium)" /><Dot color="var(--color-secondary)" /><Dot color="var(--color-secondary)" />
                      <span className="ml-1 text-[0.7rem] opacity-50">dns record</span>
                    </div>
                    <pre className="px-4 py-3 text-xs whitespace-pre-wrap text-[color:var(--color-base-content)]/90">{verifyInfo.recordName}  IN  TXT  &quot;{verifyInfo.token}&quot;</pre>
                  </div>
                )}
                <div className="mt-4 flex items-center gap-3">
                  <button className="btn btn-sm border hairline bg-transparent hover:bg-white/5 text-[color:var(--color-base-content)]" onClick={checkVerify} disabled={checking}>
                    {checking ? <span className="loading loading-spinner loading-xs" /> : "Check verification"}
                  </button>
                  {verifyMsg && <span className="text-xs font-mono text-[color:var(--color-secondary)]">{verifyMsg}</span>}
                </div>
              </div>
            )}
          </section>
        )}

        {error && <div className="no-print panel mt-6 p-4 border-l-2" style={{ borderLeftColor: "var(--sev-high)" }}><span className="font-mono text-sm text-[color:var(--sev-high)]">{error}</span></div>}

        {/* live progress */}
        {(scanning || (phases.length > 0 && !report)) && (
          <section ref={progressRef} className="no-print mt-8 grid lg:grid-cols-[1fr_1.2fr] gap-5 scroll-mt-6">
            {/* timeline */}
            <div className="panel p-5">
              <div className="flex items-center justify-between mb-4">
                <span className="eyebrow">Live pipeline</span>
                {scanning && <span className="flex items-center gap-2 text-xs font-mono text-[color:var(--color-primary)]"><span className="w-1.5 h-1.5 rounded-full bg-[color:var(--color-primary)] tl-running inline-block" />running</span>}
              </div>
              <ol className="relative">
                {phases.map((p, i) => {
                  const done = p.status === "done", running = p.status === "running", skipped = p.status === "skipped";
                  const color = done ? "var(--color-success)" : running ? "var(--color-primary)" : skipped ? "var(--color-secondary)" : "var(--hairline-strong)";
                  return (
                    <li key={p.id} className="flex gap-3 pb-4 last:pb-0">
                      <div className="flex flex-col items-center">
                        <span className={`w-2.5 h-2.5 rounded-full tl-dot ${running ? "tl-running" : ""}`} style={{ background: color }} />
                        {i < phases.length - 1 && <span className="w-px flex-1 mt-1" style={{ background: "var(--hairline)" }} />}
                      </div>
                      <div className="-mt-0.5 pb-1">
                        <div className="text-sm font-medium flex items-center gap-2">
                          {p.title}
                          {done && <span className="text-[color:var(--color-success)]">✓</span>}
                        </div>
                        <div className="font-mono text-[0.68rem] text-[color:var(--color-secondary)]">
                          {running ? "scanning…" : skipped ? p.note || "skipped" : done ? "complete" : "queued"}
                        </div>
                      </div>
                    </li>
                  );
                })}
              </ol>
              {Object.keys(stats).length > 0 && (
                <div className="mt-4 pt-4 border-t hairline flex flex-wrap gap-2">
                  {Object.entries(stats).map(([k, v]) => (
                    <span key={k} className="font-mono text-[0.7rem] px-2 py-1 rounded border hairline text-[color:var(--color-secondary)]">
                      {k} <b className="text-[color:var(--color-base-content)] ml-1">{v}</b>
                    </span>
                  ))}
                </div>
              )}
            </div>

            {/* console */}
            <div className="console self-start">
              <div className="console-bar px-3 py-2 flex items-center gap-2">
                <Dot color="var(--sev-critical)" /><Dot color="var(--sev-medium)" /><Dot color="var(--sev-clean)" />
                <span className="ml-2 text-[0.7rem] opacity-50 mono">sentinel@scan — {domain}</span>
              </div>
              <div className="p-3 text-xs max-h-[22rem] overflow-auto space-y-0.5">
                {logs.length === 0 && <div className="opacity-40">initializing pipeline…</div>}
                {logs.map((l, i) => (
                  <div key={i} className="fadein flex gap-2">
                    <span className="text-[color:var(--color-primary)]/70 select-none">›</span>
                    <span className="text-[color:var(--color-base-content)]/85 break-all">{l}</span>
                  </div>
                ))}
                {liveFindings.map((f) => (
                  <div key={f.id} className={`fadein flex gap-2 sev-${f.severity}`}>
                    <span style={{ color: "var(--sev)" }} className="select-none">◆</span>
                    <span style={{ color: "var(--sev)" }}>{f.title}</span>
                  </div>
                ))}
                {scanning && <div className="inline-block w-2 h-4 bg-[color:var(--color-primary)] animate-pulse align-middle" />}
              </div>
            </div>
          </section>
        )}

        {/* report */}
        {report && (
          <div className="mt-8">
            <button
              className="no-print btn btn-sm btn-ghost gap-1.5 mb-3 text-[color:var(--color-secondary)] hover:text-[color:var(--color-base-content)]"
              onClick={() => {
                setReport(null);
                setDomain("");
                window.history.replaceState(null, "", window.location.pathname);
              }}
            >
              ← New scan
            </button>
            <ReportView report={report} />
          </div>
        )}
      </main>
    </div>
  );
}

function ShieldGlyph() {
  return (
    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" aria-hidden>
      <path d="M12 2l7 3v6c0 4.5-3 8.3-7 9-4-0.7-7-4.5-7-9V5l7-3z" stroke="var(--color-primary)" strokeWidth="1.6" strokeLinejoin="round" />
      <path d="M9 12l2 2 4-4" stroke="var(--color-primary)" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  );
}
function LockGlyph() {
  return (
    <svg width="10" height="10" viewBox="0 0 24 24" fill="none" aria-hidden>
      <rect x="5" y="11" width="14" height="9" rx="2" stroke="currentColor" strokeWidth="2" />
      <path d="M8 11V8a4 4 0 018 0v3" stroke="currentColor" strokeWidth="2" />
    </svg>
  );
}
function Dot({ color }: { color: string }) {
  return <span className="w-2.5 h-2.5 rounded-full inline-block" style={{ background: color, opacity: 0.85 }} />;
}
