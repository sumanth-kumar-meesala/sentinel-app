import { test } from "node:test";
import assert from "node:assert/strict";
import type { Report } from "./types";
import { scoreReport } from "./score.ts";

function base(): Report {
  return {
    runId: "t-1", domain: "example.com", verified: false,
    startedAt: "2026-07-24T00:00:00Z", finishedAt: "2026-07-24T00:05:00Z",
    stats: {}, findings: [], subdomains: [], emails: [],
    evidenceFiles: [], toolStatus: [],
    liveHosts: [], stealerUrls: [], apexIps: [], relatedAssets: [], typosquats: [],
  };
}

test("vizury-like report scores F / Critical", () => {
  const r = base();
  r.stats = { stealerRecords: 36, subdomains: 83, emailsExposed: 12, exposedServices: 2 };
  r.subdomains = Array.from({ length: 83 }, (_, i) => `h${i}.example.com`);
  r.findings = [
    { id: "f1", phase: "breach", severity: "high", title: "36 credential sets stolen by infostealer malware", detail: "Includes INTERNAL systems (HR/admin)." },
  ];
  r.dns = { spf: true, spfStrict: true, dmarc: "missing", dnssec: false, dkimSelectors: [] };
  const s = scoreReport(r);
  assert.ok(s.score < 60, `expected F-band score, got ${s.score}`);
  assert.equal(s.grade, "F");
  assert.equal(s.riskLevel, "critical");
});

test("clean report scores A / Low", () => {
  const r = base();
  r.dns = { spf: true, spfStrict: true, dmarc: "enforced", dnssec: true, dkimSelectors: ["default"] };
  const s = scoreReport(r);
  assert.ok(s.score >= 90, `expected A-band, got ${s.score}`);
  assert.equal(s.grade, "A");
  assert.equal(s.riskLevel, "low");
});

test("dimensions sum to weight 100", () => {
  const s = scoreReport(base());
  assert.equal(s.dimensions.reduce((a, d) => a + d.weight, 0), 100);
});

import { correlate } from "./score.ts";

test("stolen credential URL on a live host fires a critical correlation", () => {
  const r = base();
  r.stealerUrls = ["https://adpatchmanager.example.com:17450/configurations.do"];
  r.liveHosts = ["adpatchmanager.example.com"];
  const c = correlate(r);
  assert.ok(c.some((x) => x.severity === "critical" && /live/i.test(x.title)),
    "expected a critical stolen-cred ∩ live-host correlation");
});

test("no compound risks yields empty correlation list", () => {
  assert.deepEqual(correlate(base()), []);
});

import { computeAnalytics, buildTrend, toCsv } from "./score.ts";

test("computeAnalytics attaches score, correlations, and graph", () => {
  const r = base();
  r.stealerUrls = ["https://a.example.com/login"]; r.liveHosts = ["a.example.com"];
  r.apexIps = ["1.2.3.4"];
  const a = computeAnalytics(r);
  assert.ok(a.score >= 0 && a.score <= 100);
  assert.ok(a.correlations.length >= 1);
  assert.ok(a.graph.nodes.some((n) => n.kind === "domain"));
  assert.equal(a.trend, null);
});

test("buildTrend diffs findings and score", () => {
  const cur = base(); cur.findings = [{ id: "f1", phase: "dns", severity: "medium", title: "No DMARC", detail: "" }];
  const prior = base(); prior.runId = "t-0"; prior.finishedAt = "2026-06-30T00:00:00Z";
  prior.findings = [{ id: "p1", phase: "cloud", severity: "high", title: "Open bucket", detail: "" }];
  prior.analytics = { score: 40 } as any;
  const t = buildTrend(cur, prior, 71);
  assert.equal(t.scoreDelta, 31);
  assert.deepEqual(t.newFindings, ["No DMARC"]);
  assert.deepEqual(t.resolvedFindings, ["Open bucket"]);
});

test("toCsv escapes commas and quotes", () => {
  const csv = toCsv([{ id: "f1", phase: "dns", severity: "low", title: 'a,b', detail: 'he said "hi"' }]);
  assert.match(csv, /^id,phase,severity,title,detail/);
  assert.match(csv, /"a,b"/);
  assert.match(csv, /"he said ""hi"""/);
});
