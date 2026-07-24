"use client";
import { Analytics, Severity } from "@/lib/types";

const SEV_VAR: Record<Severity, string> = {
  critical: "var(--sev-critical)", high: "var(--sev-high)", medium: "var(--sev-medium)",
  low: "var(--sev-low)", info: "var(--sev-info)", clean: "var(--sev-clean)",
};
const COLUMN: Record<string, number> = { domain: 0, ip: 1, asn: 2, host: 1, finding: 3 };
const COL_X = [70, 300, 530, 760];

export default function RiskGraph({ graph }: { graph: Analytics["graph"] }) {
  if (!graph.nodes.length) return null;
  // Layered layout: bucket nodes by column, space evenly on Y.
  const cols: Record<number, typeof graph.nodes> = {};
  for (const n of graph.nodes) { const c = COLUMN[n.kind] ?? 1; (cols[c] ||= []).push(n); }
  const pos = new Map<string, { x: number; y: number }>();
  const ROW = 46, TOP = 40;
  let maxRows = 0;
  for (const [c, list] of Object.entries(cols)) {
    maxRows = Math.max(maxRows, list.length);
    list.forEach((n, i) => pos.set(n.id, { x: COL_X[Number(c)] ?? 300, y: TOP + i * ROW }));
  }
  const height = TOP + maxRows * ROW + 20;

  return (
    <div className="overflow-x-auto">
      <svg viewBox={`0 0 840 ${height}`} width="100%" style={{ minWidth: 640 }} role="img" aria-label="Asset relationship graph">
        {graph.edges.map((e, i) => {
          const a = pos.get(e.from), b = pos.get(e.to);
          if (!a || !b) return null;
          return <line key={i} x1={a.x + 60} y1={a.y} x2={b.x - 60} y2={b.y} stroke="var(--hairline)" strokeWidth={1} />;
        })}
        {graph.nodes.map((n) => {
          const p = pos.get(n.id)!;
          const fill = n.severity ? SEV_VAR[n.severity] : "var(--color-primary)";
          return (
            <g key={n.id} transform={`translate(${p.x},${p.y})`}>
              <rect x={-60} y={-14} width={120} height={28} rx={6}
                fill="color-mix(in oklab, var(--color-base-200) 70%, transparent)" stroke={fill} strokeWidth={1.4} />
              <text x={0} y={4} textAnchor="middle" className="mono"
                style={{ fill: "var(--color-base-content)", fontSize: 9 }}>
                {n.label.length > 18 ? n.label.slice(0, 17) + "…" : n.label}
              </text>
            </g>
          );
        })}
      </svg>
    </div>
  );
}
