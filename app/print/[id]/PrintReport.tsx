"use client";
import { useEffect } from "react";
import ReportDoc from "@/components/ReportDoc";
import type { Report } from "@/lib/types";

export default function PrintReport({ report, theme }: { report: Report; theme: string }) {
  useEffect(() => {
    document.documentElement.setAttribute("data-theme", theme);
    // full-bleed themed page (no atmosphere, no white margins in the PDF)
    const atm = document.querySelector<HTMLElement>(".atmosphere");
    if (atm) atm.style.display = "none";
    document.documentElement.style.background = "var(--color-base-300)";
    document.body.style.background = "var(--color-base-300)";
  }, [theme]);

  return (
    <div style={{ padding: "12mm 14mm 16mm", background: "var(--color-base-300)", minHeight: "100vh" }}>
      <ReportDoc report={report} />
    </div>
  );
}
