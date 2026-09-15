"use client";

import { Chapter4BenchmarkRunner } from "@/components/Chapter4BenchmarkRunner";
import { PageHeader } from "@/components/common";

export default function BenchmarkPage() {
  return (
    <div className="space-y-6">
      <PageHeader
        title="Benchmark Runner"
        description="Empirical DevSecOps evaluation comparing Dynamic Application Security Testing (DAST via OWASP ZAP v2.15.0) against Interactive Application Security Testing (IAST via Aegis v0.3.0)."
      />
      <Chapter4BenchmarkRunner />
    </div>
  );
}
