import assert from "node:assert/strict";
import test from "node:test";

import { unexpectedVulnerabilities } from "./check_npm_audit.mjs";

const allowedPostcss = {
  name: "postcss",
  severity: "high",
  via: [{ source: 1124252, severity: "high" }],
};

test("allows only the named advisory through its wrapper package", () => {
  const report = {
    vulnerabilities: {
      next: { name: "next", severity: "high", via: ["postcss"] },
      postcss: allowedPostcss,
    },
  };

  assert.deepEqual(unexpectedVulnerabilities(report), []);
});

test("rejects a new advisory on an otherwise allowed package", () => {
  const report = {
    vulnerabilities: {
      postcss: {
        ...allowedPostcss,
        via: [...allowedPostcss.via, { source: 9999999, severity: "high" }],
      },
    },
  };

  assert.deepEqual(unexpectedVulnerabilities(report), ["postcss"]);
});

test("rejects a new high-severity package", () => {
  const report = {
    vulnerabilities: {
      unrelated: {
        name: "unrelated",
        severity: "critical",
        via: [{ source: 9999999, severity: "critical" }],
      },
    },
  };

  assert.deepEqual(unexpectedVulnerabilities(report), ["unrelated"]);
});

test("rejects a wrapper whose reported dependency cause is missing", () => {
  const report = {
    vulnerabilities: {
      wrapper: { name: "wrapper", severity: "high", via: ["missing"] },
    },
  };

  assert.deepEqual(unexpectedVulnerabilities(report), ["wrapper"]);
});

test("ignores findings below the CI severity threshold", () => {
  const report = {
    vulnerabilities: {
      lowRisk: {
        name: "low-risk",
        severity: "moderate",
        via: [{ source: 9999999, severity: "moderate" }],
      },
    },
  };

  assert.deepEqual(unexpectedVulnerabilities(report), []);
});
