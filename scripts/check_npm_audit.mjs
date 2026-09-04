import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

// Next 15.5.25 pins PostCSS 8.4.31. npm currently requires a Next 16 framework
// upgrade to replace it. Keep the exception narrow: a new advisory, package, or
// transitive path still fails CI instead of inheriting this waiver accidentally.
export const ALLOWED_ADVISORIES = new Set([
  1117015, // GHSA-qx2v-qp2m-jg93
  1124252, // GHSA-6g55-p6wh-862q
  1130709, // GHSA-fxqj-rqcc-2cmp
  1139510, // GHSA-r28c-9q8g-f849
]);

const FAILING_SEVERITIES = new Set(["high", "critical"]);

export function unexpectedVulnerabilities(report) {
  const vulnerabilities = report?.vulnerabilities ?? {};
  const memo = new Map();

  function isAllowed(name, visiting = new Set()) {
    if (memo.has(name)) return memo.get(name);
    if (visiting.has(name)) return false;

    const vulnerability = vulnerabilities[name];
    if (!vulnerability) return false;
    if (!FAILING_SEVERITIES.has(vulnerability.severity)) {
      return true;
    }

    const nextVisiting = new Set(visiting).add(name);
    const allowed = vulnerability.via.every((cause) =>
      typeof cause === "string"
        ? isAllowed(cause, nextVisiting)
        : ALLOWED_ADVISORIES.has(cause.source),
    );
    memo.set(name, allowed);
    return allowed;
  }

  return Object.keys(vulnerabilities).filter(
    (name) =>
      FAILING_SEVERITIES.has(vulnerabilities[name].severity) &&
      !isAllowed(name),
  );
}

function runAudit() {
  const windows = process.platform === "win32";
  const executable = windows ? (process.env.ComSpec ?? "cmd.exe") : "npm";
  // Windows resolves npm through npm.cmd, which Node cannot execute directly. Invoke the
  // command processor with a fixed command string; no repository or user input reaches it.
  const args = windows
    ? ["/d", "/s", "/c", "npm audit --omit=dev --json"]
    : ["audit", "--omit=dev", "--json"];
  const result = spawnSync(executable, args, { encoding: "utf8" });

  if (result.error) {
    process.stderr.write(
      `npm audit could not start: ${result.error.message}\n`,
    );
    return 2;
  }

  let report;
  try {
    report = JSON.parse(result.stdout);
  } catch {
    process.stderr.write(
      result.stderr || result.stdout || "npm audit produced no JSON output.\n",
    );
    return 2;
  }

  const unexpected = unexpectedVulnerabilities(report);
  if (unexpected.length) {
    process.stderr.write(
      `Unexpected high/critical npm vulnerabilities: ${unexpected.join(", ")}\n`,
    );
    return 1;
  }

  const known = Object.keys(report.vulnerabilities ?? {}).filter((name) =>
    FAILING_SEVERITIES.has(report.vulnerabilities[name].severity),
  );
  process.stdout.write(
    known.length
      ? `Only explicitly deferred npm advisories remain: ${known.join(", ")}\n`
      : "No high or critical npm vulnerabilities found.\n",
  );
  return 0;
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  process.exitCode = runAudit();
}
