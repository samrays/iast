import { getCurrentTrace, isTainted } from "./taint.js";

export interface FindingEvent {
  ruleKey: string;
  severity: string;
  sinkSignature: string;
  sourceKind: string;
  sinkArgument: string;
  traceId: string;
}

export function checkSqlSink(sql: string, sinkSignature = "pg.Client.query"): FindingEvent | null {
  try {
    const { tainted, record } = isTainted(sql);
    if (!tainted || !record) {
      return null;
    }

    const trace = getCurrentTrace();
    const traceId = trace ? trace.traceId : "unknown-trace";
    const sourceKind = record.ranges[0] ? record.ranges[0].sourceKind : "PARAMETER";

    return {
      ruleKey: "sql-injection",
      severity: "CRITICAL",
      sinkSignature,
      sourceKind,
      sinkArgument: sql.substring(0, 2000),
      traceId,
    };
  } catch {
    // Fail-open safety: never break the application if inspection throws
    return null;
  }
}

export function checkCommandSink(cmd: string, sinkSignature = "child_process.exec"): FindingEvent | null {
  try {
    const { tainted, record } = isTainted(cmd);
    if (!tainted || !record) {
      return null;
    }

    const trace = getCurrentTrace();
    const traceId = trace ? trace.traceId : "unknown-trace";
    const sourceKind = record.ranges[0] ? record.ranges[0].sourceKind : "PARAMETER";

    return {
      ruleKey: "command-injection",
      severity: "CRITICAL",
      sinkSignature,
      sourceKind,
      sinkArgument: cmd.substring(0, 2000),
      traceId,
    };
  } catch {
    return null;
  }
}
