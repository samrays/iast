import { checkCommandSink, checkSqlSink, FindingEvent } from "./sinks.js";
import { getCurrentTrace, markTainted, startTraceContext } from "./taint.js";

export interface AgentConfig {
  agentId: string;
  organizationId: string;
  gatewayUrl?: string;
}

export class AegisAgent {
  public readonly agentId: string;
  public readonly organizationId: string;
  public readonly gatewayUrl: string;
  public readonly eventBuffer: FindingEvent[] = [];

  constructor(config: AgentConfig) {
    this.agentId = config.agentId;
    this.organizationId = config.organizationId;
    this.gatewayUrl = config.gatewayUrl || "http://localhost:8081";
  }

  public static start(config: AgentConfig): AegisAgent {
    const agent = new AegisAgent(config);
    return agent;
  }

  public runWithRequest<T>(
    route: string,
    method: string,
    params: Record<string, string>,
    fn: () => T
  ): T {
    const traceId = `node-trace-${Math.random().toString(36).substring(2, 10)}`;
    return startTraceContext(traceId, route, method, () => {
      for (const [key, val] of Object.entries(params)) {
        markTainted(val, "PARAMETER", key);
      }
      return fn();
    });
  }

  public inspectQuery(sql: string): FindingEvent | null {
    const finding = checkSqlSink(sql);
    if (finding) {
      this.eventBuffer.push(finding);
    }
    return finding;
  }
}

export { checkCommandSink, checkSqlSink, getCurrentTrace, markTainted, startTraceContext };
