import { describe, expect, it } from "vitest";
import { AegisAgent, checkSqlSink, markTainted } from "../src/index.js";

describe("Aegis Node.js Agent Taint & Sink Engine", () => {
  it("initializes agent successfully", () => {
    const agent = AegisAgent.start({ agentId: "node-1", organizationId: "org-1" });
    expect(agent.agentId).toBe("node-1");
    expect(agent.organizationId).toBe("org-1");
  });

  it("detects SQL injection with AsyncLocalStorage trace context", () => {
    const agent = AegisAgent.start({ agentId: "node-1", organizationId: "org-1" });

    agent.runWithRequest("/users/search", "GET", { id: "' OR '1'='1" }, () => {
      const taintedInput = markTainted("' OR '1'='1", "PARAMETER", "id");
      const query = `SELECT * FROM users WHERE id = ${taintedInput}`;

      const finding = agent.inspectQuery(query);
      expect(finding).not.toBeNull();
      expect(finding?.ruleKey).toBe("sql-injection");
      expect(finding?.severity).toBe("CRITICAL");
      expect(agent.eventBuffer.length).toBe(1);
    });
  });

  it("produces no finding for clean untainted query", () => {
    const cleanQuery = "SELECT * FROM users WHERE id = 123";
    const finding = checkSqlSink(cleanQuery);
    expect(finding).toBeNull();
  });
});
