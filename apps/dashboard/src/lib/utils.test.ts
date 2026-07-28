import { describe, expect, it, vi } from "vitest";

import {
  absoluteTime,
  compactNumber,
  describePermission,
  humanizeAction,
  humanizeEnum,
  initials,
  relativeTime,
} from "./utils";

describe("relativeTime", () => {
  it("handles the whole range an operator sees in a table", () => {
    const now = Date.now();
    vi.spyOn(Date, "now").mockReturnValue(now);

    expect(relativeTime(new Date(now - 5_000).toISOString())).toBe("5s ago");
    expect(relativeTime(new Date(now - 120_000).toISOString())).toBe("2m ago");
    expect(relativeTime(new Date(now - 7_200_000).toISOString())).toBe("2h ago");
    expect(relativeTime(new Date(now - 172_800_000).toISOString())).toBe("2d ago");
  });

  it("says 'never' rather than showing an epoch date", () => {
    expect(relativeTime(null)).toBe("never");
    expect(relativeTime(undefined)).toBe("never");
  });

  it("degrades gracefully on a malformed timestamp", () => {
    expect(relativeTime("not-a-date")).toBe("unknown");
  });

  it("never renders a negative duration for slight clock skew", () => {
    const now = Date.now();
    vi.spyOn(Date, "now").mockReturnValue(now);
    expect(relativeTime(new Date(now + 3_000).toISOString())).toBe("just now");
  });
});

describe("absoluteTime", () => {
  it("returns a dash for missing values", () => {
    expect(absoluteTime(null)).toBe("—");
    expect(absoluteTime("nonsense")).toBe("—");
  });

  it("renders a real timestamp", () => {
    expect(absoluteTime("2026-07-28T09:30:00Z")).toContain("2026");
  });
});

describe("humanizers", () => {
  it("turns API enums into sentence case", () => {
    expect(humanizeEnum("PENDING_DELETION")).toBe("Pending deletion");
    expect(humanizeEnum("ONLINE")).toBe("Online");
  });

  it("drops the audit action namespace", () => {
    expect(humanizeAction("application.created")).toBe("Created");
    expect(humanizeAction("security.token_reuse")).toBe("Token reuse");
  });

  it("describes a permission readably", () => {
    expect(describePermission("finding:triage")).toBe("Triage finding");
    expect(describePermission("app:read")).toBe("Read app");
  });
});

describe("initials", () => {
  it("uses both name parts when available", () => {
    expect(initials("Ada Lovelace")).toBe("AL");
  });

  it("falls back to the email local part", () => {
    expect(initials("", "grace.hopper@example.com")).toBe("GH");
  });

  it("copes with a single token", () => {
    expect(initials("Prince")).toBe("PR");
  });

  it("never throws on empty input", () => {
    expect(initials("", "")).toBe("?");
  });
});

describe("compactNumber", () => {
  it("shortens large counts for stat tiles", () => {
    expect(compactNumber(1284)).toMatch(/1\.3K/i);
    expect(compactNumber(42)).toBe("42");
  });
});
