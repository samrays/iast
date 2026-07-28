import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { ApiError, api, refreshAccessToken, tokenStore } from "./api-client";

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json" },
  });
}

function problemResponse(status: number, code: string, detail: string): Response {
  return new Response(
    JSON.stringify({
      type: `https://docs.aegis.dev/errors/${code}`,
      title: code,
      status,
      detail,
      instance: "/api/v1/test",
      code,
      request_id: "req-123",
      errors: [{ field: "password", code: "policy", message: "Password must be longer." }],
    }),
    { status, headers: { "content-type": "application/problem+json" } },
  );
}

const futureExpiry = () => new Date(Date.now() + 900_000).toISOString();

describe("token store", () => {
  beforeEach(() => tokenStore.clear());

  it("holds the token in memory and never touches storage", () => {
    const setItem = vi.spyOn(Storage.prototype, "setItem");
    tokenStore.set("token-abc", futureExpiry());

    expect(tokenStore.get()).toBe("token-abc");
    // The single most important property of this module (threat T-12).
    expect(setItem).not.toHaveBeenCalled();
    expect(window.localStorage.length).toBe(0);
  });

  it("reports a missing token as stale", () => {
    expect(tokenStore.isStale()).toBe(true);
  });

  it("treats an almost-expired token as stale so a refresh happens first", () => {
    tokenStore.set("token-abc", new Date(Date.now() + 5_000).toISOString());
    expect(tokenStore.isStale(30_000)).toBe(true);
    expect(tokenStore.isStale(1_000)).toBe(false);
  });

  it("clears on demand", () => {
    tokenStore.set("token-abc", futureExpiry());
    tokenStore.clear();
    expect(tokenStore.get()).toBeNull();
  });
});

describe("refresh", () => {
  beforeEach(() => tokenStore.clear());
  afterEach(() => vi.unstubAllGlobals());

  it("is single-flight so concurrent 401s cannot trip reuse detection", async () => {
    // Two parallel refreshes would present the same cookie twice and the API would revoke
    // the whole token family (ADR-0006). One shared promise is the entire point.
    const fetchMock = vi.fn().mockResolvedValue(
      jsonResponse({ access_token: "fresh", expires_at: futureExpiry() }),
    );
    vi.stubGlobal("fetch", fetchMock);

    const [a, b, c] = await Promise.all([
      refreshAccessToken(),
      refreshAccessToken(),
      refreshAccessToken(),
    ]);

    expect([a, b, c]).toEqual([true, true, true]);
    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(tokenStore.get()).toBe("fresh");
  });

  it("sends credentials so the HttpOnly cookie travels", async () => {
    const fetchMock = vi.fn().mockResolvedValue(
      jsonResponse({ access_token: "fresh", expires_at: futureExpiry() }),
    );
    vi.stubGlobal("fetch", fetchMock);

    await refreshAccessToken();

    const [, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(init.credentials).toBe("include");
  });

  it("clears the token when the session is gone", async () => {
    tokenStore.set("stale", futureExpiry());
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(new Response(null, { status: 401 })));

    await expect(refreshAccessToken()).resolves.toBe(false);
    expect(tokenStore.get()).toBeNull();
  });

  it("keeps the token on a network error rather than signing the user out", async () => {
    tokenStore.set("still-good", futureExpiry());
    vi.stubGlobal("fetch", vi.fn().mockRejectedValue(new TypeError("offline")));

    await expect(refreshAccessToken()).resolves.toBe(false);
    expect(tokenStore.get()).toBe("still-good");
  });
});

describe("request handling", () => {
  beforeEach(() => tokenStore.clear());
  afterEach(() => vi.unstubAllGlobals());

  it("retries exactly once after refreshing on a 401", async () => {
    tokenStore.set("expired", futureExpiry());
    const fetchMock = vi
      .fn()
      // first call: the protected endpoint rejects
      .mockResolvedValueOnce(problemResponse(401, "invalid_token", "Expired."))
      // second call: the refresh succeeds
      .mockResolvedValueOnce(jsonResponse({ access_token: "fresh", expires_at: futureExpiry() }))
      // third call: the retried request
      .mockResolvedValueOnce(jsonResponse({ items: [], page: { next_cursor: null, has_more: false, limit: 25 } }));
    vi.stubGlobal("fetch", fetchMock);

    const result = await api.applications.list();

    expect(result.items).toEqual([]);
    expect(fetchMock).toHaveBeenCalledTimes(3);
  });

  it("does not retry a 403 — the permission will not change on a second attempt", async () => {
    tokenStore.set("valid", futureExpiry());
    const fetchMock = vi
      .fn()
      .mockResolvedValue(problemResponse(403, "permission_denied", "Needs app:read."));
    vi.stubGlobal("fetch", fetchMock);

    await expect(api.applications.list()).rejects.toBeInstanceOf(ApiError);
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it("surfaces the problem document, including field errors", async () => {
    tokenStore.set("valid", futureExpiry());
    // A Response body can only be read once, and this test issues two requests — so the
    // mock must mint a fresh Response per call rather than hand back the same instance.
    vi.stubGlobal(
      "fetch",
      vi.fn().mockImplementation(async () =>
        problemResponse(422, "weak_password", "Password is too weak."),
      ),
    );

    await expect(api.auth.changePassword("old", "short")).rejects.toMatchObject({
      status: 422,
      code: "weak_password",
      message: "Password is too weak.",
    });

    try {
      await api.auth.changePassword("old", "short");
    } catch (error) {
      expect(error).toBeInstanceOf(ApiError);
      expect((error as ApiError).fieldErrors).toEqual({
        password: "Password must be longer.",
      });
      expect((error as ApiError).requestId).toBe("req-123");
    }
  });

  it("omits the Authorization header on anonymous calls", async () => {
    tokenStore.set("should-not-be-sent", futureExpiry());
    const fetchMock = vi
      .fn()
      .mockResolvedValue(jsonResponse({ access_token: "x", expires_at: futureExpiry(), session_id: "s" }));
    vi.stubGlobal("fetch", fetchMock);

    await api.auth.login("user@example.com", "password");

    const [, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect((init.headers as Record<string, string>).Authorization).toBeUndefined();
  });

  it("serializes array query parameters as repeated keys", async () => {
    tokenStore.set("valid", futureExpiry());
    const fetchMock = vi
      .fn()
      .mockResolvedValue(jsonResponse({ items: [], page: { next_cursor: null, has_more: false, limit: 25 } }));
    vi.stubGlobal("fetch", fetchMock);

    await api.applications.list({ tag: ["pci", "payments"], q: "pay" });

    const [url] = fetchMock.mock.calls[0] as [string];
    expect(url).toContain("tag=pci");
    expect(url).toContain("tag=payments");
    expect(url).toContain("q=pay");
  });

  it("returns undefined for a 204 rather than trying to parse a body", async () => {
    tokenStore.set("valid", futureExpiry());
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(new Response(null, { status: 204 })));

    await expect(api.applications.remove("018f-abc")).resolves.toBeUndefined();
  });
});
