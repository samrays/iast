/**
 * Typed client for the control-plane API.
 *
 * Two properties matter more than anything else here and are worth stating plainly:
 *
 * 1. **The access token lives in memory only.** Never `localStorage`, never
 *    `sessionStorage`, never a readable cookie. A stored token survives the tab and is
 *    reachable from any injected script (threat T-12).
 * 2. **Refresh is single-flight.** The API revokes an entire token family when a consumed
 *    refresh token is replayed (ADR-0006). Two parallel 401s firing two refreshes would
 *    trip that on the client's own behaviour, so every caller awaits one shared promise.
 */

import type {
  ApiKeyIssued,
  ApiKeySummary,
  ApplicationSummary,
  AuditEventSummary,
  AgentSummary,
  ChainVerification,
  Criticality,
  CurrentPrincipal,
  DetectionRule,
  EnvironmentKind,
  EnvironmentSummary,
  Finding,
  FindingComment,
  FindingDetail,
  FindingStatus,
  Language,
  LoginResult,
  LogoutResponse,
  MemberSummary,
  MfaEnrolResponse,
  OrganizationSummary,
  Page,
  PermissionCatalogueEntry,
  ProblemDetail,
  ProtectionMode,
  RoleSummary,
  TokenResponse,
  Uuid,
} from "./types";

export const API_BASE_URL = (
  process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8080"
).replace(/\/$/, "");

const API_PREFIX = "/api/v1";

/** An API failure carrying the server's RFC 9457 problem document. */
export class ApiError extends Error {
  readonly status: number;
  readonly problem: ProblemDetail | null;

  constructor(status: number, problem: ProblemDetail | null, fallback: string) {
    super(problem?.detail || fallback);
    this.name = "ApiError";
    this.status = status;
    this.problem = problem;
  }

  get code(): string {
    return this.problem?.code ?? "unknown_error";
  }

  get requestId(): string {
    return this.problem?.request_id ?? "";
  }

  /** Field-level messages, for attaching to form inputs. */
  get fieldErrors(): Record<string, string> {
    const result: Record<string, string> = {};
    for (const item of this.problem?.errors ?? []) {
      result[item.field] = result[item.field]
        ? `${result[item.field]} ${item.message}`
        : item.message;
    }
    return result;
  }
}

// --- in-memory token store --------------------------------------------------------

interface TokenState {
  accessToken: string | null;
  expiresAt: number | null;
}

const state: TokenState = { accessToken: null, expiresAt: null };
let refreshInFlight: Promise<boolean> | null = null;
const listeners = new Set<(authenticated: boolean) => void>();

export const tokenStore = {
  set(token: string, expiresAt: string): void {
    state.accessToken = token;
    state.expiresAt = new Date(expiresAt).getTime();
    listeners.forEach((listener) => listener(true));
  },
  clear(): void {
    state.accessToken = null;
    state.expiresAt = null;
    listeners.forEach((listener) => listener(false));
  },
  get(): string | null {
    return state.accessToken;
  },
  /**
   * True when the token is absent or within the skew window of expiring. Refreshing a
   * little early avoids a guaranteed 401 on a request that is already in flight.
   */
  isStale(skewMs = 30_000): boolean {
    if (!state.accessToken || state.expiresAt === null) return true;
    return Date.now() >= state.expiresAt - skewMs;
  },
  subscribe(listener: (authenticated: boolean) => void): () => void {
    listeners.add(listener);
    return () => listeners.delete(listener);
  },
};

// --- transport ---------------------------------------------------------------------

async function readProblem(response: Response): Promise<ProblemDetail | null> {
  const contentType = response.headers.get("content-type") ?? "";
  if (!contentType.includes("json")) return null;
  try {
    return (await response.json()) as ProblemDetail;
  } catch {
    return null;
  }
}

/**
 * Rotate the refresh cookie for a new access token.
 *
 * The refresh token itself is an `HttpOnly` cookie scoped to `/api/v1/auth`; this code
 * cannot read it and does not need to — `credentials: "include"` is what sends it.
 */
export async function refreshAccessToken(): Promise<boolean> {
  if (refreshInFlight) return refreshInFlight;

  refreshInFlight = (async () => {
    try {
      const response = await fetch(
        `${API_BASE_URL}${API_PREFIX}/auth/refresh`,
        {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          credentials: "include",
          body: JSON.stringify({}),
        },
      );
      if (!response.ok) {
        tokenStore.clear();
        return false;
      }
      const tokens = (await response.json()) as TokenResponse;
      tokenStore.set(tokens.access_token, tokens.expires_at);
      return true;
    } catch {
      // A network failure is not proof the session is gone; keep whatever we hold and let
      // the caller surface the error.
      return false;
    } finally {
      refreshInFlight = null;
    }
  })();

  return refreshInFlight;
}

interface RequestOptions {
  method?: "GET" | "POST" | "PATCH" | "PUT" | "DELETE";
  body?: unknown;
  query?: Record<
    string,
    string | number | boolean | string[] | undefined | null
  >;
  /** Skip the Authorization header and the refresh dance (login, MFA verify). */
  anonymous?: boolean;
  signal?: AbortSignal;
}

function buildUrl(path: string, query: RequestOptions["query"]): string {
  const url = new URL(`${API_BASE_URL}${API_PREFIX}${path}`);
  for (const [key, value] of Object.entries(query ?? {})) {
    if (value === undefined || value === null || value === "") continue;
    if (Array.isArray(value)) {
      value.forEach((item) => url.searchParams.append(key, item));
    } else {
      url.searchParams.set(key, String(value));
    }
  }
  return url.toString();
}

async function request<T>(
  path: string,
  options: RequestOptions = {},
): Promise<T> {
  const { method = "GET", body, query, anonymous = false, signal } = options;

  if (!anonymous && tokenStore.isStale()) {
    await refreshAccessToken();
  }

  const send = async (): Promise<Response> => {
    const headers: Record<string, string> = { Accept: "application/json" };
    if (body !== undefined) headers["Content-Type"] = "application/json";
    const token = tokenStore.get();
    if (!anonymous && token) headers.Authorization = `Bearer ${token}`;

    return fetch(buildUrl(path, query), {
      method,
      headers,
      credentials: "include",
      body: body === undefined ? undefined : JSON.stringify(body),
      ...(signal ? { signal } : {}),
    });
  };

  let response = await send();

  // One retry, and only for an expired credential. Retrying a 403 would just fail again;
  // retrying more than once risks the family-revocation path described above.
  if (response.status === 401 && !anonymous) {
    const refreshed = await refreshAccessToken();
    if (refreshed) {
      response = await send();
    }
  }

  if (!response.ok) {
    throw new ApiError(
      response.status,
      await readProblem(response),
      response.statusText,
    );
  }
  if (response.status === 204) return undefined as T;
  return (await response.json()) as T;
}

// --- endpoints ---------------------------------------------------------------------

export const api = {
  auth: {
    login: (email: string, password: string, organizationSlug?: string) =>
      request<LoginResult>("/auth/login", {
        method: "POST",
        anonymous: true,
        body: {
          email,
          password,
          ...(organizationSlug ? { organization_slug: organizationSlug } : {}),
        },
      }),

    verifyMfa: (challengeToken: string, code: string) =>
      request<TokenResponse>("/auth/mfa/verify", {
        method: "POST",
        anonymous: true,
        body: { challenge_token: challengeToken, code },
      }),

    register: (payload: {
      organization_name: string;
      email: string;
      password: string;
      full_name: string;
    }) =>
      request<{
        organization: OrganizationSummary;
        user_id: Uuid;
        email: string;
        tokens: TokenResponse;
      }>("/auth/register", { method: "POST", anonymous: true, body: payload }),

    me: (signal?: AbortSignal) =>
      request<CurrentPrincipal>("/auth/me", signal ? { signal } : {}),

    logout: () => request<LogoutResponse>("/auth/logout", { method: "POST" }),

    logoutAll: () =>
      request<LogoutResponse>("/auth/logout-all", { method: "POST" }),

    changePassword: (currentPassword: string, newPassword: string) =>
      request<LogoutResponse>("/auth/password/change", {
        method: "POST",
        body: { current_password: currentPassword, new_password: newPassword },
      }),

    enrolMfa: (password: string) =>
      request<MfaEnrolResponse>("/auth/mfa/enroll", {
        method: "POST",
        body: { password },
      }),

    confirmMfa: (code: string) =>
      request<void>("/auth/mfa/confirm", { method: "POST", body: { code } }),

    disableMfa: (password: string) =>
      request<void>("/auth/mfa/disable", {
        method: "POST",
        body: { password },
      }),
  },

  organization: {
    current: () => request<OrganizationSummary>("/organizations/current"),

    update: (payload: { name?: string; settings?: Record<string, unknown> }) =>
      request<OrganizationSummary>("/organizations/current", {
        method: "PATCH",
        body: payload,
      }),

    members: (params: { limit?: number; cursor?: string } = {}) =>
      request<Page<MemberSummary>>("/organizations/current/members", {
        query: params,
      }),

    invite: (payload: { email: string; full_name: string; role_ids: Uuid[] }) =>
      request<MemberSummary>("/organizations/current/members/invite", {
        method: "POST",
        body: payload,
      }),

    updateMember: (membershipId: Uuid, roleIds: Uuid[]) =>
      request<MemberSummary>(`/organizations/current/members/${membershipId}`, {
        method: "PATCH",
        body: { role_ids: roleIds },
      }),

    removeMember: (membershipId: Uuid) =>
      request<void>(`/organizations/current/members/${membershipId}`, {
        method: "DELETE",
      }),

    roles: () => request<RoleSummary[]>("/organizations/current/roles"),

    createRole: (payload: {
      name: string;
      description: string;
      permissions: string[];
    }) =>
      request<RoleSummary>("/organizations/current/roles", {
        method: "POST",
        body: payload,
      }),

    updateRole: (
      roleId: Uuid,
      payload: { name?: string; description?: string; permissions?: string[] },
    ) =>
      request<RoleSummary>(`/organizations/current/roles/${roleId}`, {
        method: "PATCH",
        body: payload,
      }),

    deleteRole: (roleId: Uuid) =>
      request<void>(`/organizations/current/roles/${roleId}`, {
        method: "DELETE",
      }),
  },

  permissions: {
    catalogue: () => request<PermissionCatalogueEntry[]>("/permissions"),
  },

  apiKeys: {
    list: () => request<ApiKeySummary[]>("/api-keys"),

    create: (payload: {
      name: string;
      permissions: string[];
      expires_in_days: number | null;
    }) => request<ApiKeyIssued>("/api-keys", { method: "POST", body: payload }),

    revoke: (id: Uuid) =>
      request<void>(`/api-keys/${id}`, { method: "DELETE" }),
  },

  applications: {
    list: (
      params: {
        limit?: number;
        cursor?: string;
        q?: string;
        tag?: string[];
      } = {},
    ) => request<Page<ApplicationSummary>>("/applications", { query: params }),

    get: (id: Uuid) => request<ApplicationSummary>(`/applications/${id}`),

    create: (payload: {
      name: string;
      language: Language;
      criticality: Criticality;
      tags: string[];
      repository_url?: string | null;
      description: string;
      environments: Array<{ kind: EnvironmentKind; internet_facing: boolean }>;
    }) =>
      request<ApplicationSummary>("/applications", {
        method: "POST",
        body: payload,
      }),

    update: (
      id: Uuid,
      payload: {
        name?: string;
        criticality?: Criticality;
        tags?: string[];
        repository_url?: string | null;
        description?: string;
      },
    ) =>
      request<ApplicationSummary>(`/applications/${id}`, {
        method: "PATCH",
        body: payload,
      }),

    remove: (id: Uuid) =>
      request<void>(`/applications/${id}`, { method: "DELETE" }),

    environments: (id: Uuid) =>
      request<EnvironmentSummary[]>(`/applications/${id}/environments`),

    addEnvironment: (
      id: Uuid,
      payload: { kind: EnvironmentKind; internet_facing: boolean },
    ) =>
      request<EnvironmentSummary>(`/applications/${id}/environments`, {
        method: "POST",
        body: payload,
      }),
  },

  environments: {
    setProtection: (environmentId: Uuid, mode: ProtectionMode) =>
      request<EnvironmentSummary>(`/environments/${environmentId}/protection`, {
        method: "PUT",
        body: { mode },
      }),
  },

  agents: {
    list: (params: { limit?: number; cursor?: string; status?: string } = {}) =>
      request<Page<AgentSummary>>("/agents", { query: params }),

    get: (id: Uuid) => request<AgentSummary>(`/agents/${id}`),

    update: (
      id: Uuid,
      payload: { enabled?: boolean; pinned_version?: string | null },
    ) =>
      request<AgentSummary>(`/agents/${id}`, {
        method: "PATCH",
        body: payload,
      }),
  },

  findings: {
    list: (
      params: {
        limit?: number;
        cursor?: string;
        status?: string[];
        severity?: string[];
        rule_key?: string;
        application_id?: string;
        environment?: string;
        search?: string;
      } = {},
    ) => request<Page<Finding>>("/findings", { query: params }),

    get: (id: string) => request<FindingDetail>(`/findings/${id}`),

    triage: (
      id: string,
      body: {
        status: FindingStatus;
        note?: string;
        accepted_for_days?: number;
      },
    ) => request<Finding>(`/findings/${id}`, { method: "PATCH", body }),

    comment: (id: string, body: string) =>
      request<FindingComment>(`/findings/${id}/comments`, {
        method: "POST",
        body: { body },
      }),
  },

  rules: {
    list: () => request<DetectionRule[]>("/rules"),

    setEnabled: (key: string, body: { enabled: boolean; reason?: string }) =>
      request<DetectionRule>(`/rules/${key}`, { method: "PUT", body }),
  },

  audit: {
    list: (
      params: {
        limit?: number;
        cursor?: string;
        action?: string;
        actor_user_id?: string;
        occurred_after?: string;
      } = {},
    ) => request<Page<AuditEventSummary>>("/audit-events", { query: params }),

    verify: () => request<ChainVerification>("/audit-events/verify"),
  },
};
