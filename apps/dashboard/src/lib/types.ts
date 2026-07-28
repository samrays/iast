/**
 * Wire types for the Phase 2 control-plane API.
 *
 * Hand-written rather than generated, deliberately: the OpenAPI document is the contract,
 * but a generated client would drag every schema in the spec into the bundle and make the
 * diff on an API change unreadable. These mirror `apps/api/.../interfaces/http/schemas.py`
 * and the E2E suite fails if they drift.
 */

export type Uuid = string;
export type IsoDateTime = string;

// --- pagination ------------------------------------------------------------------

export interface PageMeta {
  next_cursor: string | null;
  has_more: boolean;
  limit: number;
}

export interface Page<T> {
  items: T[];
  page: PageMeta;
}

// --- errors ----------------------------------------------------------------------

/** RFC 9457 problem document, as produced by `interfaces/http/errors.py`. */
export interface ProblemDetail {
  type: string;
  title: string;
  status: number;
  detail: string;
  instance: string;
  code: string;
  request_id: string;
  errors?: Array<{ field: string; code: string; message: string }>;
  organizations?: string[];
  missing_permissions?: string[];
}

// --- auth ------------------------------------------------------------------------

export interface TokenResponse {
  access_token: string;
  token_type: string;
  expires_at: IsoDateTime;
  refresh_token: string | null;
  refresh_expires_at: IsoDateTime | null;
  session_id: Uuid;
}

export interface MfaChallengeResponse {
  mfa_required: true;
  challenge_token: string;
  expires_at: IsoDateTime;
  methods: string[];
}

export type LoginResult = TokenResponse | MfaChallengeResponse;

export function isMfaChallenge(result: LoginResult): result is MfaChallengeResponse {
  return "mfa_required" in result && result.mfa_required;
}

export interface OrganizationSummary {
  id: Uuid;
  name: string;
  slug: string;
  status: "ACTIVE" | "SUSPENDED" | "PENDING_DELETION";
}

export interface RoleSummary {
  id: Uuid;
  name: string;
  description: string;
  is_system: boolean;
  permissions: string[];
}

export interface CurrentPrincipal {
  user_id: Uuid;
  email: string;
  full_name: string;
  mfa_enabled: boolean;
  is_platform_admin: boolean;
  organization: OrganizationSummary;
  roles: RoleSummary[];
  permissions: string[];
  session_id: Uuid | null;
}

export interface MfaEnrolResponse {
  secret: string;
  provisioning_uri: string;
  recovery_codes: string[];
}

export interface LogoutResponse {
  sessions_revoked: number;
}

// --- members ---------------------------------------------------------------------

export interface MemberSummary {
  membership_id: Uuid;
  user_id: Uuid;
  email: string;
  full_name: string;
  status: "ACTIVE" | "INVITED" | "SUSPENDED";
  roles: RoleSummary[];
  permissions: string[];
  joined_at: IsoDateTime | null;
  last_login_at: IsoDateTime | null;
}

export interface PermissionCatalogueEntry {
  value: string;
  resource: string;
  action: string;
  privileged: boolean;
}

// --- api keys --------------------------------------------------------------------

export interface ApiKeySummary {
  id: Uuid;
  name: string;
  prefix: string;
  permissions: string[];
  created_at: IsoDateTime | null;
  expires_at: IsoDateTime | null;
  last_used_at: IsoDateTime | null;
  revoked_at: IsoDateTime | null;
  is_active: boolean;
}

export interface ApiKeyIssued {
  api_key: ApiKeySummary;
  /** Returned exactly once. There is no endpoint that can show it again. */
  secret: string;
}

// --- inventory -------------------------------------------------------------------

export const LANGUAGES = ["JAVA", "DOTNET", "NODE", "PYTHON", "GO"] as const;
export type Language = (typeof LANGUAGES)[number];

export const CRITICALITIES = ["LOW", "MEDIUM", "HIGH", "CRITICAL"] as const;
export type Criticality = (typeof CRITICALITIES)[number];

export const ENVIRONMENT_KINDS = ["DEVELOPMENT", "QA", "STAGING", "PRODUCTION"] as const;
export type EnvironmentKind = (typeof ENVIRONMENT_KINDS)[number];

export const PROTECTION_MODES = ["OFF", "MONITOR", "BLOCK"] as const;
export type ProtectionMode = (typeof PROTECTION_MODES)[number];

export interface EnvironmentSummary {
  id: Uuid;
  application_id: Uuid;
  kind: EnvironmentKind;
  internet_facing: boolean;
  protection_mode: ProtectionMode;
  created_at: IsoDateTime | null;
}

export interface ApplicationSummary {
  id: Uuid;
  name: string;
  slug: string;
  language: Language;
  criticality: Criticality;
  tags: string[];
  repository_url: string | null;
  description: string;
  created_at: IsoDateTime | null;
  environments: EnvironmentSummary[];
}

// --- agents ----------------------------------------------------------------------

export const AGENT_STATUSES = [
  "REGISTERED",
  "ONLINE",
  "DEGRADED",
  "OFFLINE",
  "DISABLED",
] as const;
export type AgentStatus = (typeof AGENT_STATUSES)[number];

export interface AgentSummary {
  id: Uuid;
  application_environment_id: Uuid;
  fingerprint: string;
  hostname: string;
  language: Language;
  agent_version: string;
  runtime_version: string;
  status: AgentStatus;
  config_version: string;
  cpu_overhead_pct: number | null;
  memory_mb: number | null;
  events_sent: number;
  events_dropped: number;
  pinned_version: string | null;
  last_seen_at: IsoDateTime | null;
  created_at: IsoDateTime | null;
}

// --- audit -----------------------------------------------------------------------

export interface AuditEventSummary {
  id: Uuid;
  sequence: number;
  action: string;
  actor_type: "USER" | "API_KEY" | "AGENT" | "SYSTEM";
  actor_user_id: Uuid | null;
  actor_label: string;
  resource_type: string;
  resource_id: string;
  outcome: "SUCCESS" | "FAILURE" | "DENIED";
  ip_address: string | null;
  request_id: string;
  metadata: Record<string, unknown>;
  occurred_at: IsoDateTime | null;
}

export interface ChainVerification {
  intact: boolean;
  entries_checked: number;
  first_broken_sequence: number | null;
}
