/**
 * Client-side permission helpers.
 *
 * These drive what the UI *offers*, never what the user is *allowed* to do. Authorization
 * is enforced in the API's application layer (ADR-0002); hiding a button is a courtesy so
 * people are not invited to fail, not a control. Anything gated here is gated there too.
 */

export const Permission = {
  ORG_READ: "org:read",
  ORG_WRITE: "org:write",
  ORG_DELETE: "org:delete",
  USER_INVITE: "user:invite",
  USER_REMOVE: "user:remove",
  ROLE_WRITE: "role:write",
  APP_READ: "app:read",
  APP_WRITE: "app:write",
  APP_DELETE: "app:delete",
  AGENT_READ: "agent:read",
  AGENT_WRITE: "agent:write",
  FINDING_READ: "finding:read",
  FINDING_TRIAGE: "finding:triage",
  FINDING_SUPPRESS: "finding:suppress",
  POLICY_READ: "policy:read",
  POLICY_WRITE: "policy:write",
  REPORT_READ: "report:read",
  REPORT_WRITE: "report:write",
  AUDIT_READ: "audit:read",
  SETTINGS_WRITE: "settings:write",
  AI_RUN: "ai:run",
  AI_APPROVE: "ai:approve",
} as const;

export type PermissionValue = (typeof Permission)[keyof typeof Permission];

export function hasPermission(held: string[], required: PermissionValue): boolean {
  return held.includes(required);
}

export function hasAnyPermission(held: string[], required: PermissionValue[]): boolean {
  return required.some((permission) => held.includes(permission));
}
