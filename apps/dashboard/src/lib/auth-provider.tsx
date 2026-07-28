"use client";

import { useRouter } from "next/navigation";
import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useRef,
  useState,
  type ReactNode,
} from "react";

import { ApiError, api, refreshAccessToken, tokenStore } from "./api-client";
import type { CurrentPrincipal, LoginResult } from "./types";
import { isMfaChallenge } from "./types";
import { hasPermission, type PermissionValue } from "./permissions";

type AuthStatus = "loading" | "authenticated" | "anonymous";

interface AuthContextValue {
  status: AuthStatus;
  principal: CurrentPrincipal | null;
  permissions: string[];
  can: (permission: PermissionValue) => boolean;
  login: (email: string, password: string, organizationSlug?: string) => Promise<LoginResult>;
  completeMfa: (challengeToken: string, code: string) => Promise<void>;
  logout: (allSessions?: boolean) => Promise<void>;
  reload: () => Promise<void>;
}

const AuthContext = createContext<AuthContextValue | null>(null);

/**
 * Session state for the console.
 *
 * On mount it tries a refresh: the access token lives in memory and is therefore gone
 * after a page reload, but the `HttpOnly` refresh cookie is not. That single call is what
 * makes a hard refresh keep the user signed in without ever persisting a token where a
 * script could read it.
 */
export function AuthProvider({ children }: { children: ReactNode }) {
  const [status, setStatus] = useState<AuthStatus>("loading");
  const [principal, setPrincipal] = useState<CurrentPrincipal | null>(null);
  const router = useRouter();
  const bootstrapped = useRef(false);

  const loadPrincipal = useCallback(async () => {
    try {
      const me = await api.auth.me();
      setPrincipal(me);
      setStatus("authenticated");
    } catch {
      tokenStore.clear();
      setPrincipal(null);
      setStatus("anonymous");
    }
  }, []);

  useEffect(() => {
    // React 18+ strict mode mounts effects twice in development; a second bootstrap would
    // fire a second refresh and look like token reuse to the server.
    if (bootstrapped.current) return;
    bootstrapped.current = true;

    void (async () => {
      const refreshed = await refreshAccessToken();
      if (!refreshed) {
        setStatus("anonymous");
        return;
      }
      await loadPrincipal();
    })();
  }, [loadPrincipal]);

  // Keep an access token alive while the tab is open. The API issues 15-minute tokens; a
  // refresh a minute before expiry means a user reading a long page never sees a flicker.
  useEffect(() => {
    if (status !== "authenticated") return;
    const timer = window.setInterval(() => {
      if (tokenStore.isStale(60_000)) void refreshAccessToken();
    }, 60_000);
    return () => window.clearInterval(timer);
  }, [status]);

  const login = useCallback(
    async (email: string, password: string, organizationSlug?: string) => {
      const result = await api.auth.login(email, password, organizationSlug);
      if (!isMfaChallenge(result)) {
        tokenStore.set(result.access_token, result.expires_at);
        await loadPrincipal();
      }
      return result;
    },
    [loadPrincipal],
  );

  const completeMfa = useCallback(
    async (challengeToken: string, code: string) => {
      const tokens = await api.auth.verifyMfa(challengeToken, code);
      tokenStore.set(tokens.access_token, tokens.expires_at);
      await loadPrincipal();
    },
    [loadPrincipal],
  );

  const logout = useCallback(
    async (allSessions = false) => {
      try {
        await (allSessions ? api.auth.logoutAll() : api.auth.logout());
      } catch (error) {
        // A failed logout must still clear local state — leaving a stale principal on
        // screen after the user asked to leave is worse than a silent server error.
        if (!(error instanceof ApiError)) throw error;
      } finally {
        tokenStore.clear();
        setPrincipal(null);
        setStatus("anonymous");
        router.replace("/login");
      }
    },
    [router],
  );

  const value = useMemo<AuthContextValue>(
    () => ({
      status,
      principal,
      permissions: principal?.permissions ?? [],
      can: (permission) => hasPermission(principal?.permissions ?? [], permission),
      login,
      completeMfa,
      logout,
      reload: loadPrincipal,
    }),
    [status, principal, login, completeMfa, logout, loadPrincipal],
  );

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth(): AuthContextValue {
  const context = useContext(AuthContext);
  if (!context) throw new Error("useAuth must be used inside <AuthProvider>.");
  return context;
}
