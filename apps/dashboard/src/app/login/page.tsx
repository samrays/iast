"use client";

import { useRouter } from "next/navigation";
import { KeyRound, ShieldHalf } from "lucide-react";
import { useEffect, useState, type FormEvent } from "react";

import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { ApiError } from "@/lib/api-client";
import { useAuth } from "@/lib/auth-provider";
import { isMfaChallenge } from "@/lib/types";

type Stage =
  | { kind: "credentials" }
  | { kind: "mfa"; challengeToken: string }
  | { kind: "organization"; slugs: string[] };

export default function LoginPage() {
  const { status, login, completeMfa } = useAuth();
  const router = useRouter();

  const [stage, setStage] = useState<Stage>({ kind: "credentials" });
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [organizationSlug, setOrganizationSlug] = useState("");
  const [code, setCode] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [retryAfter, setRetryAfter] = useState<number | null>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    if (status === "authenticated") router.replace("/");
  }, [status, router]);

  const handleFailure = (caught: unknown) => {
    if (caught instanceof ApiError) {
      // The API deliberately returns one generic message for unknown-user and
      // wrong-password (threat T-07). Do not embellish it here.
      if (caught.code === "validation_error" && caught.problem?.organizations) {
        setStage({ kind: "organization", slugs: caught.problem.organizations });
        setError("You belong to more than one organization. Choose which to sign in to.");
        return;
      }
      if (caught.code === "account_locked") {
        setRetryAfter(null);
        setError(caught.message);
        return;
      }
      setError(caught.message);
      return;
    }
    setError("Could not reach the control plane. Check that the API is running.");
  };

  const submitCredentials = async (event: FormEvent) => {
    event.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const result = await login(email, password, organizationSlug || undefined);
      if (isMfaChallenge(result)) {
        setStage({ kind: "mfa", challengeToken: result.challenge_token });
      } else {
        router.replace("/");
      }
    } catch (caught) {
      handleFailure(caught);
    } finally {
      setBusy(false);
    }
  };

  const submitMfa = async (event: FormEvent) => {
    event.preventDefault();
    if (stage.kind !== "mfa") return;
    setBusy(true);
    setError(null);
    try {
      await completeMfa(stage.challengeToken, code);
      router.replace("/");
    } catch (caught) {
      handleFailure(caught);
      setCode("");
    } finally {
      setBusy(false);
    }
  };

  return (
    <main className="flex min-h-screen items-center justify-center bg-background px-4 py-12">
      <div className="w-full max-w-sm">
        <div className="mb-8 flex flex-col items-center gap-3 text-center">
          <span className="flex size-11 items-center justify-center rounded-xl bg-primary text-primary-foreground">
            <ShieldHalf className="size-6" />
          </span>
          <div>
            <h1 className="text-xl font-semibold tracking-tight">Aegis IAST</h1>
            <p className="mt-1 text-sm text-muted-foreground">
              Sign in to the security console
            </p>
          </div>
        </div>

        {stage.kind === "mfa" ? (
          <form onSubmit={submitMfa} className="space-y-4" noValidate>
            <div className="flex items-center gap-2 rounded-md border border-border bg-muted/40 px-3 py-2 text-sm">
              <KeyRound className="size-4 shrink-0 text-muted-foreground" aria-hidden />
              <span className="text-muted-foreground">
                Enter the code from your authenticator, or a recovery code.
              </span>
            </div>
            <div className="space-y-2">
              <Label htmlFor="code">Verification code</Label>
              <Input
                id="code"
                name="code"
                inputMode="text"
                autoComplete="one-time-code"
                autoFocus
                required
                value={code}
                onChange={(event) => setCode(event.target.value)}
                placeholder="123456"
                className="text-center font-mono text-lg tracking-[0.3em]"
                aria-invalid={error ? true : undefined}
              />
            </div>
            {error ? (
              <p role="alert" className="text-sm text-destructive">
                {error}
              </p>
            ) : null}
            <Button type="submit" className="w-full" loading={busy}>
              Verify
            </Button>
            <Button
              type="button"
              variant="ghost"
              className="w-full"
              onClick={() => {
                setStage({ kind: "credentials" });
                setError(null);
                setCode("");
              }}
            >
              Back
            </Button>
          </form>
        ) : (
          <form onSubmit={submitCredentials} className="space-y-4" noValidate>
            <div className="space-y-2">
              <Label htmlFor="email">Email</Label>
              <Input
                id="email"
                name="email"
                type="email"
                autoComplete="username"
                autoFocus
                required
                value={email}
                onChange={(event) => setEmail(event.target.value)}
                placeholder="you@example.com"
                aria-invalid={error ? true : undefined}
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="password">Password</Label>
              <Input
                id="password"
                name="password"
                type="password"
                autoComplete="current-password"
                required
                value={password}
                onChange={(event) => setPassword(event.target.value)}
                aria-invalid={error ? true : undefined}
              />
            </div>

            {stage.kind === "organization" ? (
              <div className="space-y-2">
                <Label htmlFor="organization">Organization</Label>
                <select
                  id="organization"
                  name="organization"
                  required
                  value={organizationSlug}
                  onChange={(event) => setOrganizationSlug(event.target.value)}
                  className="flex h-9 w-full rounded-md border border-input bg-card px-3 text-sm shadow-sm focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
                >
                  <option value="">Select…</option>
                  {stage.slugs.map((slug) => (
                    <option key={slug} value={slug}>
                      {slug}
                    </option>
                  ))}
                </select>
              </div>
            ) : null}

            {error ? (
              <p role="alert" className="text-sm text-destructive">
                {error}
                {retryAfter ? ` Try again in ${retryAfter}s.` : ""}
              </p>
            ) : null}

            <Button type="submit" className="w-full" loading={busy}>
              Sign in
            </Button>
          </form>
        )}

        <p className="mt-8 text-center text-2xs leading-relaxed text-muted-foreground">
          Access tokens are held in memory only and never written to storage. Your session
          is refreshed through an HttpOnly cookie.
        </p>
      </div>
    </main>
  );
}
