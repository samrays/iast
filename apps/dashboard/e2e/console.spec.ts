import { expect, test, type Page } from "@playwright/test";

/**
 * These specs drive the console against a live API. They register their own organization
 * so a run never depends on seed data and never collides with another run.
 */

const API_URL = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8080";
const PASSWORD = "correct-horse-battery-77";

interface Tenant {
  email: string;
  organization: string;
}

async function registerTenant(page: Page): Promise<Tenant> {
  const suffix = Math.random().toString(36).slice(2, 10);
  const email = `e2e-${suffix}@example.com`;
  const organization = `E2E ${suffix}`;

  const response = await page.request.post(`${API_URL}/api/v1/auth/register`, {
    data: {
      organization_name: organization,
      email,
      password: PASSWORD,
      full_name: "End To End",
    },
  });
  expect(response.status(), await response.text()).toBe(201);
  return { email, organization };
}

async function signIn(page: Page, tenant: Tenant): Promise<void> {
  await page.goto("/login");
  await page.getByLabel("Email").fill(tenant.email);
  await page.getByLabel("Password").fill(PASSWORD);
  await page.getByRole("button", { name: "Sign in" }).click();
  await expect(page.getByRole("heading", { name: /Good to see you/i })).toBeVisible();
}

test.describe("authentication", () => {
  test("rejects bad credentials without revealing whether the account exists", async ({ page }) => {
    await page.goto("/login");
    await page.getByLabel("Email").fill("nobody-at-all@example.com");
    await page.getByLabel("Password").fill("definitely-not-the-password");
    await page.getByRole("button", { name: "Sign in" }).click();

    // Scope to the form: Next renders its own route announcer with role="alert".
    const alert = page.locator("form").getByRole("alert");
    await expect(alert).toBeVisible();
    await expect(alert).toContainText(/invalid credentials/i);
  });

  test("signs in and reaches the overview", async ({ page }) => {
    const tenant = await registerTenant(page);
    await signIn(page, tenant);
    // The organization name appears in the sidebar and in the page description.
    await expect(page.getByText(tenant.organization).first()).toBeVisible();
  });

  test("keeps the access token out of browser storage", async ({ page }) => {
    const tenant = await registerTenant(page);
    await signIn(page, tenant);

    // The whole point of ADR-0006: the token is in memory, the refresh cookie is HttpOnly.
    const storage = await page.evaluate(() => ({
      local: JSON.stringify(window.localStorage),
      session: JSON.stringify(window.sessionStorage),
    }));
    expect(storage.local).toBe("{}");
    expect(storage.session).toBe("{}");

    const cookies = await page.context().cookies();
    const refresh = cookies.find((cookie) => cookie.name === "aegis_refresh");
    expect(refresh, "refresh cookie must be set").toBeTruthy();
    expect(refresh?.httpOnly).toBe(true);
    expect(refresh?.sameSite).toBe("Strict");
  });

  test("survives a hard reload by refreshing through the cookie", async ({ page }) => {
    const tenant = await registerTenant(page);
    await signIn(page, tenant);

    await page.reload();

    // The in-memory token is gone after a reload; the session must come back anyway.
    await expect(page.getByRole("heading", { name: /Good to see you/i })).toBeVisible();
  });

  test("sends an unauthenticated visitor to the login page", async ({ page }) => {
    await page.goto("/applications");
    await expect(page).toHaveURL(/\/login/);
  });

  test("signs out and blocks the console afterwards", async ({ page }) => {
    const tenant = await registerTenant(page);
    await signIn(page, tenant);

    await page.getByRole("button", { name: /End To End/i }).click();
    await page.getByRole("menuitem", { name: "Sign out" }).click();

    await expect(page).toHaveURL(/\/login/);
    await page.goto("/agents");
    await expect(page).toHaveURL(/\/login/);
  });
});

test.describe("console", () => {
  test("registers an application and shows it in the inventory", async ({ page }) => {
    const tenant = await registerTenant(page);
    await signIn(page, tenant);

    await page.getByRole("link", { name: "Applications", exact: true }).click();
    await expect(page.getByRole("heading", { name: "Applications" })).toBeVisible();

    await page.getByRole("button", { name: "Register application" }).first().click();
    await page.getByLabel("Name").fill("Payments API");
    await page.getByLabel("Tags").fill("pci, payments");
    await page.getByRole("button", { name: "Register", exact: true }).click();

    await expect(page.getByRole("link", { name: "Payments API" })).toBeVisible();
    await expect(page.getByText("payments-api")).toBeVisible();
  });

  test("opens an application and reports it as unobserved", async ({ page }) => {
    const tenant = await registerTenant(page);
    await signIn(page, tenant);

    await page.goto("/applications");
    await page.getByRole("button", { name: "Register application" }).first().click();
    await page.getByLabel("Name").fill("Ledger Service");
    await page.getByRole("button", { name: "Register", exact: true }).click();
    await page.getByRole("link", { name: "Ledger Service" }).click();

    await expect(page.getByRole("heading", { name: "Ledger Service" })).toBeVisible();
    // No agent has reported, and the console must say so rather than imply safety.
    await expect(page.getByText(/unobserved/i)).toBeVisible();
  });

  test("shows the five seeded system roles", async ({ page }) => {
    const tenant = await registerTenant(page);
    await signIn(page, tenant);

    await page.getByRole("link", { name: "Roles" }).click();
    for (const role of ["Owner", "Admin", "Security Analyst", "Developer", "Viewer"]) {
      await expect(page.getByRole("heading", { name: role, exact: true })).toBeVisible();
    }
  });

  test("issues an API key and shows the secret exactly once", async ({ page }) => {
    const tenant = await registerTenant(page);
    await signIn(page, tenant);

    await page.getByRole("link", { name: "API keys" }).click();
    await page.getByRole("button", { name: "Issue key" }).first().click();
    await page.getByLabel("Name").fill("ci-pipeline");
    await page.getByRole("checkbox").first().check();
    await page.getByRole("button", { name: "Issue key" }).last().click();

    await expect(page.getByText("Copy your key now")).toBeVisible();
    // The full secret is the <pre>; the table behind the dialog shows only the prefix.
    await expect(page.locator("pre")).toContainText(/^ak_\w+\./);

    await page.getByRole("button", { name: "Done" }).click();
    // The list shows the prefix only — the secret is unrecoverable by design.
    await expect(page.locator("pre")).toHaveCount(0);
    await expect(page.getByText(/ak_\w+…/).first()).toBeVisible();
  });

  test("verifies the audit chain and records the read", async ({ page }) => {
    const tenant = await registerTenant(page);
    await signIn(page, tenant);

    await page.getByRole("link", { name: "Audit log" }).click();
    await expect(page.getByText("Chain intact")).toBeVisible();
    await expect(page.getByText(/Organization created|Login succeeded/i).first()).toBeVisible();
  });

  test("opens the command palette and navigates with it", async ({ page }) => {
    const tenant = await registerTenant(page);
    await signIn(page, tenant);

    await page.keyboard.press("Control+k");
    await expect(page.getByPlaceholder(/Search applications/i)).toBeVisible();

    await page.getByPlaceholder(/Search applications/i).fill("agent");
    await page.getByRole("option", { name: /Agent fleet/i }).click();
    await expect(page.getByRole("heading", { name: "Agent fleet" })).toBeVisible();
  });

  test("switches theme and keeps it after navigation", async ({ page }) => {
    const tenant = await registerTenant(page);
    await signIn(page, tenant);

    // Light is the default; dark is opt-in.
    await expect(page.locator("html")).not.toHaveClass(/dark/);

    await page.getByRole("button", { name: /Switch to dark theme/i }).click();
    await expect(page.locator("html")).toHaveClass(/dark/);

    await page.getByRole("link", { name: "Agent fleet" }).click();
    await expect(page.locator("html")).toHaveClass(/dark/);
  });

  test("reports an empty fleet honestly", async ({ page }) => {
    const tenant = await registerTenant(page);
    await signIn(page, tenant);

    await page.getByRole("link", { name: "Agent fleet" }).click();
    await expect(page.getByText("No agents registered")).toBeVisible();
  });
});
