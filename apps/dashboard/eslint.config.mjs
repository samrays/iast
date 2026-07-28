import { dirname } from "node:path";
import { fileURLToPath } from "node:url";

import { FlatCompat } from "@eslint/eslintrc";

const compat = new FlatCompat({ baseDirectory: dirname(fileURLToPath(import.meta.url)) });

const config = [
  ...compat.extends("next/core-web-vitals", "next/typescript"),
  {
    ignores: [
      ".next/**",
      "node_modules/**",
      "playwright-report/**",
      "test-results/**",
      "next-env.d.ts",
    ],
  },
  {
    // Test fixtures use plain anchors to prove component composition; they are not app
    // navigation, so the next/link rule does not apply.
    files: ["**/*.test.tsx", "**/*.test.ts"],
    rules: { "@next/next/no-html-link-for-pages": "off" },
  },
  {
    rules: {
      // The access token is deliberately memory-only (ADR-0006). Persisting it anywhere a
      // script can read is the exact failure this lint rule exists to prevent.
      "no-restricted-globals": [
        "error",
        { name: "localStorage", message: "Never persist session state. Tokens stay in memory." },
        { name: "sessionStorage", message: "Never persist session state. Tokens stay in memory." },
      ],
      "@typescript-eslint/no-unused-vars": [
        "error",
        { argsIgnorePattern: "^_", varsIgnorePattern: "^_" },
      ],
    },
  },
];

export default config;
