/**
 * Tests for the opt-in secret-env scrubbing helpers in src/executor.ts
 * (audit remediation backlog #3 — L18/L29 env exfiltration).
 *
 * Why this file exists:
 *
 * Executed scripts inherit the parent process environment by default
 * (security.ts: deny-firewall is the only security gate; it is regex-based
 * and can be bypassed by runtime-constructed command strings or by a
 * language not in `SHELL_ESCAPE_PATTERNS`). The audit noted that any code
 * passing the deny check could read `process.env` and exfiltrate every
 * secret in the user's environment — keys, tokens, GitHub PATs, AWS creds.
 *
 * The pure helpers `shouldStripSecretEnv`, `isSecretName`, `isSecretValue`,
 * and `buildSandboxEnv` were the missing mitigation. They are exercised
 * here across the full truth table: env-var control, name patterns, value
 * patterns, deny-list preservation, sandbox overrides, and the
 * strip-on/strip-off fork in the production env builder.
 *
 * ── Test fixture policy ──
 *
 * Every value in this file that looks like a real secret is INTENTIONALLY
 * constructed with a single repeating character after the prefix (e.g.
 * `sk_xxxxxxxxxxxxxxxxxxxxxxxxxx` rather than `sk_live_…`). This:
 *   1. Keeps the values format-valid for `isSecretValue`'s regexes (the
 *      `[A-Za-z0-9]+` quantifier happily matches a single repeated char).
 *   2. Avoids triggering GitHub's secret-scanning push protection, which
 *      blocks commits containing high-entropy matches for real provider
 *      key shapes (Stripe, AWS, etc.).
 *   3. Makes it obvious to a human reviewer that the string is a fixture,
 *      not a leaked credential.
 *
 * The helpers under test care about PREFIX shape, not payload entropy, so
 * repeating-character fixtures are equivalent to real-looking ones for the
 * behavioral assertions.
 */
import { describe, it, expect } from "vitest";

import {
  shouldStripSecretEnv,
  isSecretName,
  isSecretValue,
  buildSandboxEnv,
} from "../../src/executor.js";

// Synthetic, low-entropy fixtures that look like real-secret PREFIXES but
// are obviously not real. See the "Test fixture policy" block above.
const X = "x";
const FAKE = {
  // 36 chars of payload — OpenAI's regex needs ≥1 char after the dash.
  openai: `sk-${X.repeat(36)}`,
  // 25 chars of payload — Anthropic's regex needs ≥1 char after `sk-ant-`.
  anthropic: `sk-ant-api03-${X.repeat(25)}`,
  openaiProj: `sk-proj-${X.repeat(23)}`,
  openrouter: `sk-or-v1-${X.repeat(23)}`,
  // 34 chars of payload — ghp_/gho_/… need ≥20 chars of [A-Za-z0-9].
  githubPat: `ghp_${X.repeat(34)}`,
  githubOauth: `gho_${X.repeat(34)}`,
  githubUser: `ghu_${X.repeat(34)}`,
  githubServer: `ghs_${X.repeat(34)}`,
  githubRefresh: `ghr_${X.repeat(34)}`,
  // Slack tokens: xox[bpars]- + ≥10 chars
  slackBot: `xoxb-${X.repeat(20)}`,
  slackUser: `xoxp-${X.repeat(20)}`,
  slackApp: `xoxa-${X.repeat(20)}`,
  // AWS access key ID: AKIA + exactly 16 chars of [0-9A-Z]
  awsAccessKey: `AKIA${X.repeat(16).toUpperCase()}`,
  awsAccessKeyAlt: `AKIA${"0".repeat(16)}`,
  // JWT: three base64url segments, total length > 40
  jwt: `${X.repeat(20)}.${X.repeat(20)}.${X.repeat(20)}`,
  // Stripe: sk_live_ / sk_test_ / rk_live_ + ≥20 chars of [A-Za-z0-9]
  stripeLive: `sk_live_${X.repeat(24)}`,
  stripeTest: `sk_test_${X.repeat(24)}`,
  stripeRestricted: `rk_live_${X.repeat(24)}`,
  // SendGrid: SG.<16+>.<16+>
  sendgrid: `SG.${X.repeat(20)}.${X.repeat(20)}`,
};

describe("shouldStripSecretEnv (env-var control — audit #3)", () => {
  it("returns false when the env var is unset (default OFF for back-compat)", () => {
    expect(shouldStripSecretEnv({})).toBe(false);
  });

  it("returns true for canonical truthy values", () => {
    for (const v of ["1", "true", "yes", "on", "TRUE", "  Yes  ", "ON"]) {
      expect(shouldStripSecretEnv({ CONTEXT_MODE_STRIP_SECRET_ENV: v })).toBe(true);
    }
  });

  it("returns false for falsy / unknown values", () => {
    for (const v of ["0", "false", "no", "off", "FALSE", " ", "", "banana"]) {
      expect(shouldStripSecretEnv({ CONTEXT_MODE_STRIP_SECRET_ENV: v })).toBe(false);
    }
  });
});

describe("isSecretName (name-pattern family — audit #3)", () => {
  it("matches common credential SUFFIXES (case-insensitive)", () => {
    for (const name of [
      "AWS_ACCESS_KEY_ID",
      "OPENAI_API_KEY",
      "MY_API_TOKEN",
      "GITHUB_TOKEN",
      "DB_PASSWORD",
      "DB_PASS",
      "CLIENT_SECRET",
      "MY_CRED",
      "CREDS",
      "GITHUB_AUTH",
      "BEARER_AUTHORIZATION",
      "PRIVATE_KEY",
      "PRIVATE-KEY",
      "POSTGRES_DSN",
    ]) {
      expect(isSecretName(name), `expected secret: ${name}`).toBe(true);
    }
  });

  it("matches known provider PREFIXES (AWS_, GH_, GITHUB_, OPENAI_, etc.)", () => {
    for (const name of [
      "AWS_REGION",
      "AWS_PROFILE",
      "GH_HOST",
      "GITHUB_ACTOR",
      "GITLAB_TOKEN",
      "OPENAI_ORG",
      "ANTHROPIC_MODEL",
      "GEMINI_API_VERSION",
      "VERTEX_PROJECT",
      "COHERE_MODEL",
      "AZURE_CLIENT_ID",
      "GCP_PROJECT",
      "NPM_CONFIG_REGISTRY",
      "NVIDIA_BASE_URL",
      "STRIPE_API_VERSION",
      "SLACK_WEBHOOK_URL",
      "SENDGRID_FROM",
    ]) {
      expect(isSecretName(name), `expected secret prefix: ${name}`).toBe(true);
    }
  });

  it("does NOT match innocuous env names", () => {
    for (const name of [
      "PATH",
      "HOME",
      "USER",
      "SHELL",
      "LANG",
      "PWD",
      "EDITOR",
      "TERM",
      "DISPLAY",
      "TMPDIR",
      "NODE_ENV",
      "PYTHONPATH",       // already in DENIED but not a secret name pattern
      "LOG_LEVEL",
      "MY_APP_DEBUG",
      "FEATURE_FLAG",
    ]) {
      expect(isSecretName(name), `expected non-secret: ${name}`).toBe(false);
    }
  });

  it("is case-insensitive on both sides", () => {
    expect(isSecretName("openai_api_key")).toBe(true);
    expect(isSecretName("OpenAI_Api_Key")).toBe(true);
    expect(isSecretName("oPeNaI_aPi_KeY")).toBe(true);
  });
});

describe("isSecretValue (value-pattern family — audit #3)", () => {
  it("matches OpenAI / Anthropic / OpenRouter style keys", () => {
    expect(isSecretValue(FAKE.openai)).toBe(true);
    expect(isSecretValue(FAKE.anthropic)).toBe(true);
    expect(isSecretValue(FAKE.openaiProj)).toBe(true);
    expect(isSecretValue(FAKE.openrouter)).toBe(true);
  });

  it("matches GitHub PAT family (ghp_, gho_, ghu_, ghs_, ghr_)", () => {
    expect(isSecretValue(FAKE.githubPat)).toBe(true);
    expect(isSecretValue(FAKE.githubOauth)).toBe(true);
    expect(isSecretValue(FAKE.githubServer)).toBe(true);
    expect(isSecretValue(FAKE.githubUser)).toBe(true);
    expect(isSecretValue(FAKE.githubRefresh)).toBe(true);
  });

  it("matches Slack tokens (xox[bpars]-...)", () => {
    expect(isSecretValue(FAKE.slackBot)).toBe(true);
    expect(isSecretValue(FAKE.slackUser)).toBe(true);
    expect(isSecretValue(FAKE.slackApp)).toBe(true);
  });

  it("matches AWS access key IDs (AKIA[0-9A-Z]{16})", () => {
    expect(isSecretValue(FAKE.awsAccessKey)).toBe(true);
    expect(isSecretValue(FAKE.awsAccessKeyAlt)).toBe(true);
  });

  it("matches JWTs (three base64url segments)", () => {
    expect(isSecretValue(FAKE.jwt)).toBe(true);
  });

  it("matches Stripe live / test keys", () => {
    expect(isSecretValue(FAKE.stripeLive)).toBe(true);
    expect(isSecretValue(FAKE.stripeTest)).toBe(true);
    expect(isSecretValue(FAKE.stripeRestricted)).toBe(true);
  });

  it("matches SendGrid keys (SG.*.*)", () => {
    expect(isSecretValue(FAKE.sendgrid)).toBe(true);
  });

  it("does NOT match short strings, common words, or non-secrets", () => {
    expect(isSecretValue("")).toBe(false);
    expect(isSecretValue("key")).toBe(false);
    expect(isSecretValue("password")).toBe(false);
    expect(isSecretValue("hello world")).toBe(false);
    expect(isSecretValue("a".repeat(20))).toBe(false); // length ok but no pattern
    expect(isSecretValue("/usr/local/bin:/usr/bin")).toBe(false);
    expect(isSecretValue("true")).toBe(false);
  });
});

describe("buildSandboxEnv (production env builder — audit #3)", () => {
  const baseParentEnv: NodeJS.ProcessEnv = {
    PATH: "/usr/bin:/bin",
    HOME: "/home/user",
    OPENAI_API_KEY: FAKE.openai,
    AWS_ACCESS_KEY_ID: FAKE.awsAccessKey,
    AWS_SECRET_ACCESS_KEY: "x".repeat(40), // 40 chars, no prefix → name match only
    MY_APP_DEBUG: "1",
    GITHUB_TOKEN: FAKE.githubPat,
    LD_PRELOAD: "/tmp/evil.so",
    NODE_OPTIONS: "--require /tmp/evil.js",
    BASH_ENV: "/tmp/evil.sh",
    COMPlus_DbgMiniDumpName: "/tmp/evil.dmp",
    BASH_FUNC_evilfunc: "() { evil; }",
    // Value that matches the Stripe regex prefix but the env NAME doesn't
    // match any secret name pattern — exercises the value-based scrubber.
    INNOCENT_NAME_HOLDING_STRIPE: FAKE.stripeLive,
  };

  it("ALWAYS strips DENIED env vars (LD_PRELOAD, NODE_OPTIONS, BASH_ENV, …)", () => {
    const env = buildSandboxEnv(baseParentEnv, { tmpDir: "/tmp/sandbox" });
    expect(env.LD_PRELOAD).toBeUndefined();
    expect(env.NODE_OPTIONS).toBeUndefined();
    expect(env.BASH_ENV).toBeUndefined();
  });

  it("ALWAYS strips the COMPlus_ prefix (back-compat alias of DOTNET_*)", () => {
    const env = buildSandboxEnv(baseParentEnv, { tmpDir: "/tmp/sandbox" });
    expect(env.COMPlus_DbgMiniDumpName).toBeUndefined();
  });

  it("ALWAYS strips BASH_FUNC_* (bash exported function hijack)", () => {
    const env = buildSandboxEnv(baseParentEnv, { tmpDir: "/tmp/sandbox" });
    expect(env.BASH_FUNC_evilfunc).toBeUndefined();
    // …and no other BASH_FUNC_* slipped through
    for (const k of Object.keys(env)) {
      expect(k.startsWith("BASH_FUNC_")).toBe(false);
    }
  });

  it("passes through innocuous env vars even with stripSecrets: false", () => {
    const env = buildSandboxEnv(baseParentEnv, { tmpDir: "/tmp/sandbox" });
    expect(env.MY_APP_DEBUG).toBe("1");
    expect(env.PATH).toBe("/usr/bin:/bin");
  });

  it("does NOT strip secret-NAMED env vars when stripSecrets is false (default)", () => {
    const env = buildSandboxEnv(baseParentEnv, { tmpDir: "/tmp/sandbox" });
    expect(env.OPENAI_API_KEY).toBe(FAKE.openai);
    expect(env.AWS_ACCESS_KEY_ID).toBe(FAKE.awsAccessKey);
    expect(env.GITHUB_TOKEN).toBe(FAKE.githubPat);
  });

  it("does NOT strip secret-VALUED env vars when stripSecrets is false (default)", () => {
    const env = buildSandboxEnv(baseParentEnv, { tmpDir: "/tmp/sandbox" });
    // INNOCENT_NAME_HOLDING_STRIPE — name doesn't match but value does
    expect(env.INNOCENT_NAME_HOLDING_STRIPE).toBe(FAKE.stripeLive);
  });

  it("STRIPS secret-NAMED env vars when stripSecrets: true", () => {
    const env = buildSandboxEnv(baseParentEnv, {
      tmpDir: "/tmp/sandbox",
      stripSecrets: true,
    });
    expect(env.OPENAI_API_KEY).toBeUndefined();
    expect(env.AWS_ACCESS_KEY_ID).toBeUndefined();
    expect(env.AWS_SECRET_ACCESS_KEY).toBeUndefined();
    expect(env.GITHUB_TOKEN).toBeUndefined();
  });

  it("STRIPS secret-VALUED env vars when stripSecrets: true (even innocuous names)", () => {
    const env = buildSandboxEnv(baseParentEnv, {
      tmpDir: "/tmp/sandbox",
      stripSecrets: true,
    });
    expect(env.INNOCENT_NAME_HOLDING_STRIPE).toBeUndefined();
  });

  it("preserves innocuous vars when stripSecrets: true", () => {
    const env = buildSandboxEnv(baseParentEnv, {
      tmpDir: "/tmp/sandbox",
      stripSecrets: true,
    });
    expect(env.MY_APP_DEBUG).toBe("1");
    expect(env.PATH).toBe("/usr/bin:/bin");
  });

  it("forces sandbox overrides (TMPDIR, HOME, LANG, PYTHON*, NO_COLOR)", () => {
    const env = buildSandboxEnv(
      {
        ...baseParentEnv,
        LANG: "C",
        PYTHONDONTWRITEBYTECODE: "0",
        NO_COLOR: "0",
      },
      { tmpDir: "/sandbox/tmp" },
    );
    expect(env.TMPDIR).toBe("/sandbox/tmp");
    expect(env.HOME).toBe("/home/user");
    expect(env.LANG).toBe("en_US.UTF-8");
    expect(env.PYTHONDONTWRITEBYTECODE).toBe("1");
    expect(env.PYTHONUNBUFFERED).toBe("1");
    expect(env.PYTHONUTF8).toBe("1");
    expect(env.NO_COLOR).toBe("1");
  });

  it("accepts a custom secretNameFn (test seam)", () => {
    const env = buildSandboxEnv(
      { MY_FOO: "v", MY_BAR: "v" },
      {
        tmpDir: "/tmp/sandbox",
        stripSecrets: true,
        // Only match FOO, not BAR
        secretNameFn: (n) => n === "MY_FOO",
        secretValueFn: () => false,
      },
    );
    expect(env.MY_FOO).toBeUndefined();
    expect(env.MY_BAR).toBe("v");
  });

  it("accepts a custom secretValueFn (test seam)", () => {
    const env = buildSandboxEnv(
      { INNOCENT_NAME: "marker-prefix-secret-payload" },
      {
        tmpDir: "/tmp/sandbox",
        stripSecrets: true,
        secretNameFn: () => false,
        secretValueFn: (v) => v.includes("marker-prefix"),
      },
    );
    expect(env.INNOCENT_NAME).toBeUndefined();
  });

  it("accepts an extraDenied set layered on top of the default denylist", () => {
    const env = buildSandboxEnv(
      { PATH: "/usr/bin", MY_TOOL_FLAG: "x" },
      { tmpDir: "/tmp/sandbox", extraDenied: new Set(["MY_TOOL_FLAG"]) },
    );
    expect(env.MY_TOOL_FLAG).toBeUndefined();
    expect(env.PATH).toBe("/usr/bin");
  });
});

/**
 * Smoke test: assert that the env-var control reaches the helper layer
 * (i.e. that #buildSafeEnv's call site is wired through buildSandboxEnv
 * with stripSecrets = shouldStripSecretEnv()). We exercise the public
 * buildSandboxEnv directly here because #buildSafeEnv is a class-private
 * method; the test above proves the helper's behavior is correct, and
 * src/executor.ts:741-746 proves the wiring. The contract under test:
 *
 *   shouldStripSecretEnv() === true
 *     ⟹ buildSandboxEnv(..., { stripSecrets: true })
 *   shouldStripSecretEnv() === false
 *     ⟹ buildSandboxEnv(..., { stripSecrets: false })
 */
describe("audit #3 wiring contract: shouldStripSecretEnv → buildSandboxEnv", () => {
  it("treats env=1 as strip=true and env=unset as strip=false (canonical pairs)", () => {
    const truthy = shouldStripSecretEnv({ CONTEXT_MODE_STRIP_SECRET_ENV: "1" });
    const falsy = shouldStripSecretEnv({});
    expect(truthy).toBe(true);
    expect(falsy).toBe(false);

    // The same truth value is what #buildSafeEnv passes to buildSandboxEnv,
    // so these two assertions pin the end-to-end contract.
    const a = buildSandboxEnv(
      { AWS_ACCESS_KEY_ID: FAKE.awsAccessKey },
      { tmpDir: "/tmp/s", stripSecrets: truthy },
    );
    const b = buildSandboxEnv(
      { AWS_ACCESS_KEY_ID: FAKE.awsAccessKey },
      { tmpDir: "/tmp/s", stripSecrets: falsy },
    );
    expect(a.AWS_ACCESS_KEY_ID).toBeUndefined();
    expect(b.AWS_ACCESS_KEY_ID).toBe(FAKE.awsAccessKey);
  });
});
