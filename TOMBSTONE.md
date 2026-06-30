# TOMBSTONE — context-mode

- **Status:** ARCHIVE-RECOMMENDED (pending maintainer confirmation)
- **Date:** 2026-06-29
- **Source:** v37 fleet audit `_META-RETROSPECTIVE.md` §4 (fork taxonomy) — classified "no-op mirror"
- **Tracking:** P4.3

## Why

`KooshaPari/context-mode` is a fork of `mksglu/context-mode`. The v37 audit classified it as a
**no-op / minimally-diverged mirror** (≈0-ahead / 16-behind upstream at audit time). A fork that
adds no durable value and lags upstream is maintenance overhead with no payoff.

> Note: the local copy has since received a small remediation commit (`fix(p3): remediate top audit
> findings (#1)`). If that delta is worth preserving, **upstream it to `mksglu/context-mode`** before
> archiving; otherwise it does not justify keeping an independent fork.

## Recommended action (maintainer's call)

1. **If no unique value:** upstream any worthwhile delta, then **archive** this repo
   (GitHub Settings → Archive — read-only, non-destructive, reversible). Do **not** hard-delete.
2. **If kept as a tracking fork:** establish an upstream-sync cadence (periodic fast-forward from
   `mksglu/context-mode`) and add a `FORK.md` documenting attribution + sync policy, so it stops
   drifting into a stale mirror.

This tombstone is a recommendation, not an action — archiving is the maintainer's decision.
