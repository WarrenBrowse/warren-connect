# warren-connect: rules for Claude Code

The **wallet-to-SSO identity broker**: it turns a Warren wallet signature into a
DiscourseConnect assertion, so the support forum (`forum.warrenbrowse.com`)
authenticates users with no email, no password, and no client IP. It also carries
the problem-report intake that lets the desktop app attach its redacted logs to a
forum topic.

Deployed at `connect.warrenbrowse.com` by `/srv/warren/compose.forum.yml`. Design
and ops: `warren-core/docs/55-FORUM-DISCOURSE-SUPPORT.md`.

> Shared Warren rules (single source of truth: WarrenBrowse/warren-workspace).
> They resolve when this repo is checked out inside the workspace (mani sync);
> cloned standalone, the imports just warn harmlessly. Never restate one of them
> here: import it.
@../shared/rules/00-conventions.md
@../shared/rules/10-tdd.md
@../shared/rules/20-errors-secrets.md
@../shared/rules/30-git-commits.md

## Prime directive: the forum must learn as little as possible

This service sits between a wallet and a third-party forum. Everything it does
not forward is a privacy property of the product.

- **No email, no password, no client IP reaches Discourse.** Caddy pins
  `X-Forwarded-For` to `0.0.0.0`; do not "fix" that as a bug.
- **A wallet signature is the only credential.** Verify it against the canonical
  `X-Warren` message from `warren-contract`; never reimplement the signing
  format here.
- **The forum never sees the logs.** A problem report is uploaded through this
  service, already redacted by the app. Never store, log or forward the report
  body beyond its destination.
- **No-log discipline applies to the broker itself**: no pubkey, address or IP in
  a log line, an error, or a metric label.

## Every route with a body states its own limit

Axum's `DefaultBodyLimit` is 2 MiB, and it applies silently to any route with a
`Bytes` or `Json` extractor. That default once WAS the real ceiling of the
problem-report intake while the documented cap sat just under it by luck.

**Any route taking a body states its cap explicitly: a `DefaultBodyLimit`
layer, or a handler-side cap when it must apply after the rate limiter (the
`/v1/help/intake` case, which takes a raw `Request` on purpose); never inherit
axum's silent 2 MiB default.** The current
values, and how they interact with the app-side and Discourse-side caps, are the
`warren-support` skill, section "the problem-report size chain". Raise those caps
from the bottom up (Discourse, then here, then the app) or a report grows past a
ceiling still in force and gets refused outright.

**`MAX_LOG_SESSIONS` x `MAX_LOG_BYTES` is resident memory.** Pre-topic sessions
park the DECOMPRESSED log, so those two constants move together or a cap raise
multiplies into gigabytes on a small box.

## Verify before commit

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```
