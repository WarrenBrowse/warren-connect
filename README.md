# warren-connect

DiscourseConnect SSO provider for the Warren community forum
(`forum.warrenbrowse.com`). Users sign in by proving control of their Warren
wallet key (Ed25519, the frozen `X-Warren-*` canonical request format from
`warren-contract`); Discourse receives a pairwise opaque handle, a synthetic
`.invalid` email, and never a password, a real email, or a client IP.

Design record and runbook: `warren-core/docs/55-FORUM-DISCOURSE-SUPPORT.md`
(internal design record; warren-core is Warren's private backend repo).

## Endpoints

| Route | Purpose |
|---|---|
| `GET /sso` | DiscourseConnect entry (HMAC-verified), renders the approval page |
| `POST /v1/forum/login` | Wallet-signed approval from the Warren app |
| `GET /v1/session/:sid/status` | Browser poll: `pending` / `approved` |
| `GET /v1/session/:sid/complete` | Redirect back into Discourse with the signed payload |
| `GET /attach?topic=<id>` | Attach-logs page for an existing bug topic: deep link + polling |
| `GET /attach?sid=<sid>` | Attach-logs page for a pre-topic session minted by `/v1/attach/new` |
| `POST /v1/forum/attach-logs` | Wallet-signed gzipped problem report from the Warren app |
| `POST /v1/forum/notifications` | Wallet-signed read of the caller's own forum notifications, for the app's activity panel |
| `POST /v1/attach/new` | Mints a pre-topic attach session (TTL 30 min), returns `{"sid"}` |
| `GET /v1/attach/:sid/meta` | Composer prefill poll: `pending`, then `received` + `version`/`os` parsed from the report |
| `POST /v1/attach/:sid/bind` | Binds a received pre-topic session to a freshly created topic (author check + upload + staff PM + whisper); `409 no_log` before the app delivered |
| `GET /v1/attach/:sid/status` | Browser poll: `pending` / `received` / `done` / `cancelled` |
| `POST /v1/attach/:sid/cancel` | App-initiated cancel of an attach session |
| `POST /v1/help/intake` | Public unauthenticated guest help form: creates a PUBLIC Discourse topic as the intake bot, returns `{"topic_url","reference","code"}` (201) |
| `POST /v1/help/reply` | Public guest follow-up: posts into the topic its `code` was issued for, returns `{"topic_url"}` (201) |
| `GET /internal/by-pubkey/{ss58}` | Support lookup (bearer `INTERNAL_TOKEN`): recompute a wallet's handle + whether it registered |
| `GET /internal/by-handle/{username}` | Support lookup (bearer): the wallet behind a handle |
| `GET /internal/forum/digest` | Unsigned broadcast activity digest (bearer): one unread count per anonymous slot, consumed and signed by warren-core |
| `GET /transparency` | Public what-we-can-and-cannot-see page |
| `GET /healthz` | Liveness |

Staff is an allowlist of Warren pubkeys configured in `WARREN_ADMIN_PUBKEYS`: a
listed wallet is promoted to Discourse admin/moderator via the SSO payload on
every login. The roster is deployment configuration rather than source, so this
repository carries the mechanism without naming its operators. An entry that is
not a valid Warren address refuses startup, identified by position (the no-log
rule forbids echoing the material). An empty roster leaves the forum with no
staff wallet, logged as a warning at startup. `INTERNAL_TOKEN` (>= 32 bytes, or
empty to disable) gates the `/internal/*` support-lookup endpoints, consumed by
warren-admin.

## Configuration (environment)

| Var | Meaning |
|---|---|
| `LISTEN_ADDR` | default `0.0.0.0:8095` |
| `PUBLIC_HOST` | host embedded in deep links, default `connect.warrenbrowse.com` |
| `DISCOURSE_CONNECT_SECRET` | shared with the Discourse `discourse_connect_secret` setting (>= 32 bytes) |
| `FORUM_HANDLE_SECRET` | keyed pairwise-handle derivation secret (>= 32 bytes, NEVER rotate casually) |
| `FORUM_DATABASE_URL` | own `forum_auth` database (migrations embedded) |
| `WARREN_DATABASE_URL_RO` | Warren API database, SELECT-only role (subscription check) |
| `DISCOURSE_DATABASE_URL_RO` | Discourse's own database, SELECT-only role. Unset disables the activity digest and the notification panel (503 on their endpoints) and nothing else |
| `DISCOURSE_URL` | Discourse base for the admin API, default `http://discourse` (docker alias, bypasses the edge basic_auth) |
| `DISCOURSE_API_KEY` | Discourse admin API key; empty disables the attach-logs feature (its endpoints return 503) |
| `DISCOURSE_API_USERNAME` | acting API user, default `system` |
| `WARREN_STAFF_GROUP` | group receiving the log PMs, default `staff` |
| `WARREN_ADMIN_PUBKEYS` | forum staff wallets, comma-separated SS58; empty means no staff |
| `DISCOURSE_INTAKE_CATEGORY_ID` | category id (u64) for guest intake topics; unset disables the intake endpoint (503) |
| `DISCOURSE_INTAKE_USERNAME` | low-privilege bot user authoring guest intake topics, default `warren-intake` |
| `DISCOURSE_INTAKE_API_KEY` | user API key minted for the intake bot (the attach-logs key is tied to `system` and cannot impersonate the bot); falls back to `DISCOURSE_API_KEY` when that one is a global key |
| `HELP_REPLY_MAX_PER_IP` | guest follow-ups admitted per IP and per hour, default 10 |
| `HELP_REPLY_MAX_GLOBAL` | guest follow-ups admitted in total per hour, default 60 |

Guest help intake: non-clients (payment blocked, install failures) cannot pass
the ever-paid SSO gate, so the help forms on `https://warren.ro` and
`https://checkout.warrenbrowse.com` (the only two CORS origins) POST
`{"kind": "payment"|"install", "message", "platform"?, "website"}` (no contact field on purpose: the topic is public and there is no mail infrastructure; the returned topic_url is the follow-up channel; an unknown `contact` key from stale forms is ignored by serde)
to `/v1/help/intake`; the service opens a public topic in
`DISCOURSE_INTAKE_CATEGORY_ID` as `DISCOURSE_INTAKE_USERNAME` and returns the
topic URL the guest can follow without an account. Message 20..4000 chars,
platform <= 40; `website` is a honeypot and must be empty. `Content-Type: application/json` is required (CSRF boundary: forces a
CORS preflight for cross-origin browser calls).

Attachments (optional): `"attachments": [{"name", "type", "data"}]`, at most 2,
`data` standard base64, 4 MiB decoded each, whole body capped at 12 MiB. The
declared `type` is checked against the file's magic bytes and only
png/jpeg/webp/gif/pdf pass, so a renamed payload is refused rather than
published. The filename is rebuilt from an allowlist (no path separator, no
markdown metacharacter, extension forced from the sniffed type) because it
lands in a public post as a link label. Each file is uploaded to Discourse
before the topic is created: an upload failure aborts the whole intake with a
502 rather than opening a topic that silently lost the screenshots. Discourse
enforces its own `authorized_extensions`, `max_image_size_kb` and
`max_attachment_size_kb` on top, and the intake bot needs upload rights.
An over-cap body is 413; the rate limiter runs before the body is buffered, so
a body that declares its length costs no budget while one that hides it (no
`Content-Length`) is charged a slot. The per-IP budget buckets on
the RIGHTMOST X-Forwarded-For entry (the one our Caddy appends); budgets are
tunable via `INTAKE_MAX_PER_IP` (default 3/h) and `INTAKE_MAX_GLOBAL`
(default 30/h, a deliberate circuit breaker)
(any violation is the same 422). Rate limits: 3 intakes/hour/IP (requests
without `X-Forwarded-For` share one fail-closed bucket)
plus 30/hour globally, both in-memory only; the client IP is never logged,
persisted, or forwarded to Discourse. Design record: warren-core
`docs/58-SUPPORT-STAFF-GUIDE.md` 9.1-9.2 (internal design record).

Guest follow-up: the intake response also carries a `code`
(`WRN-XXXX-XXXX-XXXX-XXXX`), which the guest posts back to `/v1/help/reply`
with `{"code", "message", "website", "attachments"?}` to add a message to
their own topic without an account. The code is a keyed MAC over the topic id
(48-bit tag, Crockford base32, case- and separator-insensitive on input), so
the service stores no ticket table and a redeploy cannot orphan a code; it is
derived from `FORUM_HANDLE_SECRET`, which therefore also governs the codes.
It is a credential: it is returned once, never logged, and never written into
the public topic. An unknown or tampered code, and a code whose topic is gone,
are the same `404 {"error":"unknown_code"}`; a topic the intake bot does not
own is refused the same way (defence in depth behind the MAC). Follow-ups have
their own budget, `HELP_REPLY_MAX_PER_IP` (default 10/h) and
`HELP_REPLY_MAX_GLOBAL` (default 60/h), so a spam wave of new reports cannot
lock a reporter out of a conversation, and a mistyped code costs one slot
rather than a whole report budget. **Caddy must hand this route the real
client IP like `/v1/help/intake`**, or every visitor worldwide shares one
bucket.

The attach-logs flow (topic mode): a topic author opens `/attach?topic=<id>`,
the page deep-links `warren://attach-logs?sid=...&topic=...&host=...` into the
Warren app, the app sends the wallet-signed gzipped redacted report, and this
service verifies the signer is the topic author, uploads the log,
private-messages the staff group with the attachment, and leaves a staff-only
whisper on the public topic. The log never appears publicly.

Pre-topic mode: the forum theme calls `POST /v1/attach/new` while the user is
still composing the report, opens `/attach?sid=<sid>` (deep link carries
`topic=0`), and polls `/v1/attach/:sid/meta` to prefill the form from the
report's `warren-product-version` / `os` metadata lines. The app's signed
upload with `topic_id` 0 is parked in the session (state `received`, at most
100 sessions hold log bytes; the oldest holder is evicted at capacity). Right
after topic creation the theme calls `POST /v1/attach/:sid/bind` with the new
`topic_id`: same author check, then the same three Discourse writes. The
session API (`new`, `meta`, `bind`, `status`, `cancel`) answers CORS for the
origin `https://forum.warrenbrowse.com` only.

## Build and deploy

```bash
cargo test
cross build --release --target x86_64-unknown-linux-musl
docker build -t warren-connect:vX.Y.Z .
```

Deployed on the API host as part of the forum compose stack.

## License

AGPL-3.0-or-later. See [LICENSE](LICENSE).
