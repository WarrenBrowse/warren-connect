# Forum login v2: bound approval

This document is the wire and UX contract of the forum sign-in between
warren-connect and the three Warren app clients (desktop, Android, iOS). The
golden vector `vectors/forum_login_v2.json` (warren-vectors) pins every byte
this document names; where the two disagree, the vector wins.

## Why v2 exists

In v1 a sign-in session id (`sid`) was the only thing linking the approving
app to the browser, and a sid travels in deep links, QR codes and typed codes
that anybody can forward. Somebody could open their own forum sign-in, send the
victim the app link or the QR from their approval page, and receive a forum
session as the victim once the victim approved it. For an account that is
already a Discourse admin, that session is an admin session, whatever the SSO
payload says, because Discourse keeps the grant.

v2 makes completion require two proofs that cannot travel together:

1. **The browser secret.** `GET /sso` sets a 256-bit random cookie,
   `__Host-warren_login`, in the browser that opened the sign-in; the session
   stores its SHA-256. Every browser-side call (state poll, confirm,
   completion) must present it.
2. **The completion code.** The signed approval's answer carries a one-time
   6-digit code (OS RNG). No page ever renders it and it is never logged. The
   browser that opened the sign-in must present it (typed by the user, or
   handed over by the app through the handoff page) before it can complete.

A relayed approval hands the code to the victim's app and leaves the
attacker's browser with a cookie and no code. Five wrong codes cancel the
sign-in, so guessing succeeds with probability 5 in a million per approval the
attacker manages to obtain.

## Ids and inputs

A session has two ids, both 32 lowercase hex characters:

| id | carried by | the provider calls it |
|---|---|---|
| same-device id | the approval page button `<scheme>://forum-login?sid=<id>&host=<host>`, the Android intent link, the sign-in code shown under "The app did not open?" | `SameDevice` |
| cross-device id | the QR only: `<scheme>://forum-login?sid=<id>&host=<host>&xd=1` | `CrossDevice` |

The app receives a sid in three ways, and its UX depends on which:

- **deep link without `xd`**: same device, the browser is on this machine;
- **deep link with `xd=1`** (the QR): another device;
- **typed sign-in code** (Settings, Community forum, Enter sign-in code): the
  same-device id, but the user may be reading it off another device's screen.

## Endpoints

`<host>` is the allowlisted connect host of the compiled environment
(`connect.warrenbrowse.com` in prod). JSON bodies carry their keys in
ascending order.

### App side

#### `POST /v1/forum/login` (signed)

The X-Warren signed request, unchanged in its headers and signing rule. The
body changes:

```
{"login_version":2,"sid":"<sid>"}
```

exact bytes, compact, `login_version` first. `sid` is whichever id the app
received. `login_version` is inside the signed bytes, so it cannot be removed
by anyone relaying the request.

| status | body | meaning | app outcome |
|---|---|---|---|
| 200 | `{"completion":{"code":"<6 digits>","handoff_url":"https://<host>/handoff#sid=<same-device id>&code=<code>"},"handle":"<handle>","notify_slot":<n>,"status":"approved"}` | approved on the same-device id | approved, same-device completion |
| 200 | `{"completion":{"code":"<6 digits>"},"handle":"<handle>","notify_slot":<n>,"status":"approved"}` | approved on the cross-device id | approved, cross-device completion |
| 200 | `{"handle":...,"status":"approved"}` without `completion` | a provider that predates v2 (see compatibility) | approved, legacy completion |
| 400 | `{"error":"app_update_required"}` | the v1 body was refused | generic failure (a v2 client never sends v1) |
| 400 | `malformed payload` (text) | unknown `login_version` | generic failure |
| 401 | `{"error":"clock_skew"}` | device clock outside the 60 s window | clock-skew message (unchanged) |
| 403 | text | wallet never subscribed | subscription-required (unchanged) |
| 404 | text | session unknown, expired, cancelled, or already approved | expired (unchanged) |

`notify_slot` is omitted when none was drawn, as in v1. `handle` and
`notify_slot` keep their v1 meaning.

A session accepts exactly one approval. A second approval, from any wallet,
answers 404.

#### `GET /v1/session/{sid}/status` (the preflight, no cookie)

Unchanged for the app. Without the login cookie the provider answers
`200 {"status":"pending"}` while the session waits for an approval, and 404
otherwise; either id. The app keeps reading it before it signs, for the
`Date` header (the trusted clock) and to tell a dead session from a refused
signature. An app never holds the login cookie.

#### `POST /v1/session/{sid}/cancel` (no cookie, no body)

Unchanged: the app's decline. Either id. It ends a session that still waits
for an approval and does nothing to one past it. Always answers
`200 {"status":"cancelled"}`.

### Browser side (the provider's own pages)

The app never calls these. They are listed so client implementers know what
the browser does after the app's part is over.

| route | cookie | answers |
|---|---|---|
| `GET /sso?sso&sig` | sets `__Host-warren_login=<64 hex>; Max-Age=300; Path=/; Secure; HttpOnly; SameSite=Lax`, reusing the value the browser already holds | the approval page; a nonce whose live session belongs to another browser gets a 403 "started in another browser" page and no session |
| `GET /v1/session/{sid}/status` | required (same-device id) | `{"status":"pending"}`, `{"status":"awaiting_code"}`, `{"status":"approved"}`, `{"status":"completed"}`, `{"reason":"<reason>","status":"cancelled"}`; 403 `{"error":"browser_mismatch"}` for another browser's cookie or an unknown id, identical in both cases |
| `POST /v1/session/{sid}/confirm` | required, `Content-Type: application/json`, body `{"code":"<6 digits>"}` | 200 `{"status":"approved"}`; 422 `{"attempts_left":<n>,"error":"code_invalid"}`; 409 `{"reason":"code_attempts_exhausted","status":"cancelled"}` on the fifth wrong code; 409 with the state document when no code is awaited; 403 `browser_mismatch`; 400 without the JSON media type or for a code that is not 6 digits (no attempt spent) |
| `GET /v1/session/{sid}/complete` | required | 303 to Discourse with the signed payload when `approved`; 303 to the forum root when this browser already completed it (a second tab); 409 with the state document otherwise; 403 `browser_mismatch` |
| `GET /handoff` | sent by the page's own fetch | the handoff page (below) |

States: `pending` (waiting for the app), `awaiting_code` (the app approved in
v2, the browser must present the code), `approved` (ready to complete: the
code was confirmed, or a legacy approval was accepted), `completed`,
`cancelled`. Cancel reasons: `user_cancelled`, `subscription_required`,
`clock_skew`, `app_update_required`, `code_attempts_exhausted`.

The session TTL is 300 s from the moment the browser opened the page, confirm
step included.

### The handoff page

`https://<host>/handoff#sid=<same-device id>&code=<code>`. The sid and the code
ride in the URL fragment only, which no browser sends to a server, so they
reach no access log. The page's script reads them, removes the fragment from
the address bar and the history, and posts the confirm with the browser's own
cookie:

- the browser that opened the sign-in completes it and lands in the forum;
- any other browser shows: "This browser did not start this sign-in. [...] If
  someone sent you a link or a code to approve, they were trying to sign in to
  the forum as you: do not send them anything." The code is never displayed;
- a browser that reports cookies disabled is told it cannot finish the sign-in
  and to type the code on the sign-in page instead, without any request.

## App behaviour

### Consent prompt

Unchanged, including the `xd=1` wording ("the browser being signed in is on
another device [...] If someone sent you this code, they are signing in as
you").

### After a 200 with a `completion` object

Validate `completion.code` against `^[0-9]{6}$` and, when present,
`completion.handoff_url` against the exact prefix
`https://<allowlisted connect host>/handoff#sid=` followed by 32 lowercase hex,
`&code=` and the same code. Anything else is ignored as absent.

| how the sid arrived | what the app shows | handoff |
|---|---|---|
| deep link, no `xd` | "Finishing the sign-in in your browser". A secondary action, "The sign-in page is in another browser? Show the code", reveals the code with the warning below | open `handoff_url` in the system default browser at once (desktop: `shell.openExternal`; Android: `ACTION_VIEW` intent; iOS: `UIApplication.open`) |
| deep link with `xd=1` (QR) | the code, large, with: "Type this code on the sign-in page of your other device. Never read it out or send it to anyone, including someone who says they are from Warren." | none is given, never build one |
| typed sign-in code | the code with the same warning, plus a button "Finish in this device's browser" | on the button only, when `handoff_url` is present |

Rules for every platform:

- The code lives in memory for the screen that shows it, and at most 300 s
  after the answer arrived (the session is dead by then); it is never
  persisted, logged, put in a notification, copied to the clipboard
  automatically, or included in a problem report. The same holds for
  `handoff_url`, which contains the code and the sid.
- The handoff URL is opened only after a same-device approval and only once.
  The app does not open it after a QR approval, even if a provider sent one.
- A failed handoff needs no special handling in the app: the page explains
  itself, and the user can fall back to "Show the code".

### After a 200 without `completion`

The provider predates v2. Show the v1 outcome ("approved, return to your
browser"); the browser completes on its own.

### Everything else

Every non-200 outcome maps exactly as in v1. `400 app_update_required` cannot
happen to a v2 client and maps to the generic failure.

## Compatibility

- **A v2 app against a v1 provider** (warren-connect v0.15.8 and older): the
  v1 provider parses the body ignoring unknown fields, verifies the signature
  over the same bytes, and answers the v1 body without `completion`. The app
  follows the legacy completion. Nothing else changes.
- **A v1 app against a v2 provider**: its body carries no `login_version`.
  - staff wallets (on `WARREN_ADMIN_PUBKEYS`, or admin or moderator of their
    forum account, or whose staff status cannot be read) are always refused;
  - everyone else is refused unless `WARREN_CONNECT_LEGACY_APPROVAL=allow`,
    and when accepted, the login still completes only in the browser holding
    the cookie;
  - a refusal answers 400 `app_update_required` (the v1 app shows a generic
    failure) and cancels the browser session with reason
    `app_update_required`, which the page renders as "update your Warren app".
- The preflight and the cancel behave for a v1 app exactly as before.

## Client implementation notes

- **Desktop**: the daemon's `SignForumLogin` signs the fixed body
  (`mullvad-daemon` `forum_login_body`); it becomes
  `{"login_version":2,"sid":"<sid>"}`. The Electron main process
  (`forum-login.ts`) parses `completion` out of the 200 body, validates it as
  above, opens the handoff for a same-device deep link, and hands the code to
  the renderer for the QR and typed cases over IPC. The code never reaches the
  renderer's logs or the redux store beyond the screen that shows it.
- **Android and iOS**: the shared `warren-forum` crate builds the body and
  maps the answer. The FFI envelope gains an additive `completion` object,
  `{"ok":true,"handle":"...","notify_slot":1,"completion":{"code":"123456","handoff_url":"https://..."}}`,
  omitted when the provider sent none. Kotlin and Swift show the code and
  open the handoff; neither logs the envelope.
- **Tests**: replay `forum_login_v2.json`: the `login_bound` request bytes
  through each signer, the two approved answers through the answer parser
  (code, handoff URL, and the handoff validation rejecting a foreign host, a
  query-string carrier or a code mismatch), and the legacy answer without
  `completion`.

## Security properties

- A relayed same-device or cross-device approval does not complete the
  attacker's browser: it lacks the code, and the code went to the victim's
  app (`tests/sso_flow.rs`, `a_relayed_*`).
- Without the cookie a browser cannot read the state, confirm, or complete;
  a stranger's cookie answers exactly like an unknown id.
- A replayed `sso` payload from another browser gets no session.
- Staff is asserted only on a v2 approval on the same-device id, which the
  browser completing it confirmed with the code.
- Residuals:
  - a victim who reads the code to an attacker (the same limit as any
    one-time code; the app's warning and the handoff page are the answer);
  - a typed sign-in code resolves as the same-device id, so an allowlisted
    wallet approving one typed from another device's screen still carries the
    staff claim to whichever browser presents the code;
  - once approved, a login can be ended only by its own browser: a victim who
    notices a relayed approval cannot withdraw it, and the attacker keeps five
    guesses until the TTL;
  - the legacy transition window for non-staff wallets while the flag is
    `allow`;
  - an app-side cancel by anyone holding a sid, before the approval only.
