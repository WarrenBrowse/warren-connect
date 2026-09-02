//! Server-rendered pages: the login approval page and the transparency page.
//! Fully self-contained (inline CSS/JS, server-side SVG QR, no web fonts): no
//! external resource is ever loaded, so the page itself cannot leak a request.
//! Visual identity mirrors warren-website (the "Terrier Warren" palette, oklch
//! tokens, a system serif for display and the system sans for body).

use qrcode::QrCode;
use qrcode::render::svg;
use std::sync::LazyLock;

use crate::i18n::Lang;

/// Shared design tokens + base typography (warren-website "Terrier Warren").
/// No web font is loaded; a system serif approximates the display face and the
/// system sans the body, keeping the page request-free.
const STYLE: &str = r#"
:root{
  --bg:oklch(0.92 0.028 78); --fg:oklch(0.25 0.028 60);
  --card:oklch(0.96 0.02 80); --muted:oklch(0.45 0.03 60);
  --primary:oklch(0.47 0.10 50); --primary-hover:oklch(0.40 0.11 48);
  --primary-fg:oklch(0.97 0.018 78); --gold:oklch(0.62 0.09 74);
  --border:oklch(0.82 0.045 78);
}
*{box-sizing:border-box}
body{margin:0;background:#efe6d1;background:var(--bg);color:#3a2f24;color:var(--fg);
  font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,system-ui,sans-serif;
  line-height:1.6;-webkit-font-smoothing:antialiased;text-rendering:optimizeLegibility;}
.serif{font-family:"Iowan Old Style","Palatino Linotype",Palatino,"Book Antiqua",Georgia,serif;}
h1,h2{font-family:"Iowan Old Style","Palatino Linotype",Palatino,"Book Antiqua",Georgia,serif;
  font-weight:600;letter-spacing:.005em;color:var(--fg);}
a{color:var(--primary)}
.brand{font-family:"Iowan Old Style",Palatino,Georgia,serif;font-weight:600;
  text-transform:uppercase;letter-spacing:.34em;font-size:1.05rem;color:var(--fg);}
.label{text-transform:uppercase;letter-spacing:.22em;font-size:.72rem;font-weight:700;
  color:var(--primary);}
.spark{color:var(--gold);font-size:1rem;line-height:1;display:inline-block}
.rule{height:1px;border:0;background:linear-gradient(90deg,transparent,var(--gold),transparent);}
.muted{color:var(--muted);font-size:.85rem;}
code{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;
  background:oklch(0.88 0.04 80);padding:.12rem .38rem;border-radius:5px;font-size:.9em;}
.tagline{font-style:italic;color:var(--gold);letter-spacing:.02em;}
"#;

/// URL scheme the app of THIS stack's environment registers. The app parses a
/// deep link against its own scheme and silently ignores any other, so serving
/// a production link to a beta install makes the app open and do nothing.
/// Unset means production, leaving an existing deployment untouched.
#[must_use]
pub fn configured_scheme_from(raw: Option<&str>) -> &str {
    match raw.map(str::trim).filter(|v| !v.is_empty()) {
        Some(v) => v,
        None => "warren",
    }
}

fn scheme() -> &'static str {
    static SCHEME: LazyLock<String> = LazyLock::new(|| {
        configured_scheme_from(std::env::var("WARREN_DEEP_LINK_SCHEME").ok().as_deref()).to_owned()
    });
    &SCHEME
}

/// The deep link the app registers for forum logins, on the configured scheme.
#[must_use]
pub fn deep_link_with_scheme(scheme: &str, sid: &str, host: &str) -> String {
    format!("{scheme}://forum-login?sid={sid}&host={host}")
}

/// The `warren://` deep link the app registers for forum logins.
#[must_use]
pub fn deep_link(sid: &str, host: &str) -> String {
    deep_link_with_scheme(scheme(), sid, host)
}

/// The deep link carried by the QR, on the configured scheme.
///
/// It carries the session's SECOND id plus `xd=1`. Both halves matter: the id
/// is what lets the service refuse to assert staff on this path, and the flag
/// is what lets the app say plainly that the sign-in is happening on another
/// device, which is the only thing that can make a relayed approval look
/// wrong to the person approving it.
#[must_use]
pub fn cross_device_deep_link_with_scheme(scheme: &str, qr_sid: &str, host: &str) -> String {
    format!("{scheme}://forum-login?sid={qr_sid}&host={host}&xd=1")
}

/// The QR's deep link on the configured scheme.
#[must_use]
pub fn cross_device_deep_link(qr_sid: &str, host: &str) -> String {
    cross_device_deep_link_with_scheme(scheme(), qr_sid, host)
}

/// The Android application id registering `scheme`, one per product
/// environment (warren-app `android/app/build.gradle.kts`, `productFlavors`).
/// Chromium's `intent://` form needs it to open the app directly and to fall
/// back to a URL when the app is absent; an unknown scheme gets no intent link
/// and the page keeps the plain one.
#[must_use]
pub fn android_package_for_scheme(scheme: &str) -> Option<&'static str> {
    match scheme {
        "warren" => Some("com.warrenbrowse.vpn"),
        "warren-beta" => Some("com.warrenbrowse.vpn.beta"),
        "warren-staging" => Some("com.warrenbrowse.vpn.staging"),
        _ => None,
    }
}

/// The Chromium-on-Android form of the same-device login link: the app
/// package is named so Chrome opens it without a chooser, and the fallback
/// URL (appended by the page script, which alone knows its own address)
/// brings the user back to this page with the recovery block open instead of
/// dropping the tap silently. Everything before `#Intent` is the frozen deep
/// link the app parses, so the two forms cannot diverge.
#[must_use]
pub fn android_intent_link_with_scheme(scheme: &str, sid: &str, host: &str) -> Option<String> {
    let package = android_package_for_scheme(scheme)?;
    Some(format!(
        "intent://forum-login?sid={sid}&host={host}#Intent;scheme={scheme};package={package};S.browser_fallback_url="
    ))
}

/// Approval page shown to the browser while waiting for the app's signature.
#[must_use]
pub fn approval_page(
    lang: Lang,
    ids: &crate::sessions::SessionIds,
    host: &str,
    nonce: &str,
) -> String {
    let s = lang.strings();
    let code = lang.code();
    let sid = ids.sid.as_str();
    let link = deep_link(sid, host);
    let intent_link = android_intent_link_with_scheme(scheme(), sid, host).unwrap_or_default();
    let qr_link = cross_device_deep_link(&ids.qr_sid, host);
    let qr_svg = QrCode::new(qr_link.as_bytes()).map_or_else(
        |_| String::new(),
        |c| {
            c.render::<svg::Color<'_>>()
                .min_dimensions(180, 180)
                .quiet_zone(true)
                .build()
        },
    );
    format!(
        r##"<!doctype html>
<html lang="{code}">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex">
<title>{tab}</title>
<style nonce="{nonce}">{style}
  body{{display:flex;min-height:100vh;align-items:center;justify-content:center;padding:1.5rem;}}
  .card{{background:var(--card);border:1px solid var(--border);border-radius:16px;
    padding:2.4rem 2rem;max-width:27rem;width:100%;text-align:center;
    box-shadow:0 18px 40px -24px oklch(0.25 0.03 60 / .5);}}
  .brand{{display:block;margin-bottom:.5rem;}}
  h1{{font-size:1.5rem;margin:.5rem 0 1rem;}}
  p{{margin:.6rem 0;}}
  a.button{{display:inline-block;background:var(--primary);color:var(--primary-fg);
    padding:.75rem 1.6rem;border-radius:10px;text-decoration:none;font-weight:600;
    margin:1.1rem 0 .3rem;transition:background .15s ease;}}
  a.button:hover{{background:var(--primary-hover);}}
  .qr{{background:#fff;display:inline-block;padding:.55rem;border-radius:10px;
    margin-top:.6rem;line-height:0;border:1px solid var(--border);}}
  .qr svg{{width:180px;height:180px;display:block;}}
  .foot{{margin-top:1.6rem;}}
  /* Recovery block: hidden until a tap provably went nowhere. */
  #noapp{{text-align:left;background:oklch(0.9 0.035 80);border:1px solid var(--border);
    border-radius:12px;padding:.9rem 1rem;margin:1rem 0 .4rem;}}
  #noapp h2{{font-size:1.05rem;margin:0 0 .5rem;}}
  #noapp p{{font-size:.9rem;margin:.45rem 0;}}
  #noapp code{{font-size:1rem;letter-spacing:.06em;word-break:break-all;}}
  button.copy{{font:inherit;font-size:.85rem;font-weight:600;color:var(--primary);
    background:transparent;border:1px solid var(--primary);border-radius:8px;
    padding:.3rem .7rem;margin-left:.4rem;cursor:pointer;}}
</style>
</head>
<body>
<div class="card">
  <span class="brand">Warren</span>
  <div class="spark">&#10022;</div>
  <div class="label">{label}</div>
  <h1>{heading}</h1>
  <p>{body}</p>
  <a class="button" id="open" href="{link}" data-intent="{intent_link}">{button}</a>
  <div id="noapp" hidden>
    <h2>{noapp_heading}</h2>
    <p>{noapp_browser}</p>
    <p>{noapp_code}</p>
    <p><code>{sid}</code><button class="copy" id="copy" type="button"
       data-copied="{copied}">{copy}</button></p>
    <p>{noapp_install}</p>
  </div>
  <p class="muted">{scan}</p>
  <div class="qr">{qr_svg}</div>
  <p class="muted">{session} <code>{sid}</code> &middot; {expires}</p>
  <p id="state" class="muted"
     data-expired="{expired}" data-subscription="{subscription}"
     data-cancelled="{cancelled}" data-clock="{clock}">{waiting}</p>
  <hr class="rule">
  <p class="foot tagline">{tagline}</p>
</div>
<script nonce="{nonce}">
  const el = document.getElementById('state');
  let timer = null;
  let done = false;
  // Did the tap take the user to the app? Measured, never assumed: a page
  // that leaves (pagehide, or hidden visibility) was handed to the app; a
  // page still fully visible NOAPP_MS after the tap was not (Firefox's own
  // "open in app" sheet, a stale app without the handler, no app at all).
  // Live 2026-08-28/29: two such taps sat on "Waiting for approval" for the
  // whole session with nothing on screen saying what to do.
  const NOAPP_MS = 1500;
  const open = document.getElementById('open');
  const noapp = document.getElementById('noapp');
  let left = false;
  const leaving = () => {{ left = true; }};
  window.addEventListener('pagehide', leaving);
  document.addEventListener('visibilitychange', () => {{
    if (document.visibilityState === 'hidden') leaving();
  }});
  open.addEventListener('click', () => {{
    left = false;
    setTimeout(() => {{ if (!left && !done) noapp.hidden = false; }}, NOAPP_MS);
  }});
  // Chromium on Android drops a custom-scheme tap silently when nothing
  // handles it; the intent form names the package and a fallback URL, which
  // is this very page with the recovery block open. Firefox keeps the plain
  // link: it raises its own sheet on that form, and confirming it is the path
  // the live logins prove.
  const ua = navigator.userAgent;
  if (open.dataset.intent && /Android/i.test(ua) && !/Firefox|Fennec|Focus|FxiOS/i.test(ua)) {{
    const back = new URL(window.location.href);
    back.searchParams.set('noapp', '1');
    open.href = open.dataset.intent + encodeURIComponent(back.href) + ';end';
  }}
  if (new URLSearchParams(window.location.search).get('noapp') === '1') {{
    noapp.hidden = false;
  }}
  const copy = document.getElementById('copy');
  copy.addEventListener('click', async () => {{
    try {{
      await navigator.clipboard.writeText('{sid}');
      copy.textContent = copy.dataset.copied;
    }} catch (e) {{}}
  }});
  const poll = async () => {{
    timer = null;
    if (done) return;
    try {{
      // Bounded: a fetch frozen by a background tab must settle, or the
      // chain is stranded with nothing left to reschedule it.
      const r = await fetch('/v1/session/{sid}/status',
        {{ signal: AbortSignal.timeout(5000) }});
      // Only "no such session" is terminal; a 502 while the service restarts
      // is not, and the next poll recovers from it.
      if (r.status === 404) {{ done = true; el.textContent = el.dataset.expired; return; }}
      if (!r.ok) {{ timer = setTimeout(poll, 700); return; }}
      const s = await r.json();
      if (s.status === 'approved') {{ done = true; window.location = '/v1/session/{sid}/complete'; return; }}
      if (s.status === 'cancelled') {{
        done = true;
        el.textContent = s.reason === 'subscription_required' ? el.dataset.subscription
          : s.reason === 'clock_skew' ? el.dataset.clock
          : el.dataset.cancelled;
        return;
      }}
    }} catch (e) {{}}
    timer = setTimeout(poll, 700);
  }};
  // Tapping the button backgrounds this tab and the browser freezes its
  // timers (measured live 2026-08-18: an approved login sat on "waiting" for
  // ~50 s after the return). Poll the moment the page is visible again. A
  // pending timer is replaced so there is ever one chain; a fetch in flight
  // is left to settle (it is bounded above) and reschedules itself.
  document.addEventListener('visibilitychange', () => {{
    if (document.visibilityState === 'visible' && !done && timer !== null) {{
      clearTimeout(timer);
      poll();
    }}
  }});
  poll();
</script>
</body>
</html>"##,
        style = STYLE,
        nonce = nonce,
        tab = s.a_tab,
        label = s.a_label,
        heading = s.a_heading,
        body = s.a_body,
        button = s.a_button,
        scan = s.a_scan,
        session = s.a_session,
        expires = s.a_expires,
        waiting = s.a_waiting,
        expired = s.a_expired,
        subscription = s.a_subscription,
        cancelled = s.a_cancelled,
        clock = s.a_clock,
        noapp_heading = s.a_noapp_heading,
        noapp_browser = s.a_noapp_browser,
        noapp_code = s.a_noapp_code,
        noapp_install = s.a_noapp_install,
        copy = s.a_copy,
        copied = s.a_copied,
        tagline = s.tagline,
    )
}

/// The attach-logs deep link on an explicit scheme. FROZEN shape past the
/// scheme: the app parses it verbatim. Topic 0 means "new report being
/// composed" (pre-topic session).
#[must_use]
pub fn attach_deep_link_with_scheme(scheme: &str, sid: &str, topic_id: u64, host: &str) -> String {
    format!("{scheme}://attach-logs?sid={sid}&topic={topic_id}&host={host}")
}

/// The deep link the app registers for attaching problem-report logs to a
/// forum topic, on the configured scheme.
#[must_use]
pub fn attach_deep_link(sid: &str, topic_id: u64, host: &str) -> String {
    attach_deep_link_with_scheme(scheme(), sid, topic_id, host)
}

use crate::FORUM_PUBLIC_URL;

/// Attach-logs page (topic mode): explains the flow, auto-attempts the deep
/// link, offers a manual click, polls the attach session every 2 s, and on
/// success redirects back to the topic.
#[must_use]
pub fn attach_page(lang: Lang, sid: &str, topic_id: u64, host: &str, nonce: &str) -> String {
    let s = lang.strings();
    // On done: show the success text briefly, then land back on the topic.
    let settle = format!(
        "if (s.status === 'done') {{ say(el.dataset.done, false);\n        \
         setTimeout(() => location.replace('{FORUM_PUBLIC_URL}/t/{topic_id}'), 1500); return; }}"
    );
    attach_page_shell(
        lang,
        sid,
        &attach_deep_link(sid, topic_id, host),
        s.l_expires,
        s.l_done,
        &settle,
        nonce,
    )
}

/// Attach-logs page (pre-topic mode, session minted by `/v1/attach/new`): the
/// composer lives in the forum tab, so on receipt the page tells the user to
/// return there (and tries `window.close()`, which succeeds when this tab was
/// script-opened) instead of redirecting.
#[must_use]
pub fn attach_page_pre(lang: Lang, sid: &str, host: &str, nonce: &str) -> String {
    let s = lang.strings();
    let settle = "if (s.status === 'received' || s.status === 'done') {\n        \
         say(el.dataset.done, false);\n        \
         setTimeout(() => window.close(), 1500); return; }";
    attach_page_shell(
        lang,
        sid,
        &attach_deep_link(sid, 0, host),
        s.l_expires_pre,
        s.l_received,
        settle,
        nonce,
    )
}

/// Shared shell of the two attach pages; `settle_js` decides what the poll
/// does when the session reaches its success state (`el.dataset.done` carries
/// `done_text`).
fn attach_page_shell(
    lang: Lang,
    sid: &str,
    link: &str,
    expires: &str,
    done_text: &str,
    settle_js: &str,
    nonce: &str,
) -> String {
    let s = lang.strings();
    let code = lang.code();
    format!(
        r##"<!doctype html>
<html lang="{code}">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex">
<title>{tab}</title>
<style nonce="{nonce}">{style}
  body{{display:flex;min-height:100vh;align-items:center;justify-content:center;padding:1.5rem;}}
  .card{{background:var(--card);border:1px solid var(--border);border-radius:16px;
    padding:2.4rem 2rem;max-width:27rem;width:100%;text-align:center;
    box-shadow:0 18px 40px -24px oklch(0.25 0.03 60 / .5);}}
  .brand{{display:block;margin-bottom:.5rem;}}
  h1{{font-size:1.5rem;margin:.5rem 0 1rem;}}
  p{{margin:.6rem 0;}}
  a.button{{display:inline-block;background:var(--primary);color:var(--primary-fg);
    padding:.75rem 1.6rem;border-radius:10px;text-decoration:none;font-weight:600;
    margin:1.1rem 0 .3rem;transition:background .15s ease;}}
  a.button:hover{{background:var(--primary-hover);}}
  .foot{{margin-top:1.6rem;}}
  /* Live progress. The forum writes take seconds; without a moving indicator
     the page looks frozen right after the user approves in the app. */
  .spinner{{width:1.15rem;height:1.15rem;border-radius:50%;flex:0 0 auto;
    border:2px solid var(--border);border-top-color:var(--primary);
    animation:spin .8s linear infinite;}}
  #state{{display:flex;align-items:center;justify-content:center;gap:.6rem;
    min-height:1.6rem;transition:color .2s ease;}}
  #state[data-busy="1"]{{color:var(--fg);font-weight:600;}}
  .card[data-busy="1"] a.button{{opacity:.45;pointer-events:none;}}
  @keyframes spin{{to{{transform:rotate(360deg);}}}}
  @media (prefers-reduced-motion:reduce){{.spinner{{animation-duration:2.4s;}}}}
</style>
</head>
<body>
<div class="card" id="card">
  <span class="brand">Warren</span>
  <div class="spark">&#10022;</div>
  <div class="label">{label}</div>
  <h1>{heading}</h1>
  <p>{body}</p>
  <a class="button" href="{link}">{button}</a>
  <p class="muted">{session} <code>{sid}</code> &middot; {expires}</p>
  <p id="state" class="muted"
     data-expired="{expired}" data-done="{done}"
     data-cancelled="{cancelled}" data-processing="{processing}"><span id="msg">{waiting}</span></p>
  <hr class="rule">
  <p class="foot tagline">{tagline}</p>
</div>
<script nonce="{nonce}">
  setTimeout(() => {{ window.location = '{link}'; }}, 300);
  const el = document.getElementById('state');
  const msg = document.getElementById('msg');
  const card = document.getElementById('card');
  const say = (text, busy) => {{
    msg.textContent = text;
    el.dataset.busy = busy ? '1' : '0';
    card.dataset.busy = busy ? '1' : '0';
    let sp = el.querySelector('.spinner');
    if (busy && !sp) {{ sp = document.createElement('span'); sp.className = 'spinner'; el.prepend(sp); }}
    if (!busy && sp) {{ sp.remove(); }}
  }};
  // 700 ms, not 2 s: this poll is the only thing between approving in the app
  // and the page reacting, and the response is a tiny JSON.
  const POLL_MS = 700;
  const poll = async () => {{
    try {{
      const r = await fetch('/v1/attach/{sid}/status');
      if (!r.ok) {{ say(el.dataset.expired, false); return; }}
      const s = await r.json();
      {settle_js}
      if (s.status === 'cancelled') {{ say(el.dataset.cancelled, false); return; }}
      if (s.status === 'processing') {{ say(el.dataset.processing, true); }}
    }} catch (e) {{}}
    setTimeout(poll, POLL_MS);
  }};
  poll();
</script>
</body>
</html>"##,
        style = STYLE,
        nonce = nonce,
        tab = s.l_tab,
        label = s.a_label,
        heading = s.l_heading,
        body = s.l_body,
        button = s.a_button,
        session = s.a_session,
        waiting = s.l_waiting,
        expired = s.l_expired,
        done = done_text,
        cancelled = s.l_cancelled,
        processing = s.l_processing,
        tagline = s.tagline,
    )
}

/// Public transparency page: what this service and the forum can and cannot
/// see. Kept in lockstep with doc 55 of warren-core.
#[must_use]
pub fn transparency_page(lang: Lang, nonce: &str) -> String {
    let s = lang.strings();
    let code = lang.code();
    format!(
        r##"<!doctype html>
<html lang="{code}">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{tab}</title>
<style nonce="{nonce}">{style}
  body{{max-width:47rem;margin:0 auto;padding:2.5rem 1.25rem 4rem;}}
  .brand{{display:block;margin-bottom:.2rem;}}
  h1{{font-size:1.9rem;margin:.4rem 0 1.4rem;}}
  h2{{font-size:1.25rem;margin:2.2rem 0 .6rem;}}
  pre{{background:var(--card);border:1px solid var(--border);padding:1rem;
    border-radius:10px;overflow-x:auto;}}
  table{{border-collapse:collapse;width:100%;margin:.5rem 0;}}
  td,th{{border:1px solid var(--border);padding:.6rem .7rem;text-align:left;
    vertical-align:top;}}
  th{{background:var(--card);}}
  ul{{padding-left:1.2rem;}} li{{margin:.35rem 0;}}
  .foot{{margin-top:2.4rem;}}
</style>
</head>
<body>
<span class="brand">Warren</span>
<div class="label">{label}</div>
<h1>{heading}</h1>
<p>{intro}</p>
<hr class="rule">
<h2>{see_h}</h2>
<table>
<tr><th>{col_party}</th><th>{col_sees}</th></tr>
<tr><td>{r1p}</td><td>{r1s}</td></tr>
<tr><td>{r2p}</td><td>{r2s}</td></tr>
<tr><td>{r3p}</td><td>{r3s}</td></tr>
</table>
<p>{stored}</p>
<h2>{ip_h}</h2>
<p>{ip_p}</p>
<pre>reverse_proxy discourse:80 {{
    header_up X-Forwarded-For "0.0.0.0"
    header_up X-Real-IP "0.0.0.0"
}}</pre>
<p>{ip_note}</p>
<h2>{cannot_h}</h2>
<ul><li>{c1}</li><li>{c2}</li><li>{c3}</li></ul>
<hr class="rule">
<p class="foot tagline">{tagline}</p>
</body>
</html>"##,
        style = STYLE,
        nonce = nonce,
        tab = s.t_tab,
        label = s.a_label,
        heading = s.t_heading,
        intro = s.t_intro,
        see_h = s.t_see_h,
        col_party = s.t_col_party,
        col_sees = s.t_col_sees,
        r1p = s.t_row1_party,
        r1s = s.t_row1_sees,
        r2p = s.t_row2_party,
        r2s = s.t_row2_sees,
        r3p = s.t_row3_party,
        r3s = s.t_row3_sees,
        stored = s.t_stored,
        ip_h = s.t_ip_h,
        ip_p = s.t_ip_p,
        ip_note = s.t_ip_note,
        cannot_h = s.t_cannot_h,
        c1 = s.t_cannot_1,
        c2 = s.t_cannot_2,
        c3 = s.t_cannot_3,
        tagline = s.tagline,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deep_link_embeds_session_and_host() {
        assert_eq!(
            deep_link("abc", "connect.warrenbrowse.com"),
            "warren://forum-login?sid=abc&host=connect.warrenbrowse.com"
        );
    }

    #[test]
    fn deep_links_carry_the_configured_scheme() {
        // The app registers a scheme per product environment, and its parser
        // rejects any other one silently: a beta install handed a `warren://`
        // link simply does nothing, which is what a user reports as "the app
        // opens and nothing happens". The stack tells us which app it serves.
        assert_eq!(
            deep_link_with_scheme("warren-beta", "abc", "connect.warrenbrowse.com"),
            "warren-beta://forum-login?sid=abc&host=connect.warrenbrowse.com"
        );
        assert_eq!(
            attach_deep_link_with_scheme("warren-beta", "abc", 7, "connect.warrenbrowse.com"),
            "warren-beta://attach-logs?sid=abc&topic=7&host=connect.warrenbrowse.com"
        );
        // Unset means production, so an existing deployment is unaffected.
        assert_eq!(configured_scheme_from(None), "warren");
        assert_eq!(configured_scheme_from(Some("warren-beta")), "warren-beta");
    }

    const NONCE: &str = "0123456789abcdef0123456789abcdef";

    fn ids(sid: &str, qr_sid: &str) -> crate::sessions::SessionIds {
        crate::sessions::SessionIds {
            sid: sid.to_owned(),
            qr_sid: qr_sid.to_owned(),
        }
    }

    #[test]
    fn approval_page_contains_link_qr_and_poll() {
        let page = approval_page(
            Lang::En,
            &ids("deadbeef", "cafe"),
            "connect.warrenbrowse.com",
            NONCE,
        );
        assert!(page.contains("warren://forum-login?sid=deadbeef"));
        assert!(page.contains("<svg"), "QR must be rendered inline");
        assert!(page.contains("/v1/session/deadbeef/status"));
        assert!(!page.contains("http://cdn"), "no external resources");
        assert!(!page.contains("googleapis"), "no web fonts");
    }

    #[test]
    fn the_button_and_the_qr_never_carry_the_same_id() {
        // The button opens the app on THIS machine; the QR is read from
        // another one. Serving one id for both would erase the distinction the
        // login handler needs to refuse asserting staff over a relayed link.
        let page = approval_page(
            Lang::En,
            &ids("deadbeef", "cafe"),
            "connect.warrenbrowse.com",
            NONCE,
        );
        assert!(
            page.contains(
                r#"href="warren://forum-login?sid=deadbeef&host=connect.warrenbrowse.com""#
            ),
            "the button keeps the same-device id"
        );
        assert!(
            !page.contains("sid=cafe&host=connect.warrenbrowse.com\""),
            "the cross-device id must never be the button's"
        );
        assert_eq!(
            cross_device_deep_link_with_scheme("warren", "cafe", "connect.warrenbrowse.com"),
            "warren://forum-login?sid=cafe&host=connect.warrenbrowse.com&xd=1",
            "the marker is part of the frozen link shape the app parses"
        );
    }

    #[test]
    fn approval_page_is_localized() {
        let fr = approval_page(Lang::Fr, &ids("s", "q"), "h", NONCE);
        assert!(fr.contains("lang=\"fr\""));
        assert!(fr.contains("Ouvrir l'application Warren"));
        assert!(fr.contains("L'application ne s'est pas ouverte ?"));
        let ro = approval_page(Lang::Ro, &ids("s", "q"), "h", NONCE);
        assert!(ro.contains("lang=\"ro\""));
        assert!(ro.contains("Aplica\u{21b}ia nu s-a deschis?"));
    }

    #[test]
    fn approval_page_recovers_when_the_tap_does_not_open_the_app() {
        // Live 2026-08-28/29: two Firefox-for-Android users tapped the button,
        // the page never lost visibility (the app never came up), and they
        // watched "Waiting for approval" until they gave up. The page has to
        // notice that the tap went nowhere and say what to do: confirm the
        // browser's own "open in app" sheet, type the code in the app, or
        // install it.
        let page = approval_page(
            Lang::En,
            &ids("deadbeef", "cafe"),
            "connect.warrenbrowse.com",
            NONCE,
        );
        assert!(
            page.contains(r#"<div id="noapp" hidden>"#),
            "hidden until needed"
        );
        assert!(page.contains("The app did not open?"));
        assert!(page.contains("choose Open"), "names the browser's sheet");
        assert!(
            page.contains("Enter sign-in code"),
            "names the manual path in the app"
        );
        assert!(
            page.contains("1.0.0 or later"),
            "names the minimum app version"
        );
        assert!(
            page.contains("pagehide"),
            "departure is detected by the page leaving"
        );
        assert!(
            page.contains("NOAPP_MS = 1500"),
            "reveal after a bounded wait"
        );
        assert!(
            page.contains("navigator.clipboard"),
            "the code can be copied for the app"
        );
        assert!(page.contains("Copy code"));
        assert!(
            page.contains("get('noapp') === '1'"),
            "the intent fallback lands on the revealed block"
        );
    }

    #[test]
    fn approval_page_offers_a_chromium_intent_link_with_fallback() {
        // Chromium on Android drops a custom-scheme tap silently when no app
        // handles it. An `intent://` link names the package and a fallback URL,
        // so the browser either opens the app or brings the user back here
        // with the recovery block open. Firefox keeps the plain link: its
        // handling of the plain scheme is what the live evidence proved works
        // once the user confirms the sheet.
        let page = approval_page(
            Lang::En,
            &ids("deadbeef", "cafe"),
            "connect.warrenbrowse.com",
            NONCE,
        );
        assert!(page.contains(
            r#"data-intent="intent://forum-login?sid=deadbeef&host=connect.warrenbrowse.com#Intent;scheme=warren;package=com.warrenbrowse.vpn;S.browser_fallback_url="#
        ));
        assert!(
            page.contains("/Firefox|Fennec|Focus|FxiOS/"),
            "Firefox keeps the plain link"
        );
        assert!(
            page.contains(
                r#"href="warren://forum-login?sid=deadbeef&host=connect.warrenbrowse.com""#
            ),
            "the plain link stays the default"
        );
        assert_eq!(
            android_package_for_scheme("warren-beta"),
            Some("com.warrenbrowse.vpn.beta")
        );
        assert_eq!(
            android_package_for_scheme("warren-staging"),
            Some("com.warrenbrowse.vpn.staging")
        );
        assert_eq!(
            android_package_for_scheme("warren"),
            Some("com.warrenbrowse.vpn")
        );
        assert_eq!(android_package_for_scheme("other"), None);
    }

    #[test]
    fn approval_page_never_auto_navigates_to_the_deep_link() {
        // The attach page auto-attempts its link 300 ms after load. The login
        // page must not: Chromium blocks a script-initiated custom-scheme
        // navigation without a gesture, and Firefox would raise its sheet
        // before the user has read what they are approving.
        let page = approval_page(
            Lang::En,
            &ids("deadbeef", "cafe"),
            "connect.warrenbrowse.com",
            NONCE,
        );
        assert!(!page.contains("window.location = 'warren://"));
        assert!(!page.contains("setTimeout(() => { window.location"));
    }

    #[test]
    fn attach_deep_link_is_the_frozen_shape() {
        assert_eq!(
            attach_deep_link(
                "00112233445566778899aabbccddeeff",
                42,
                "connect.warrenbrowse.com"
            ),
            "warren://attach-logs?sid=00112233445566778899aabbccddeeff&topic=42&host=connect.warrenbrowse.com"
        );
    }

    #[test]
    fn attach_page_contains_link_autopen_and_poll() {
        let page = attach_page(Lang::En, "deadbeef", 42, "connect.warrenbrowse.com", NONCE);
        assert!(
            page.contains(
                "warren://attach-logs?sid=deadbeef&topic=42&host=connect.warrenbrowse.com"
            )
        );
        assert!(page.contains("/v1/attach/deadbeef/status"));
        assert!(page.contains("robots"), "noindex like the approval page");
        assert!(!page.contains("http://cdn"), "no external resources");
        assert!(!page.contains("googleapis"), "no web fonts");
    }

    #[test]
    fn attach_page_is_localized() {
        let fr = attach_page(Lang::Fr, "s", 1, "h", NONCE);
        assert!(fr.contains("lang=\"fr\""));
        assert!(fr.contains("Ouvrir l'application Warren"));
        let ro = attach_page(Lang::Ro, "s", 1, "h", NONCE);
        assert!(ro.contains("lang=\"ro\""));
    }

    #[test]
    fn attach_page_redirects_to_the_topic_on_done() {
        let page = attach_page(Lang::En, "deadbeef", 42, "connect.warrenbrowse.com", NONCE);
        assert!(page.contains("location.replace('https://forum.warrenbrowse.com/t/42')"));
        assert!(page.contains("1500"), "brief success text before redirect");
    }

    #[test]
    fn attach_page_pre_deep_links_topic_zero_and_closes() {
        let page = attach_page_pre(Lang::En, "deadbeef", "connect.warrenbrowse.com", NONCE);
        assert!(
            page.contains(
                "warren://attach-logs?sid=deadbeef&topic=0&host=connect.warrenbrowse.com"
            )
        );
        assert!(page.contains("/v1/attach/deadbeef/status"));
        assert!(page.contains("s.status === 'received'"));
        assert!(page.contains("window.close()"));
        assert!(
            !page.contains("location.replace"),
            "the composer lives in the other tab: no redirect in pre mode"
        );
        assert!(page.contains("expires in 30 minutes"));
        assert!(page.contains("Return to the forum tab"));
        assert!(!page.contains("http://cdn"), "no external resources");
    }

    #[test]
    fn attach_page_pre_is_localized() {
        let fr = attach_page_pre(Lang::Fr, "s", "h", NONCE);
        assert!(fr.contains("lang=\"fr\""));
        assert!(fr.contains("l'onglet du forum"));
        let ro = attach_page_pre(Lang::Ro, "s", "h", NONCE);
        assert!(ro.contains("lang=\"ro\""));
    }

    #[test]
    fn transparency_page_is_localized() {
        assert!(transparency_page(Lang::En, NONCE).contains("How forum sign-in protects you"));
        assert!(transparency_page(Lang::Fr, NONCE).contains("transparence"));
        assert!(transparency_page(Lang::Ro, NONCE).contains("Discourse"));
    }

    #[test]
    fn transparency_page_states_no_cleartext_wallet_at_rest() {
        // `forum_links` lost its cleartext `pubkey_ss58` column, so a handle
        // can no longer be turned back into a wallet by anyone, ourselves
        // included. The page used to promise only that the reversing database
        // was access-controlled, which understates the guarantee and would go
        // stale in the wrong direction if the column ever came back.
        for (lang, stale) in [
            (Lang::En, "linkage database"),
            (Lang::Fr, "base de liaison"),
            (Lang::Ro, "baza de date privat"),
        ] {
            let page = transparency_page(lang, NONCE);
            assert!(
                !page.contains(stale),
                "no wallet is stored at rest: the page must not present a reversing database as the only barrier"
            );
            assert!(
                page.contains("HMAC"),
                "the page must name what is kept instead of the address"
            );
        }
        assert!(transparency_page(Lang::En, NONCE).contains("two years"));
        assert!(transparency_page(Lang::Fr, NONCE).contains("deux ans"));
        assert!(transparency_page(Lang::Ro, NONCE).contains("doi ani"));
    }
}
