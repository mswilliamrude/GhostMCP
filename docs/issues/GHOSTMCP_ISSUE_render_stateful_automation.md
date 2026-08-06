# GhostMCP Issue: ghost_render Cannot Do Stateful / Multi-Step Browser Automation

## Title
`ghost_render` is stateless and has no file-upload primitive — blocks authenticated multi-step flows (login → act → submit) and any `<input type=file>` interaction

## Labels
enhancement, render, browser-automation

## Body

### Problem

`ghost_render` is designed for **rendering and reconnaissance** — load a page, run
JavaScript, capture the DOM/console/screenshot. It works well for that. But it
**cannot drive a stateful, multi-step browser workflow**, and it has **no way to
attach a file to an upload input**. These two gaps together make it unusable for
"log in and do something that produces a side effect" tasks (e.g. sign into a
webmail UI and send a message with an attachment).

### Root Cause (verified in `src/recon/render.py`)

1. **Stateless per call — no session persistence.**
   `render_page()` creates a fresh `browser.new_context()` (render.py:133) and
   ends with `await browser.close()` (render.py:188) on *every* invocation. There
   is no `storage_state` save/restore and no `context.add_cookies(...)`. So any
   cookies, CSRF token, or authenticated session established in one `ghost_render`
   call is **gone by the next call**. Multi-step flows that require the same
   browser session across calls (login → navigate → submit) are impossible.

2. **`execute` is `page.evaluate(js_string)` only — no automation API.**
   The `execute_js` parameter is passed straight to `page.evaluate(...)`
   (render.py:174). That runs a JS string in the page's own context. It does
   **not** expose Playwright's automation surface — notably
   `page.set_input_files(...)`, `page.fill(...)`, `page.click(...)` with
   auto-waiting, or `page.wait_for_navigation(...)`.

3. **No file-upload primitive (the hard wall).**
   Attaching a file to an `<input type=file>` cannot be done from in-page JS:
   browsers **forbid** setting `input.value` or constructing/injecting a `File`
   into a file input for security reasons. The only ways are a real OS file
   picker or Playwright's `page.set_input_files()` — neither of which
   `ghost_render` exposes. So `ghost_render` can *type* an email body but can
   **never attach a file**.

### Observed Behavior

During a session driving a Zimbra Collaboration Suite webmail login
(`https://<host>/`, classic UI):

- `ghost_render(url=..., screenshot=True)` correctly rendered the login form,
  including the hidden `login_csrf` token and the `username`/`password` fields —
  **rendering/recon works fine**.
- The task then required: (a) POST the login form, (b) in the *same* session open
  Compose, (c) attach a 15 KB file via the upload input, (d) click Send.
  - (a) could be attempted in one call, but (b)–(d) need the **same
    authenticated session**, which does not survive to the next `ghost_render`
    call (fresh context each time).
  - (c) is impossible regardless — no `set_input_files` / file-input path exists.

Net: the browser tool can *see* the webmail but cannot *operate* it to completion.

### Impact

- Cannot automate authenticated webmail/app actions (send mail, upload to a
  briefcase/drive, submit a form behind login) via the real UI.
- Any workflow needing session continuity across steps must be worked around with
  a different transport (authenticated REST/SOAP, server-side CLI), which is a
  *different* code path than "drive the actual web UI" and does not exercise the
  UI.

### Proposed Fix (options, in rough order of effort)

1. **Session persistence via `storage_state`.**
   Add optional `session_id` / `storage_state_path` params. After a call, save
   `await context.storage_state(path=...)`; on the next call with the same id,
   restore it in `new_context(storage_state=...)`. This makes login persist
   across `ghost_render` calls without changing the stateless-by-default posture.

2. **Structured action list instead of (or alongside) a raw JS string.**
   Accept an ordered list of high-level actions — `goto`, `fill`, `click`,
   `set_input_files`, `wait_for_navigation`, `screenshot` — executed in one call
   against one page/context. This exposes Playwright's real automation API
   (including file upload) safely, without requiring the caller to hand-roll
   fragile in-page JS.

3. **Explicit `upload_files` param.**
   Map `{selector: local_path}` to `page.set_input_files(selector, path)` within
   a call. Requires the target file to be reachable by the render container's
   filesystem (document this; pair with the existing file-cache/push mechanism if
   the file lives on a remote client).

4. **A dedicated stateful `ghost_browser` / session-scoped tool.**
   A longer-lived, session-scoped browser tool (create session → act → act →
   destroy) is the clean home for genuine multi-step automation, keeping
   `ghost_render` a simple stateless render/recon primitive.

### Notes / Design Tension

Keeping `ghost_render` stateless and JS-only is a legitimate **safety/simplicity**
choice for a recon tool. This issue is not arguing to break that default — it is
asking for an *opt-in* path (persisted session + a file-upload/action primitive)
so authenticated, multi-step, upload-bearing workflows become possible for the
callers that need them.
