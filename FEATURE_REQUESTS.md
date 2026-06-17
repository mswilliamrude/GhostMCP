
## Feature Request: `ghost_render` — Headless Browser Rendering + JS Console Capture

### Problem
When developing SPAs (Single Page Applications) with frameworks like Vue, React, or Angular, the raw HTML contains template directives (`v-if`, `v-for`, `{{}}`) that only resolve after JavaScript executes. Current `ghost_fetch` returns the raw HTML, which is useless for diagnosing:

- Whether the JS framework successfully mounted
- Runtime JavaScript errors (ReferenceError, TypeError, etc.)
- Which Vue/React components rendered vs failed
- Console errors/warnings from the application
- The actual DOM state after client-side rendering

This makes it impossible for an AI coding agent to debug frontend issues without the user manually opening browser DevTools and reporting back.

### Proposed Solution

#### `ghost_render` tool
```
Parameters:
  url: string          — URL to load
  wait: int            — milliseconds to wait for JS execution (default 5000)
  execute: string      — optional JS to run after page loads
  extract: string      — "dom" (rendered HTML), "console" (console output), "both"
  screenshot: bool     — return a screenshot of the rendered page

Returns:
  rendered_html: string  — the DOM after JS execution (what the user actually sees)
  console_log: string[]  — all console.log/warn/error output
  js_errors: string[]    — uncaught errors, unhandled promise rejections
  title: string          — document.title after render
  screenshot: bytes      — optional PNG screenshot
```

#### Implementation
Use Playwright or Puppeteer (headless Chromium) behind the paranoia proxy chain:
- `casual`: direct headless Chrome
- `cautious`: headless + random user-agent
- `ghost`/`midnight`: headless through proxy/Tor

#### Use Cases

1. **SPA Debugging**: Fetch a Vue/React page, get the rendered DOM instead of template syntax. Immediately see if the framework mounted successfully.

2. **JS Error Detection**: The #1 reason Vue/React fails silently is a JavaScript error during setup. `ghost_render` captures `console.error` and `window.onerror` — the AI agent can read the exact error message and stack trace without the user needing DevTools.

3. **Visual Regression**: Screenshots let the agent compare what the page looks like before/after a change.

4. **Form Interaction Testing**: `execute` parameter allows filling forms, clicking buttons, and checking the result — basic E2E testing without Selenium/Cypress setup.

5. **CSP/CORS Detection**: Some pages block JS execution via Content Security Policy. `ghost_render` would surface these as errors in `js_errors`.

### Real-World Example
We're building a ZCS-replacement webmail with Vue 3 (no build step, CDN). After 20+ agent edits, the 3800-line app.js has an invisible bug that prevents Vue from mounting. `ghost_fetch` returns raw `{{ }}` templates. With `ghost_render`, we'd get either:
- The rendered page (Vue mounted successfully), OR
- The exact console error: "Uncaught ReferenceError: xxx is not defined at app.js:1234"

That single piece of information would save hours of debugging.

### Priority: HIGH
This is the single biggest gap in the AI-assisted frontend development workflow. Every other tool works great for backend/API work. Frontend debugging is flying blind without it.

---
Filed by: OpenCode agent during NewHotness webmail development session
Date: 2026-06-17
