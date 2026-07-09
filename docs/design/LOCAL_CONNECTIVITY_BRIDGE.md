# GhostMCP Local Connectivity Bridge — Design Document

**Date:** 2026-06-18
**Status:** PROPOSED
**Author:** OpenCode + William Rude
**Priority:** Medium

---

## 1. Problem Statement

GhostMCP runs in a Docker container or Azure Container Instance (ACI). When testing
local web applications (Vue, React, Angular SPAs, REST APIs, etc.), the `ghost_render`
and `ghost_fetch` tools cannot reach services listening on `localhost` because the
container has its own network namespace.

Current workarounds:
- `--network=host` (loses container isolation)
- `--add-host=host.docker.internal:host-gateway` (Linux Docker only, not ACI)
- Manual port forwarding (fragile, per-port configuration)

None of these work when GhostMCP is deployed to ACI and the web app runs on a
developer's laptop behind NAT/VPN.

## 2. Proposed Solution: Local Connectivity Bridge

A lightweight Python script (`ghost_client.py`) that runs on the developer's machine,
connects outbound to GhostMCP via WebSocket, and provides GhostMCP tools with
access to local services for webapp testing.

### Key Principles

1. **The developer initiates the connection** — outbound WebSocket from dev box to GhostMCP
2. **The developer registers available services** — explicitly declares which ports are testable
3. **No inbound ports required** — works through NAT, firewalls, VPNs, corporate proxies
4. **IDE-agnostic** — standalone script launchable by any MCP client (opencode, Cursor, VS Code, Claude Desktop)
5. **Same architecture as Unimind router** — proven pattern, portable across environments

### What It Is

A **local webapp testing bridge** that lets GhostMCP tools interact with services
running on the developer's machine.

### What It Is NOT

- Not a general-purpose proxy or tunnel
- Not a VPN replacement
- Not an ingress controller

## 3. Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Developer Machine                         │
│                                                             │
│  ┌──────────────┐     ┌──────────────────────────────────┐  │
│  │  Vue/React    │     │        ghost_client.py            │  │
│  │  Dev Server   │     │                                  │  │
│  │  :8080        │◄────│  1. Connects WS to GhostMCP      │  │
│  └──────────────┘     │  2. Receives test requests        │  │
│                        │  3. Fetches localhost locally     │  │
│  ┌──────────────┐     │  4. Returns response via WS       │  │
│  │  REST API     │     │                                  │  │
│  │  :3000        │◄────│  Registered ports: [8080, 3000]  │  │
│  └──────────────┘     └───────────────┬──────────────────┘  │
│                                       │                      │
│                                       │ Outbound WS          │
│                                       │ (ws://ghostmcp:8080) │
└───────────────────────────────────────┼──────────────────────┘
                                        │
                              ┌─────────▼─────────┐
                              │    GhostMCP        │
                              │    (Docker / ACI)  │
                              │                    │
                              │  ghost_render()    │
                              │  ghost_fetch()     │
                              │  ghost_cert()      │
                              │                    │
                              │  Detects bridge    │
                              │  connection,       │
                              │  routes requests   │
                              │  through it        │
                              └────────────────────┘
```

## 4. Connection Flow

```
1. Developer starts the bridge:
   $ python3 ghost_client.py --connect ws://10.0.10.7:8080/bridge --ports 8080,3000

2. Bridge connects to GhostMCP via WebSocket:
   → WS CONNECT ws://10.0.10.7:8080/bridge
   → Sends registration: {"type": "register", "ports": [8080, 3000], "client_id": "dev-laptop"}

3. GhostMCP acknowledges:
   ← {"type": "registered", "client_id": "dev-laptop", "ports": [8080, 3000]}

4. Agent calls ghost_render(url="http://localhost:8080"):
   → GhostMCP detects a bridge client has port 8080 registered
   → Sends request through bridge WS:
     {"type": "request", "id": "req-001", "method": "GET",
      "url": "http://localhost:8080", "headers": {...}}

5. Bridge receives request, fetches locally:
   → httpx.get("http://localhost:8080")
   → Returns response through WS:
     {"type": "response", "id": "req-001", "status": 200,
      "headers": {...}, "body": "<html>..."}

6. GhostMCP uses the response as if it fetched directly.
   For ghost_render: passes HTML to Playwright for JS execution.
```

## 5. Message Protocol

All messages are JSON over WebSocket text frames.

### Client → Server

| Type | Purpose | Payload |
|------|---------|---------|
| `register` | Declare available local ports | `{"type": "register", "ports": [8080, 3000], "client_id": "dev-laptop"}` |
| `response` | Return fetched content | `{"type": "response", "id": "req-001", "status": 200, "headers": {...}, "body": "..."}` |
| `error` | Report fetch failure | `{"type": "error", "id": "req-001", "error": "Connection refused"}` |
| `heartbeat` | Keep connection alive | `{"type": "heartbeat"}` |

### Server → Client

| Type | Purpose | Payload |
|------|---------|---------|
| `registered` | Acknowledge registration | `{"type": "registered", "client_id": "dev-laptop", "ports": [8080, 3000]}` |
| `request` | Ask bridge to fetch a URL | `{"type": "request", "id": "req-001", "method": "GET", "url": "http://localhost:8080/api/health", "headers": {...}, "body": null}` |
| `heartbeat_ack` | Respond to heartbeat | `{"type": "heartbeat_ack"}` |

## 6. GhostMCP Tool Integration

### URL Detection

When a GhostMCP tool receives a URL targeting `localhost`, `127.0.0.1`, or `0.0.0.0`:

```python
def _should_use_bridge(url: str) -> bool:
    """Check if this URL should be routed through the local connectivity bridge."""
    parsed = urlparse(url)
    return parsed.hostname in ("localhost", "127.0.0.1", "0.0.0.0", "host.docker.internal")
```

### Affected Tools

| Tool | Bridge Behavior |
|------|----------------|
| `ghost_fetch` | Route HTTP request through bridge, return response |
| `ghost_render` | Route initial page fetch through bridge, then render with Playwright |
| `ghost_cert` | Route TLS connection through bridge for cert inspection |
| `ghost_search` | Not affected (searches external engines) |
| `ghost_dork` | Not affected |
| `ghost_hash` | Not affected |
| `ghost_cve` | Not affected |
| `ghost_vuln` | Not affected |
| `ghost_threat` | Not affected |
| `ghost_subdomains` | Not affected |
| `ghost_recon` | Not affected |

### ghost_render Integration

For `ghost_render`, the bridge provides the initial HTML content, but Playwright
still needs to execute JavaScript. Two approaches:

**Option A: Bridge fetches, Playwright renders locally**
```
Bridge fetches localhost:8080 → returns HTML
GhostMCP passes HTML to Playwright as data: URL
Playwright renders, captures console/errors
```

**Option B: Playwright connects through bridge (complex)**
```
Bridge acts as HTTP proxy for Playwright's browser
Playwright navigates to the proxy which tunnels to localhost
Full JS execution with real network context
```

Option A is simpler and covers 90% of SPA debugging use cases (Vue mount errors,
React hydration failures, console.error capture). Option B would be needed for
apps that make additional API calls during rendering.

**Recommendation:** Start with Option A. Add Option B later if needed.

## 7. Bridge Script Design

### CLI Interface

```bash
# Connect to local GhostMCP container
python3 ghost_client.py --connect ws://localhost:8080/bridge --ports 8080,3000

# Connect to ACI-deployed GhostMCP
python3 ghost_client.py --connect ws://10.0.10.7:8080/bridge --ports 8080,3000,5173

# With auto-discovery (scan for listening ports)
python3 ghost_client.py --connect ws://10.0.10.7:8080/bridge --auto-discover

# With authentication
python3 ghost_client.py --connect ws://10.0.10.7:8080/bridge --ports 8080 --token <jwt>
```

### MCP Client Configuration (opencode.json)

```json
{
  "plugin": [
    "/path/to/ghost_client_plugin.ts"
  ]
}
```

Or as a standalone process launched alongside GhostMCP:

```json
{
  "mcp": {
    "ghostmcp": {
      "type": "remote",
      "url": "http://10.0.10.7:8080/sse",
      "enabled": true
    }
  }
}
```

Bridge runs independently — not part of the MCP config. It's a sidecar process.

### Reconnection

- Auto-reconnect with exponential backoff (5s, 10s, 20s, 30s max)
- Re-register ports on reconnect
- Same pattern as Unimind router

### Security Considerations

- Bridge only serves ports explicitly registered by the developer
- Requests from GhostMCP are validated against the registered port list
- No wildcard port access — must opt-in per port
- WS connection is unauthenticated for now (ws://)
- Future: WSS with JWT token for authenticated bridges

## 8. Implementation Plan

### Phase 1: Basic Bridge (MVP)

| Component | File | Lines (est.) | Description |
|-----------|------|-------------|-------------|
| Bridge client | `ghost_client.py` | ~150 | WebSocket client, port registration, HTTP fetch, response relay |
| Bridge server endpoint | `ghostmcp/mcp.py` | ~80 | `/bridge` WebSocket route, client registry, request routing |
| Tool integration | `ghostmcp/mcp.py` | ~50 | `_should_use_bridge()` check in `ghost_fetch` and `ghost_render` |
| **Total** | | **~280 lines** | |

### Phase 2: Enhanced (Future)

| Feature | Description |
|---------|-------------|
| WSS transport | TLS-encrypted bridge connections |
| JWT authentication | Authenticate bridge clients |
| Auto-discovery | Scan for listening ports on the dev machine |
| Playwright proxy mode | Full browser-through-bridge for complex SPAs |
| Multiple bridges | Support multiple developers connecting simultaneously |
| Port health monitoring | Bridge periodically checks if registered ports are still alive |

## 9. Decisions

| # | Decision | Rationale |
|---|----------|-----------|
| D1 | Standalone script, not opencode plugin | Portable across IDEs. Any MCP client can launch it. |
| D2 | WS for now, WSS later | Simplicity first. Security adds complexity. VNet provides network-level isolation. |
| D3 | Explicit port registration, not wildcard | Developer must opt-in per port. Prevents unintended exposure. |
| D4 | Option A (bridge fetch + Playwright render) first | Covers 90% of SPA debugging. Option B (proxy mode) is complex and can wait. |
| D5 | JSON text frames, not binary | Simple, debuggable, no framing overhead for HTTP request/response payloads. |
| D6 | Same reconnect pattern as Unimind router | Proven architecture, exponential backoff, re-registration on reconnect. |
| D7 | Bridge is a sidecar, not embedded in MCP config | Decoupled lifecycle. Can run without MCP client. Can connect from any machine. |

## 10. Implications

### Positive

- **SPA debugging without DevTools** — `ghost_render` can capture console errors from locally-running Vue/React apps
- **API testing against local services** — `ghost_fetch` can hit local REST APIs
- **Works from anywhere** — dev laptop behind NAT can test against ACI-deployed GhostMCP
- **IDE-agnostic** — same script works with opencode, Cursor, VS Code, Claude Desktop
- **No Docker networking hacks** — no `--network=host`, no `host.docker.internal`

### Risks

- **Security** — unauthenticated bridge in Phase 1. Mitigated by VNet isolation + explicit port registration.
- **Latency** — additional hop through WebSocket adds ~5-10ms per request. Acceptable for testing.
- **Complexity** — new component to maintain. Mitigated by keeping it under 300 lines.
- **Scope creep** — could evolve into a general-purpose tunnel. Must stay focused on webapp testing.

### What This Enables (Future)

- CI/CD integration — run GhostMCP tests against staging environments via bridge
- Multi-developer testing — multiple bridges connected to one GhostMCP instance
- Remote pair debugging — "connect your bridge so I can render your localhost"
- Integration with the DMN — DMN could proactively test local services during meditation cycles

---

## 11. Related Documents

| Document | Location |
|----------|----------|
| Reverse tickle tunnel (backlog) | `docs/status/PROJECT_STATUS.md` |
| GhostMCP feature request (ghost_render) | `FEATURE_REQUESTS.md` |
| Unimind router (reference architecture) | `Skill_Multiagent/unimind/clients/common/router.py` |
| DMN deployment options (mempalace) | MemPalace drawer `dmn-deployment` |

---

*Design developed during session 2026-06-17/18. Implementation pending.*
