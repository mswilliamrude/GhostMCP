# Feature Request: Distributed Bridge Network — Config File, Web Access, and Locality-Aware Search

**Date:** 2026-06-18
**Status:** PROPOSED
**Priority:** HIGH — enables GhostMCP to function in private VNets without internet egress

---

## 1. Problem Statement

GhostMCP deployed in a private Azure VNet has no internet egress. Search tools
(`ghost_search`, `ghost_dork`, `ghost_fetch`) cannot reach the internet directly.
Additionally, when multiple developers connect, there's an opportunity to distribute
search traffic across their connections for organic IP rotation without expensive
proxy subscriptions.

## 2. Proposed Features

### 2.1 Configuration File with File Watcher

Replace CLI `--ports` with a YAML config file that the bridge monitors for changes.
Developers can add/remove ports without restarting the bridge or exiting their IDE.

```yaml
# ~/.ghost_bridge.yaml
server: ws://10.0.10.7:8080/bridge
client_id: will-laptop

# Local services available for testing
ports:
  - 8080    # Vue dev server
  - 3000    # REST API
  - 5173    # Vite HMR

# Provide internet connectivity to GhostMCP
allow_web_access: true

# Who can use my internet connection for searches?
# Options: false | self_only | shared
#   false     — localhost ports only, no web access
#   self_only — only MY requests route through MY connection
#   shared    — add me to the round-robin pool for all GhostMCP searches
web_access_mode: self_only

# Locality info — helps GhostMCP understand geographic bias in search results
locality:
  region: US-TX           # ISO 3166-2 region code
  timezone: US/Central    # IANA timezone
  label: "Austin office"  # Human-readable description
```

**File watcher behavior:**
- Bridge checks config file mtime every 3 seconds
- On change: re-read config, diff ports, send updated registration to GhostMCP
- New ports added → register immediately
- Ports removed → unregister immediately
- `allow_web_access` or `web_access_mode` changed → re-register with new capabilities
- No bridge restart required

### 2.2 Web Access Routing (Private VNet Connectivity)

When GhostMCP has no internet egress, bridges provide the network path:

```
ghost_search("Python asyncio tutorial")
    ↓
GhostMCP (private VNet, no egress)
    ↓ routes through bridge WebSocket
Bridge client (will-laptop, Austin TX)
    ↓ fetches from will's internet connection
DuckDuckGo / Google / Serper
    ↓ returns results
Bridge → GhostMCP → Agent
```

**Three web access modes:**

| Mode | Who uses this bridge for web requests? |
|------|---------------------------------------|
| `false` | Nobody — localhost port forwarding only |
| `self_only` | Only requests initiated by THIS developer's agent session |
| `shared` | Any agent session — bridge is added to the round-robin pool |

### 2.3 Distributed Search Pool (Round-Robin IP Rotation)

When multiple developers set `web_access_mode: shared`, GhostMCP maintains a pool
of available exit points and distributes search traffic across them:

```
20 developers connected to GhostMCP
├── 5 with allow_web_access: false     → localhost only
├── 8 with web_access_mode: self_only  → their own searches only
└── 7 with web_access_mode: shared     → round-robin pool

Search request from any agent:
  1. Check: does requesting client have self_only bridge? → use it
  2. No? Pick from shared pool (round-robin)
  3. No shared bridges? Use GhostMCP direct (if egress exists)
  4. No egress? Return error
```

**Benefits:**
- Organic IP rotation — each developer's IP is different
- No proxy subscription costs
- Distributed rate limiting — DDG sees 7 different IPs instead of 1
- Voluntary — developers explicitly opt in per mode

### 2.4 Locality-Aware Search Results

Search engines return geographically biased results. GhostMCP tracks each bridge's
locality to:

1. **Tag results with provenance** — every search result includes which bridge
   (and therefore which geographic location) produced it
2. **Maintain geographic consistency** — multi-step research tasks route through
   the same bridge so results are geographically coherent
3. **Enable multi-geo research** — OSINT tasks can intentionally query through
   different regions to compare results
4. **Detect anomalies** — flag when identical queries return significantly different
   results through different bridges

**Result tagging example:**
```
[duckduckgo via will-laptop (US-TX)] Python asyncio tutorial
  1. Real Python — Async IO in Python...
  2. docs.python.org — asyncio...

[duckduckgo via mike-laptop (US-WA)] Python asyncio tutorial
  1. docs.python.org — asyncio...       ← different ordering
  2. Real Python — Async IO in Python...
```

**Locality data flow:**
```
Bridge registers:
  {"type": "register", "client_id": "will-laptop", "ports": [8080],
   "allow_web_access": true, "web_access_mode": "shared",
   "locality": {"region": "US-TX", "timezone": "US/Central", "label": "Austin office"}}

GhostMCP stores in bridge registry:
  _bridge_clients["will-laptop"] = {
      "ws": <websocket>,
      "ports": [8080],
      "web_access": True,
      "web_mode": "shared",
      "locality": {"region": "US-TX", ...}
  }

Search results tagged:
  SearchResult(title="...", url="...", source_engine="duckduckgo",
               bridge_client="will-laptop", bridge_locality="US-TX")
```

## 3. Architecture

### Bridge Client (ghost_bridge.py)

```
┌──────────────────────────────────────────────┐
│              ghost_bridge.py                  │
│                                              │
│  ┌────────────────┐  ┌───────────────────┐  │
│  │  Config Watcher │  │  WebSocket Client │  │
│  │                 │  │                   │  │
│  │  Polls ~/.ghost │  │  Maintains WS to  │  │
│  │  _bridge.yaml   │  │  GhostMCP server  │  │
│  │  every 3s       │  │                   │  │
│  │                 │  │  Sends register/  │  │
│  │  On change:     │  │  re-register on   │  │
│  │  → diff ports   │──│  config change    │  │
│  │  → re-register  │  │                   │  │
│  └────────────────┘  └────────┬──────────┘  │
│                               │              │
│  ┌────────────────────────────▼──────────┐  │
│  │         Request Handler               │  │
│  │                                       │  │
│  │  Receives: {"type": "request", ...}   │  │
│  │                                       │  │
│  │  localhost request?                   │  │
│  │    → httpx.get(localhost:PORT)         │  │
│  │                                       │  │
│  │  web request (allow_web_access)?      │  │
│  │    → httpx.get(external_url)          │  │
│  │                                       │  │
│  │  Returns: {"type": "response", ...}   │  │
│  └───────────────────────────────────────┘  │
└──────────────────────────────────────────────┘
```

### GhostMCP Server (src/mcp.py)

```
┌──────────────────────────────────────────────┐
│              GhostMCP Server                  │
│                                              │
│  ┌───────────────────────────────────────┐   │
│  │         Bridge Registry               │   │
│  │                                       │   │
│  │  _bridge_clients = {                  │   │
│  │    "will-laptop": {                   │   │
│  │      ws, ports, web_access, mode,     │   │
│  │      locality: {region, tz, label}    │   │
│  │    },                                 │   │
│  │    "mike-laptop": { ... },            │   │
│  │  }                                    │   │
│  │                                       │   │
│  │  _shared_pool = ["will", "mike", ...] │   │
│  │  _pool_index = 0  (round-robin)       │   │
│  └──────────────────┬────────────────────┘   │
│                     │                         │
│  ┌──────────────────▼────────────────────┐   │
│  │         Request Router                │   │
│  │                                       │   │
│  │  ghost_search(query) called:          │   │
│  │    1. Has requester got self_only?     │   │
│  │       → route through their bridge    │   │
│  │    2. Shared pool available?           │   │
│  │       → round-robin pick              │   │
│  │    3. Direct egress?                   │   │
│  │       → use GhostMCP's own connection │   │
│  │    4. None? → error                   │   │
│  │                                       │   │
│  │  Tag results with bridge provenance   │   │
│  └───────────────────────────────────────┘   │
└──────────────────────────────────────────────┘
```

## 4. Implementation Plan

### Phase 1: Config File + File Watcher (~80 lines)

| Component | Change |
|-----------|--------|
| `ghost_bridge.py` | Add YAML config loading, `stat()` poll loop, re-registration on change |
| `ghost_bridge.py` | Support `--config` flag (default `~/.ghost_bridge.yaml`) |
| `ghost_bridge.py` | Keep `--ports` and `--connect` as CLI overrides for quick use |

### Phase 2: Web Access Routing (~60 lines)

| Component | Change |
|-----------|--------|
| `ghost_bridge.py` | Handle web requests (non-localhost) when `allow_web_access: true` |
| `ghost_bridge.py` | Send `allow_web_access` and `web_access_mode` in registration |
| `src/mcp.py` | Store web access capability in bridge registry |
| `src/mcp.py` | Route search engine HTTP calls through bridge when no egress |

### Phase 3: Distributed Pool + Round-Robin (~50 lines)

| Component | Change |
|-----------|--------|
| `src/mcp.py` | Maintain `_shared_pool` list of bridges with `mode: shared` |
| `src/mcp.py` | Round-robin selection for search requests |
| `src/mcp.py` | `self_only` routing for per-client requests |
| `src/mcp.py` | Fallback chain: self_only → shared pool → direct → error |

### Phase 4: Locality Tracking + Result Tagging (~40 lines)

| Component | Change |
|-----------|--------|
| `ghost_bridge.py` | Send `locality` block in registration |
| `src/mcp.py` | Store locality in bridge registry |
| `src/mcp.py` | Tag `SearchResult` with `bridge_client` and `bridge_locality` |
| `src/mcp.py` | Prefer same-bridge for multi-step research (session affinity) |

### Total Estimate: ~230 lines across 2 files

## 5. Security Considerations

| Risk | Mitigation |
|------|-----------|
| Developer's IP exposed to search engines | Explicit opt-in via `allow_web_access: true` — off by default |
| Search traffic visible on developer's network | Developer chooses their risk level with `web_access_mode` |
| Shared pool member sees other users' queries | Bridge only sees HTTP requests, not who initiated them. But the bridge operator could log URLs. Mitigated by trust model (internal team). |
| Config file contains server URL | File permissions should be 600 (owner-only) |
| Malicious bridge returns fake search results | Result provenance tagging lets agents see which bridge produced results. Cross-bridge validation possible for critical queries. |

## 6. Decisions

| # | Decision | Rationale |
|---|----------|-----------|
| D1 | Config file over auto-discover | Explicit > implicit. Developer controls exactly what's exposed. |
| D2 | File watcher via mtime poll (3s) | No `watchdog` dependency. Simple, cross-platform. |
| D3 | `allow_web_access` off by default | Security first. Must opt-in to route web traffic. |
| D4 | `self_only` as default web mode | Even when enabled, searches only route through YOUR bridge by default. |
| D5 | Round-robin not weighted | Simple first. Could add latency-weighted or bandwidth-weighted later. |
| D6 | Locality is self-reported | Developer provides their own region info. No IP geolocation lookup. |
| D7 | YAML config format | Human-readable, editable, same as other project configs. |

## 7. Future Enhancements

| Feature | Description |
|---------|-------------|
| Latency-weighted pool | Prefer bridges with lower latency for time-sensitive searches |
| Bandwidth tracking | Track throughput per bridge, avoid overloading slow connections |
| Geographic targeting | `ghost_search(query, region="US-TX")` → route through Texas bridge |
| Multi-geo comparison | Automatically run same query through N bridges, compare results |
| Bridge health monitoring | Detect and remove unresponsive bridges from pool |
| Encrypted config | Support age/sops-encrypted config for sensitive server URLs |
| Auto-discover mode | Scan for listening ports (optional, off by default) |

---

*Design developed during session 2026-06-18. Builds on the Local Connectivity Bridge
(docs/design/LOCAL_CONNECTIVITY_BRIDGE.md) which provides the foundation.*
