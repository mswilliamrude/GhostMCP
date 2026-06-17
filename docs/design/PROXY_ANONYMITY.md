# GhostMCP — Proxy & Anonymity Design

**Version:** 0.1
**Date:** 2026-06-16

---

## 1. Threat Model

### What We're Hiding From

| Observer | What They See | Risk | Mitigation |
|----------|-------------|------|------------|
| Search engine | IP, UA, query, timing | Query correlation, rate limiting | Proxy rotation, fingerprint rotation |
| Network observer (ISP) | Destination IPs, DNS queries | Traffic analysis | Tor, encrypted DNS |
| Target website | Referrer, IP, crawl pattern | Source identification | Proxy, no direct fetching |
| Proxy operator | Our traffic content | MITM on HTTP | HTTPS only, Tor (onion routing) |

### What We're NOT Hiding From

| Observer | Acceptable Exposure | Why |
|----------|-------------------|-----|
| Local machine | Full query history | Our machine, our data |
| Unimind | Queries + results | We asked it to search |

---

## 2. Tor Architecture

### 2.1 Setup

```
GhostMCP → SOCKS5 → Tor (localhost:9050) → Exit Node → Target
                      │
                      └── Control Port (localhost:9051)
                           └── NEWNYM signal = new circuit
```

### 2.2 Installation

```bash
# RHEL/CentOS
sudo dnf install tor
sudo systemctl enable tor
sudo systemctl start tor

# Or via Docker
docker run -d --name ghost-tor \
    -p 9050:9050 \
    -p 9051:9051 \
    -e TOR_HashedControlPassword=$(tor --hash-password ghostmcp) \
    dperson/torproxy
```

### 2.3 Circuit Rotation

```python
import stem
from stem import Signal
from stem.control import Controller

class TorController:
    def __init__(self, control_port=9051, password="ghostmcp"):
        self.port = control_port
        self.password = password
    
    async def new_circuit(self):
        """Request a new Tor circuit (new exit IP)."""
        with Controller.from_port(port=self.port) as ctrl:
            ctrl.authenticate(password=self.password)
            ctrl.signal(Signal.NEWNYM)
        # Wait for circuit to be established
        await asyncio.sleep(3)
    
    async def get_exit_ip(self) -> str:
        """Check what exit IP we're currently using."""
        async with aiohttp.ClientSession() as session:
            proxy = "socks5://localhost:9050"
            async with session.get("https://check.torproject.org/api/ip",
                                   proxy=proxy) as resp:
                data = await resp.json()
                return data["IP"]
```

### 2.4 Circuit Rotation Strategies

| Strategy | When to Rotate | Anonymity | Speed |
|----------|---------------|-----------|-------|
| `per_request` | Every single search request | Maximum | Slowest (3s per rotation) |
| `per_engine` | When switching search engines | High | Moderate |
| `timed` | Every N seconds | Moderate | Fast |
| `on_block` | When CAPTCHA/block detected | Reactive | Fastest until blocked |
| `per_session` | Once at start | Lowest | Fastest |

---

## 3. Proxy Pool Architecture

### 3.1 Configuration

```yaml
# config/proxies.yml
tor:
  socks5: "socks5://localhost:9050"
  control_port: 9051
  control_password: "ghostmcp"
  enabled: true

socks5_pool:
  - "socks5://proxy1.example.com:1080"
  - "socks5://proxy2.example.com:1080"
  enabled: false

http_pool:
  - "http://proxy3.example.com:8080"
  enabled: false

residential:
  provider: "none"  # brightdata, oxylabs, etc.
  endpoint: ""
  api_key: ""
  enabled: false

direct:
  enabled: true  # Always available as fallback
```

### 3.2 Proxy Selection

```python
class ProxySelector:
    strategies = {
        "round_robin": lambda pool: pool[next_index % len(pool)],
        "random": lambda pool: random.choice(pool),
        "least_used": lambda pool: min(pool, key=lambda p: p.use_count),
        "fastest": lambda pool: min(pool, key=lambda p: p.avg_latency),
        "geo": lambda pool, country: [p for p in pool if p.country == country][0],
    }
```

### 3.3 Health Checking

```python
class ProxyHealthChecker:
    CHECK_URL = "https://httpbin.org/ip"
    CHECK_INTERVAL = 300  # seconds
    
    async def check(self, proxy: Proxy) -> ProxyHealth:
        try:
            start = time.monotonic()
            async with session.get(self.CHECK_URL, proxy=proxy.url, timeout=10) as resp:
                latency = time.monotonic() - start
                data = await resp.json()
                return ProxyHealth(
                    alive=True,
                    latency=latency,
                    exit_ip=data["origin"],
                    checked_at=datetime.utcnow(),
                )
        except:
            return ProxyHealth(alive=False)
```

---

## 4. Browser Fingerprinting

### 4.1 User-Agent Database

Real browser User-Agents from current browser versions (updated monthly):

```python
UA_DATABASE = {
    "chrome_windows": [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36",
    ],
    "chrome_mac": [
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36",
    ],
    "firefox_windows": [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:138.0) Gecko/20100101 Firefox/138.0",
    ],
    "firefox_linux": [
        "Mozilla/5.0 (X11; Linux x86_64; rv:138.0) Gecko/20100101 Firefox/138.0",
    ],
    "safari_mac": [
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.4 Safari/605.1.15",
    ],
    "edge_windows": [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36 Edg/137.0.0.0",
    ],
}
```

### 4.2 Consistent Fingerprint Generation

A fingerprint must be internally consistent — Chrome UA with Firefox headers is a dead giveaway:

```python
class Fingerprint:
    def __init__(self, browser_family: str = None):
        family = browser_family or random.choice(["chrome", "firefox", "safari", "edge"])
        platform = random.choice(PLATFORMS[family])
        
        self.user_agent = random.choice(UA_DATABASE[f"{family}_{platform}"])
        self.accept = ACCEPT_HEADERS[family]
        self.accept_language = random_language()
        self.accept_encoding = "gzip, deflate, br"
        
        # Chrome-specific headers
        if family in ("chrome", "edge"):
            self.sec_ch_ua = generate_ch_ua(family, self.user_agent)
            self.sec_ch_ua_mobile = "?0"
            self.sec_ch_ua_platform = f'"{PLATFORM_NAMES[platform]}"'
            self.sec_fetch_site = "none"
            self.sec_fetch_mode = "navigate"
            self.sec_fetch_user = "?1"
            self.sec_fetch_dest = "document"
        
        self.dnt = random.choice(["1", None])
        self.upgrade_insecure_requests = "1"
        
        # Header order must match browser
        self.header_order = HEADER_ORDER[family]
    
    def to_headers(self) -> dict:
        """Return headers in browser-correct order."""
        headers = OrderedDict()
        for key in self.header_order:
            val = getattr(self, key.replace("-", "_").lower(), None)
            if val is not None:
                headers[key] = val
        return headers
```

---

## 5. Request Pipeline

### 5.1 Full Request Flow

```
User query: "stalwart v0.16 credentials"
    │
    ├─→ [1] Engine Router: selects DuckDuckGo
    │
    ├─→ [2] Query Builder: "stalwart v0.16 credentials"
    │         (no dorking needed, pass through)
    │
    ├─→ [3] Timing Controller: wait 1.7s (cautious jitter)
    │
    ├─→ [4] Fingerprint Manager: generate Chrome/Windows fingerprint
    │
    ├─→ [5] Proxy Manager: select Tor circuit
    │
    ├─→ [6] HTTP Request:
    │         URL: https://html.duckduckgo.com/html/?q=stalwart+v0.16+credentials
    │         Headers: [fingerprint headers in Chrome order]
    │         Proxy: socks5://localhost:9050
    │
    ├─→ [7] Response Handler:
    │         ├── 200 OK → parse results
    │         ├── 403/429 → CAPTCHA/rate limit → rotate proxy, retry
    │         └── 5xx → engine down → try next engine
    │
    ├─→ [8] HTML Parser: extract title, URL, snippet from SERP
    │
    └─→ [9] Result: list[SearchResult]
```

---

## 6. DNS Considerations

### 6.1 DNS Leak Prevention

When using Tor, DNS must also go through Tor. With SOCKS5 proxies, DNS can leak:

```python
# BAD: DNS resolved locally, only HTTP through proxy
# This leaks what domains you're searching
aiohttp.ClientSession(connector=ProxyConnector.from_url(proxy))

# GOOD: DNS resolved through proxy (SOCKS5 remote DNS)
connector = ProxyConnector.from_url(proxy, rdns=True)  # rdns=True = remote DNS
aiohttp.ClientSession(connector=connector)
```

### 6.2 Encrypted DNS Fallback

For non-Tor proxy usage:

```python
# DNS-over-HTTPS for local resolution
DOH_SERVERS = [
    "https://cloudflare-dns.com/dns-query",
    "https://dns.google/dns-query",
    "https://dns.quad9.net/dns-query",
]
```
