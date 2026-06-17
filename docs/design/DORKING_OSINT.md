# GhostMCP — Dorking & OSINT Design

**Version:** 0.1
**Date:** 2026-06-16

---

## 1. Dorking Engine

### 1.1 Operator Compatibility Matrix

| Operator | Google | DuckDuckGo | Bing | Serper API |
|----------|--------|------------|------|------------|
| `site:` | Yes | Yes | Yes | Yes |
| `filetype:` | Yes | Yes | Yes | Yes |
| `inurl:` | Yes | Partial | Yes | Yes |
| `intitle:` | Yes | Yes | Yes | Yes |
| `intext:` | Yes | No | Yes | Yes |
| `ext:` | Yes | No | No | Yes |
| `""` (exact) | Yes | Yes | Yes | Yes |
| `-` (exclude) | Yes | Yes | Yes | Yes |
| `OR` | Yes | Yes | Yes | Yes |
| `*` (wildcard) | Yes | No | Yes | Yes |
| `AROUND(N)` | Yes | No | No | Yes |
| `before:` | Yes | No | No | Yes |
| `after:` | Yes | No | No | Yes |
| `cache:` | Yes | No | No | Partial |
| `related:` | Yes | No | No | Yes |

### 1.2 Automatic Engine Selection for Dorks

```python
def select_engine_for_dork(query: str) -> str:
    """Select the best engine based on operators used."""
    operators = extract_operators(query)
    
    # If using Google-only operators, must use Google or Serper
    google_only = {"intext:", "ext:", "AROUND(", "before:", "after:", "cache:", "related:"}
    if operators & google_only:
        return "google" if paranoia >= "ghost" else "serper"
    
    # DDG handles basic dorking fine
    if operators <= {"site:", "filetype:", "intitle:", '""', "-", "OR"}:
        return "duckduckgo"
    
    return "google"
```

---

## 2. OSINT Modules

### 2.1 Subdomain Enumeration

Sources (all passive — no active scanning):

| Source | Method | API Key |
|--------|--------|---------|
| Certificate Transparency | crt.sh API | No |
| DNS Dumpster | HTML scrape | No |
| VirusTotal | API | Yes (free) |
| SecurityTrails | API | Yes (free tier) |
| Google dorking | `site:*.domain.com` | No |
| Bing dorking | `site:*.domain.com` | No |

```python
class SubdomainEnumerator:
    async def enumerate(self, domain: str) -> set[str]:
        results = set()
        
        # Certificate Transparency (crt.sh)
        async with session.get(f"https://crt.sh/?q=%.{domain}&output=json") as resp:
            certs = await resp.json()
            for cert in certs:
                names = cert.get("name_value", "").split("\n")
                results.update(n.strip() for n in names if n.strip().endswith(domain))
        
        # Google dork
        dork_results = await ghost.dork(f"site:*.{domain} -site:www.{domain}")
        for r in dork_results:
            hostname = urlparse(r.url).hostname
            if hostname and hostname.endswith(domain):
                results.add(hostname)
        
        return results
```

### 2.2 Certificate Transparency

```python
class CertTransparency:
    async def search(self, domain: str) -> list[CertInfo]:
        """Search certificate transparency logs for a domain."""
        async with session.get(
            f"https://crt.sh/?q=%.{domain}&output=json"
        ) as resp:
            certs = await resp.json()
            return [
                CertInfo(
                    issuer=c["issuer_name"],
                    common_name=c["common_name"],
                    name_value=c["name_value"],
                    not_before=c["not_before"],
                    not_after=c["not_after"],
                    serial=c["serial_number"],
                )
                for c in certs
            ]
```

### 2.3 Technology Fingerprinting

Passive tech detection from HTTP response headers:

```python
TECH_SIGNATURES = {
    "headers": {
        "X-Powered-By": {"PHP": "php", "Express": "express", "ASP.NET": "aspnet"},
        "Server": {"nginx": "nginx", "Apache": "apache", "cloudflare": "cloudflare"},
        "X-Drupal-Cache": {"*": "drupal"},
        "X-Generator": {"WordPress": "wordpress", "Drupal": "drupal"},
        "X-AspNet-Version": {"*": "aspnet"},
    },
    "cookies": {
        "PHPSESSID": "php",
        "JSESSIONID": "java",
        "ASP.NET_SessionId": "aspnet",
        "wp-settings": "wordpress",
        "CFID": "coldfusion",
    },
    "html_patterns": {
        "wp-content/": "wordpress",
        "drupal.js": "drupal",
        "joomla": "joomla",
        "react": "react",
        "vue": "vue",
        "angular": "angular",
        "next-data": "nextjs",
    },
}

class TechFingerprinter:
    async def fingerprint(self, url: str) -> list[str]:
        """Detect technologies from HTTP response."""
        async with session.get(url) as resp:
            techs = set()
            
            # Check headers
            for header, sigs in TECH_SIGNATURES["headers"].items():
                val = resp.headers.get(header, "")
                for pattern, tech in sigs.items():
                    if pattern == "*" or pattern.lower() in val.lower():
                        techs.add(tech)
            
            # Check cookies
            for cookie in resp.cookies:
                if cookie.key in TECH_SIGNATURES["cookies"]:
                    techs.add(TECH_SIGNATURES["cookies"][cookie.key])
            
            # Check HTML
            body = await resp.text()
            for pattern, tech in TECH_SIGNATURES["html_patterns"].items():
                if pattern in body:
                    techs.add(tech)
            
            return sorted(techs)
```

---

## 3. Result Enrichment

### 3.1 Auto-Fetch and Extract

When results look promising, automatically fetch and extract content:

```python
class ContentExtractor:
    async def extract(self, url: str) -> ExtractedContent:
        async with session.get(url, proxy=proxy) as resp:
            html = await resp.text()
            
            return ExtractedContent(
                url=url,
                title=extract_title(html),
                text=extract_text(html),      # Main content, no boilerplate
                code_blocks=extract_code(html), # <pre>, <code> blocks
                links=extract_links(html),
                headers=dict(resp.headers),
                status=resp.status,
            )
    
    def extract_text(self, html: str) -> str:
        """Extract main content, strip navigation/ads/boilerplate."""
        soup = BeautifulSoup(html, "html.parser")
        # Remove noise
        for tag in soup.find_all(["nav", "footer", "header", "aside", "script", "style"]):
            tag.decompose()
        # Get text
        return soup.get_text(separator="\n", strip=True)
```

### 3.2 Result Correlation

Cross-reference results across searches:

```python
class ResultCorrelator:
    def correlate(self, searches: dict[str, list[SearchResult]]) -> CorrelationReport:
        """Find patterns across multiple searches.
        
        Example: search for config files on 3 domains
        → correlate which technologies appear on which domains
        → identify shared infrastructure
        """
        all_urls = {}
        all_techs = {}
        all_ips = {}
        
        for query, results in searches.items():
            for r in results:
                domain = urlparse(r.url).hostname
                all_urls.setdefault(domain, []).append(r)
                if r.technologies:
                    all_techs.setdefault(domain, set()).update(r.technologies)
                if r.ip_address:
                    all_ips.setdefault(r.ip_address, set()).add(domain)
        
        # Domains sharing same IP = shared hosting or same org
        shared_infra = {ip: domains for ip, domains in all_ips.items() if len(domains) > 1}
        
        return CorrelationReport(
            domains=all_urls,
            technologies=all_techs,
            shared_infrastructure=shared_infra,
        )
```

---

## 4. Operational Security

### 4.1 Query Hygiene

```python
class QuerySanitizer:
    def sanitize(self, query: str) -> str:
        """Remove personally identifying information from queries."""
        # Strip internal hostnames
        query = re.sub(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', '[IP]', query)
        # Strip internal domain patterns (configurable)
        for internal in self.config.internal_domains:
            query = query.replace(internal, '[INTERNAL]')
        return query
    
    def should_warn(self, query: str) -> str | None:
        """Warn if query might expose internal information."""
        if any(internal in query for internal in self.config.internal_domains):
            return "Query contains internal domain name"
        if re.search(r'password|secret|api.?key|token', query, re.I):
            return "Query contains credential-related terms"
        return None
```

### 4.2 Result Handling

```python
class ResultSanitizer:
    def sanitize_for_storage(self, result: SearchResult) -> SearchResult:
        """Clean results before storing."""
        # Don't store full page content of credential-containing pages
        if result.content and re.search(r'password|secret|key', result.content, re.I):
            result.content = "[REDACTED - credential content detected]"
            result.content_redacted = True
        return result
```
