# CAPTCHA Strategy: Three-Layer Anti-Bot Mitigation for GhostMCP

**Date:** 2026-06-20
**Version:** 1.0
**Status:** Design
**Sources:** Perplexity sonar-pro (8 citations), Brave Search (10 results), arxiv.org/html/2606.14525v1
**Classification:** Public

---

## Executive Summary

GhostMCP's search and web interaction tools face anti-bot challenges (CAPTCHAs, behavioral scoring, TLS fingerprinting) when scraping search engines or interacting with protected web applications. This document defines a **three-layer mitigation strategy** ordered by cost efficiency:

| Layer | Strategy | Cost | Coverage |
|---|---|---|---|
| **Layer 1: Avoid** | Don't trigger CAPTCHAs in the first place | Free | ~90% of encounters eliminated |
| **Layer 2: Self-Solve** | Use local VLM to solve image CAPTCHAs | Free (GPU we own) | ~85-95% of remaining CAPTCHAs |
| **Layer 3: API Fallback** | Third-party solving service for edge cases | ~$1-3/1000 solves | ~99% of what Layers 1-2 miss |

**Key principle:** Every self-solve we handle is knowledge we keep — we can tune the model, track which CAPTCHA types we're weak on, and improve. Outsourcing is renting someone else's capability forever. Plus, self-hosted means screenshots never leave our infrastructure.

---

## The CAPTCHA Landscape (2025-2026)

### Major Anti-Bot Systems

Six major systems dominate the anti-bot landscape, each using a combination of risk scoring, browser fingerprinting, and behavioral analysis. Understanding their detection methodology is essential for Layer 1 (avoidance).

| System | Challenge Type | Detection Methodology | Difficulty to Avoid |
|---|---|---|---|
| **reCAPTCHA v2** | Checkbox + image grid | IP reputation, browser fingerprint, behavioral data (mouse movement), Google account state | Medium |
| **reCAPTCHA v3** | Invisible (score 0-1) | All v2 signals + page context, interaction patterns. No interactive challenge — score only | Hard (no visible challenge to solve) |
| **hCaptcha** | Image grid + enterprise scoring | IP/ASN analysis, canvas/WebGL fingerprinting, behavioral analysis. Fine-grained object categories | Medium |
| **Cloudflare Turnstile** | Invisible JS challenge | JS environment checks, TLS fingerprinting (JA3/JA4 from proxy position), IP reputation, managed challenges | Hard (deep TLS integration) |
| **AWS WAF** | JS challenge + visual CAPTCHA | Rule-based + IP reputation + request patterns. Configurable per-rule enforcement | Medium (rule-dependent) |
| **FunCaptcha / Arkose Labs** | 3D game-like puzzles | Mouse trajectory analysis (micro-movements, timing), canvas/WebGL interaction, progressive difficulty | Very Hard (behavioral + spatial) |
| **GeeTest** | Slider puzzles | Movement trace analysis (trajectory, speed, acceleration, jitter), fingerprinting | Hard (requires realistic mouse simulation) |

> **Source:** Perplexity sonar-pro, June 2026, referencing steel.dev/blog/anti-bot-defense and fingerprint.com/blog/bot-detection/

### How Anti-Bot Systems Detect Automation

Modern systems treat detection as a **multi-signal classification problem**. Detection signals fall into six categories:

#### 1. Network & TLS Signals
- **IP reputation / infrastructure:** Datacenter IPs, proxy/VPN lists, TOR exits, cloud provider ASNs flagged vs residential ISPs
- **TLS fingerprinting (JA3/JA4):** Combination of offered ciphers, TLS extensions, elliptic curves, protocol version. Headless browsers produce fingerprints that differ from mainstream browsers
- **HTTP header anomalies:** User-Agent plausibility, header order (automation frameworks historically send headers in non-browser order), Sec-CH-UA client hints

#### 2. Browser Fingerprinting
- **Canvas fingerprinting:** Draw hidden graphics, hash pixel output — varies by GPU/driver/font/OS
- **WebGL fingerprinting:** GPU vendor/renderer strings, supported extensions, shader output hashes
- **AudioContext fingerprinting:** Web Audio API waveform processing varies across hardware
- **Font enumeration:** Headless containers have minimal font sets vs real systems
- **Hardware metadata:** Screen resolution, pixel ratio, CPU cores, memory, battery status

#### 3. Automation Artifact Detection
- **`navigator.webdriver` flag:** Probed on ~34% of sites (per arxiv.org/html/2606.14525v1)
- **CDP/DevTools protocol:** `window.cdc_*` variables from Selenium, DevTools domain artifacts
- **Headless mode quirks:** Missing APIs, default window size, GPU string differences

#### 4. Behavioral Analysis
- **Mouse movement:** Curvature, micro-jitter, variable speed. Straight lines or perfect curves = bot
- **Typing patterns:** Key down/up intervals, error rates, backspace usage. Uniform timings = suspicious
- **Navigation patterns:** Dwell time, scroll depth, page sequence. Instant form submission = obvious
- **Session stability:** Fingerprint or IP changes mid-session (IP rotation while cookies persist)

#### 5. Environment Consistency
- **Timezone vs IP geolocation:** JS timezone must match IP-based location
- **Locale vs language:** navigator.language must align with Accept-Language and keyboard layout
- **Platform coherence:** Claims iPhone Safari but has desktop screen and fonts

#### 6. Server-Side ML
- **Traffic clustering:** Request sequences, IPs, and device fingerprints analyzed for anomalous groups
- **Impossible travel:** Same hardware, different IPs with unrealistic time gaps

---

## Layer 1: Avoidance (Free — Eliminate ~90% of Encounters)

The cheapest CAPTCHA is the one never triggered. Layer 1 focuses on making Ghost's traffic indistinguishable from a normal browser user.

### 1.1 Search Engine Rotation (Round-Robin)

**Current behavior:** Fallback chain (serper → brave → google → duckduckgo) — switches engines only on failure.

**Proposed behavior:** Proactive round-robin rotation — distribute queries across engines to stay below each engine's detection threshold.

```python
class EngineRotator:
    """Round-robin engine selection with per-engine cooldown tracking."""
    
    def __init__(self):
        self.engines = ["brave", "google", "duckduckgo"]  # serper added if key present
        self.last_used = {}       # engine -> timestamp
        self.request_counts = {}  # engine -> count in current window
        self.cooldown_sec = 3     # minimum seconds between requests to same engine
        self.window_limits = {    # max requests per 10-minute window
            "brave": 50,          # API-based, generous
            "google": 10,         # scraping, aggressive detection
            "duckduckgo": 15,     # scraping, moderate detection
            "serper": 100,        # API-based, generous
        }
    
    def next_engine(self) -> str:
        """Select next engine: prefer engines with remaining budget and elapsed cooldown."""
        available = [e for e in self.engines if self._is_available(e)]
        if not available:
            return self._least_recently_used()  # fallback
        return available[0]  # round-robin order
```

**Impact:** Spreads load so no single engine sees more than 10-15 requests per 10-minute window. Google scraper (most CAPTCHA-prone) gets used sparingly.

### 1.2 Self-Throttling with Cooldown Tracking

Per-engine rate limiting with adaptive backoff:

| Engine | Type | Base Cooldown | Backoff on 429/CAPTCHA |
|---|---|---|---|
| Brave | API (key) | 0.5s | Not applicable (API) |
| Serper | API (key) | 0.2s | Not applicable (API) |
| Google | Scraper | 3-5s | Double cooldown, skip for 10 min |
| DuckDuckGo | Scraper | 2-3s | Double cooldown, skip for 5 min |
| Bing | Scraper | 2-3s | Double cooldown, skip for 5 min |

When a scraper engine returns a CAPTCHA or 429:
1. Mark engine as "cooling down" for N minutes
2. Double that engine's base cooldown for the session
3. Rotate to next available engine
4. Log the incident for adaptive learning

### 1.3 TLS Fingerprint Impersonation (curl_cffi)

GhostMCP already has `curl_cffi` as an optional dependency. When installed, it impersonates real browser TLS fingerprints (JA3/JA4), defeating the most common detection signal.

**Current status:** Available but only used in the Google scraper engine.

**Proposed:** Use curl_cffi for ALL scraper-based requests when available. Fall back to httpx when not installed.

```python
# TLS impersonation priority
if curl_cffi_available:
    # Impersonate Chrome 124 on Windows — matches most common JA3 fingerprint
    session = AsyncSession(impersonate="chrome124")
else:
    # Standard httpx — detectable JA3 but still works on most sites
    session = httpx.AsyncClient(...)
```

> **Research finding:** A recent measurement study found that spoofing header-level signals (user agent, header order) unblocked ~75% of previously blocked sites (arxiv.org/html/2606.14525v1). Adding TLS impersonation via curl_cffi covers the remaining JA3-based blocks.

### 1.4 Playwright Stealth Mode (ghost_render)

For `ghost_render` (headless Chromium), apply stealth patches to reduce automation detection:

**Signals to patch:**
- `navigator.webdriver` → `false` (detected on ~34% of sites)
- Realistic `navigator.plugins` and `navigator.mimeTypes` arrays
- Canvas/WebGL fingerprint consistency with claimed User-Agent
- Realistic screen dimensions and device pixel ratio
- Remove CDP artifacts (`window.cdc_*` variables)
- Realistic font enumeration (install common font packages in container)

**Implementation options:**
- `playwright-extra` with stealth plugin (community-maintained, patches ~20 detection vectors)
- Manual patching via `page.addInitScript()` for targeted fixes
- `camoufox` (stealth Firefox) as alternative when Chromium is too detectable

### 1.5 Behavioral Simulation

For interactions that go beyond simple page loads (form filling, clicking):

- **Mouse movement:** Generate Bézier curves with random micro-jitter instead of instant coordinate jumps
- **Typing:** Random inter-key delays (50-150ms) with occasional "mistakes" and corrections
- **Scroll:** Smooth scroll with variable speed, not instant `scrollTo()`
- **Timing:** Random delays between actions (500-2000ms), not deterministic intervals

```python
async def human_like_click(page, selector):
    """Click with realistic mouse movement."""
    element = await page.query_selector(selector)
    box = await element.bounding_box()
    # Generate Bézier curve from current position to target
    target_x = box["x"] + box["width"] * random.uniform(0.3, 0.7)
    target_y = box["y"] + box["height"] * random.uniform(0.3, 0.7)
    await page.mouse.move(target_x, target_y, steps=random.randint(10, 25))
    await asyncio.sleep(random.uniform(0.05, 0.15))
    await page.mouse.click(target_x, target_y)
```

### 1.6 API-First Strategy

The simplest avoidance: **use APIs instead of scrapers whenever possible.**

| Engine | API Available | Free Tier | CAPTCHAs? |
|---|---|---|---|
| Brave Search | Yes (API key) | 2,000/month | Never |
| Serper (Google) | Yes (API key) | 2,500/month | Never |
| Google | Scraping only | N/A | Frequent |
| DuckDuckGo | Scraping only | N/A | Moderate |
| Bing | API available | 1,000/month | Never (API) |

**Recommendation:** With Brave (2K) + Serper (2.5K), you get 4,500 CAPTCHA-free searches per month. That covers most use cases. Google/DDG scrapers become the rarely-used fallback, keeping their rate counters low.

---

## Layer 2: Self-Solve (Free — Local VLM, ~85-95% Success Rate)

When Layer 1 fails and a CAPTCHA appears, solve it locally using our own vision model. Zero marginal cost, zero data leaving our infrastructure.

### 2.1 The Pipeline

```
┌──────────────┐     ┌──────────────┐     ┌──────────────┐     ┌──────────────┐
│ ghost_render  │────>│  Screenshot  │────>│  Local VLM   │────>│ ghost_render  │
│ detects       │     │  + crop grid │     │  classifies  │     │ clicks tiles  │
│ CAPTCHA       │     │  into tiles  │     │  each tile   │     │ + submits     │
└──────────────┘     └──────────────┘     └──────────────┘     └──────────────┘
```

**Step-by-step:**

1. **Detection:** `ghost_render` loads a page. Before returning, check for known CAPTCHA indicators:
   - reCAPTCHA: `iframe[src*="recaptcha"]`, `div.g-recaptcha`
   - hCaptcha: `iframe[src*="hcaptcha"]`, `div.h-captcha`
   - Cloudflare: `div#challenge-form`, `cf-challenge` class
   - Generic: presence of "verify you are human", "select all", "click each image"

2. **Screenshot:** Capture the CAPTCHA element or its containing iframe as a PNG image

3. **Grid Extraction:** For image-grid CAPTCHAs (reCAPTCHA v2, hCaptcha):
   - Detect grid dimensions (3x3, 4x4) from image analysis
   - Crop into individual tiles
   - Extract the instruction text ("Select all images with traffic lights")

4. **VLM Classification:** For each tile, query the local vision model:
   ```
   Prompt: "Does this image contain a traffic light? Answer YES or NO."
   Input: [tile image]
   Output: "YES" (confidence: 0.94)
   ```

5. **Coordinate Mapping:** Map confident YES tiles back to click coordinates in the browser

6. **Execution:** `ghost_render` clicks each identified tile, then clicks the submit/verify button

7. **Verification:** Check if the CAPTCHA was accepted (page navigated, challenge div removed)
   - If rejected: retry with fresh screenshot (CAPTCHAs often regenerate)
   - After 3 failures: escalate to Layer 3

### 2.2 Vision Model Options

| Model | Parameters | VRAM | Speed | Grid Accuracy | Self-Hosted |
|---|---|---|---|---|---|
| **Qwen2.5-VL-7B** | 7B | ~8GB | ~2s/tile | High | Yes (GGUF via llama.cpp) |
| **LLaVA-1.6-7B** | 7B | ~8GB | ~2s/tile | High | Yes (GGUF) |
| **Qwen2.5-VL-3B** | 3B | ~4GB | ~1s/tile | Good | Yes (fits on smaller GPUs) |
| **CLIP ViT-L/14** | 428M | ~2GB | ~0.1s/tile | Good (zero-shot) | Yes (PyTorch) |
| **InternVL2-4B** | 4B | ~5GB | ~1.5s/tile | Good | Yes (GGUF) |

**Recommended primary:** Qwen2.5-VL-7B — best accuracy on spatial reasoning tasks, competitive with GPT-4V on VQA benchmarks, runs on our existing GPU infrastructure.

**Recommended fast path:** CLIP ViT-L/14 — 20x faster than generative VLMs, good enough for clear grid images, can pre-filter before sending ambiguous tiles to the full VLM.

**Two-stage approach:**
```
Stage 1 (CLIP, ~100ms/tile): Score all tiles against target label
  → Tiles with confidence > 0.9: select immediately
  → Tiles with confidence < 0.3: reject immediately
  → Tiles with confidence 0.3-0.9: send to Stage 2

Stage 2 (Qwen-VL, ~2s/tile): Classify ambiguous tiles with full VLM
  → Higher accuracy on edge cases (partial objects, unusual angles)
```

> **Research finding:** Perplexity reports that "off-the-shelf multimodal models can solve grid-based CAPTCHAs with high reliability when given enough context and minimal prompt engineering." Academic evaluations show >90% accuracy on traffic sign, vehicle, and crosswalk categories.

### 2.3 CAPTCHA Type-Specific Solving Strategies

#### Image Grid (reCAPTCHA v2, hCaptcha)
- **Approach:** VLM tile classification (described above)
- **Expected accuracy:** 85-95% first attempt
- **Failure mode:** Ambiguous images (is that a traffic light or a pole?), new/rare categories

#### Text CAPTCHA (Legacy)
- **Approach:** OCR via Tesseract or EasyOCR (both open-source, self-hosted)
- **Expected accuracy:** 70-90% depending on distortion level
- **Failure mode:** Heavy noise, overlapping characters

#### Slider CAPTCHA (GeeTest)
- **Approach:** Template matching to find the puzzle piece gap position, then simulate realistic drag
- **Implementation:** Screenshot → edge detection (OpenCV) → find gap → generate Bézier mouse path
- **Expected accuracy:** 80-90%
- **Failure mode:** Complex backgrounds, multiple possible positions

#### Behavioral / Invisible (reCAPTCHA v3, Turnstile)
- **Not solvable via vision** — these are risk scores, not visual challenges
- **Mitigation:** Layer 1 avoidance (stealth mode, behavioral simulation, TLS impersonation)
- **If still blocked:** Fall through to Layer 3 API or try alternative access method

#### 3D / Game-like (Arkose Labs / FunCaptcha)
- **Hardest category** — requires spatial reasoning + behavioral realism
- **Approach:** VLM for the cognitive task + behavioral simulation for the interaction
- **Expected accuracy:** 60-75% (lower due to interaction complexity)
- **Likely fallback to Layer 3 for these**

### 2.4 Integration with Unimind DMN

The Default Mode Network (DMN) already runs a local Qwen model for meditation/inference. Extending it for CAPTCHA solving:

```
ghost_render encounters CAPTCHA
    → captures screenshot
    → sends to DMN via Redis stream (captcha:solve queue)
    → DMN processes with Qwen-VL
    → returns tile classifications via Redis stream
    → ghost_render clicks and submits
```

**Advantages of DMN integration:**
- Model already loaded in GPU memory (no cold-start latency)
- Shared inference infrastructure (no second GPU process)
- DMN can learn from solve attempts (track success/failure per CAPTCHA type)
- Unimind stores CAPTCHA encounter statistics for adaptive strategy

### 2.5 Learning Loop

Every CAPTCHA encounter feeds back into the system:

```python
@dataclass
class CaptchaEvent:
    timestamp: datetime
    url: str
    captcha_type: str        # "recaptcha_v2", "hcaptcha", "turnstile", etc.
    challenge_category: str  # "traffic_lights", "bicycles", "buses", etc.
    layer_used: int          # 1=avoided, 2=self-solved, 3=API
    attempts: int            # how many tries before success
    success: bool
    solve_time_ms: int
    model_used: str          # "clip", "qwen-vl", "api:capsolver", etc.
    confidence_scores: list  # per-tile confidence for analysis
```

Stored in Unimind knowledge graph:
- Track which engines trigger CAPTCHAs most frequently → adjust rotation weights
- Track which CAPTCHA categories our VLM struggles with → prioritize fine-tuning
- Track solve success rate over time → measure model improvement

---

## Layer 3: API Fallback (~$1-3/1000 Solves)

For the ~5-10% of CAPTCHAs that Layer 2 can't solve (complex 3D puzzles, behavioral challenges, novel CAPTCHA types), fall back to a third-party solving service.

### 3.1 Service Options

| Service | Pricing | Speed | CAPTCHA Types | API Quality |
|---|---|---|---|---|
| **CapSolver** | ~$1-2/1000 | 5-15s | reCAPTCHA, hCaptcha, Turnstile, FunCaptcha, GeeTest | Good, well-documented |
| **2Captcha** | ~$1-3/1000 | 10-30s | All major types | Established, reliable |
| **Anti-Captcha** | ~$1-3/1000 | 5-20s | All major types | Good, human + AI solvers |
| **SolveCaptcha** | ~$1-2/1000 | 5-15s | All major types | Newer (2025), universal API |

### 3.2 Integration Architecture

```python
class CaptchaSolverChain:
    """Three-layer CAPTCHA solving with automatic escalation."""
    
    async def solve(self, page, captcha_info: CaptchaInfo) -> bool:
        # Layer 1: Was this supposed to be avoided?
        self._log_avoidance_failure(captcha_info)
        
        # Layer 2: Try self-solving first (free)
        if captcha_info.type in SELF_SOLVABLE_TYPES:
            result = await self._self_solve(page, captcha_info)
            if result.success:
                self._log_event(captcha_info, layer=2, success=True)
                return True
        
        # Layer 3: API fallback (paid)
        if self.api_key_configured:
            result = await self._api_solve(page, captcha_info)
            if result.success:
                self._log_event(captcha_info, layer=3, success=True)
                return True
        
        # All layers failed
        self._log_event(captcha_info, layer=3, success=False)
        return False
```

### 3.3 Cost Controls

- **Budget cap:** Configurable maximum spend per day/month (default: $0 — API disabled unless explicitly configured)
- **Per-request approval:** Option to require confirmation before spending on API solves
- **Cost tracking:** Every API solve logged with cost, integrated into Unimind usage reporting
- **API key management:** via `GHOST_CAPTCHA_API_KEY` environment variable, same pattern as other Ghost API keys

### 3.4 Privacy Consideration

Sending CAPTCHAs to third-party APIs means sending screenshots of what you're accessing to a service you don't control. This is why Layer 2 (self-hosted) is preferred:

| Layer | Data Leaves Infrastructure? | Privacy Risk |
|---|---|---|
| Layer 1 (Avoid) | No | None |
| Layer 2 (Self-Solve) | No | None |
| Layer 3 (API) | **Yes** — screenshots sent to solver service | Medium — reveals target URLs and activity |

---

## Implementation Roadmap

### Phase 1: Avoidance (Layer 1) — ~3 days
Priority: **HIGH** — eliminates 90% of the problem

| Task | Effort | Impact |
|---|---|---|
| Engine round-robin rotation | 0.5 day | Spreads load across engines |
| Per-engine cooldown tracking + adaptive backoff | 0.5 day | Prevents rate-limit triggers |
| curl_cffi TLS impersonation for all scrapers | 0.5 day | Defeats JA3 fingerprinting |
| Playwright stealth patches for ghost_render | 1 day | Reduces automation detection |
| Behavioral simulation helpers (mouse/typing/scroll) | 0.5 day | Humanizes interactions |

### Phase 2: Self-Solve (Layer 2) — ~5 days
Priority: **MEDIUM** — handles what avoidance misses

| Task | Effort | Impact |
|---|---|---|
| CAPTCHA detection in ghost_render | 0.5 day | Identify when a CAPTCHA appears |
| Grid screenshot + tile extraction | 1 day | Crop grid CAPTCHAs into tiles |
| CLIP integration for fast tile classification | 1 day | Quick pre-filter, ~100ms/tile |
| Qwen-VL integration via DMN for accurate classification | 1 day | Full VLM for ambiguous tiles |
| Slider CAPTCHA solver (template matching + drag sim) | 1 day | GeeTest-style challenges |
| Learning loop + Unimind event logging | 0.5 day | Adaptive improvement |

### Phase 3: API Fallback (Layer 3) — ~1 day
Priority: **LOW** — only for edge cases

| Task | Effort | Impact |
|---|---|---|
| CapSolver/2Captcha API client | 0.5 day | Third-party integration |
| Budget controls + cost tracking | 0.5 day | Prevent runaway spending |

### Dependencies

| Component | Required For | Status |
|---|---|---|
| curl_cffi | Layer 1 TLS impersonation | Optional dep (already in codebase) |
| playwright-extra / stealth plugin | Layer 1 browser stealth | New dependency |
| CLIP ViT-L/14 | Layer 2 fast classification | New model (~600MB download) |
| Qwen2.5-VL-7B GGUF | Layer 2 accurate classification | New model (~4-8GB download) |
| OpenCV | Layer 2 slider CAPTCHA | New dependency |
| DMN running with Qwen-VL | Layer 2 inference infrastructure | Requires DMN container update |
| GHOST_CAPTCHA_API_KEY | Layer 3 API fallback | Optional env var |

---

## Legitimate Testing Approaches

For authorized testing of our own CAPTCHA-protected applications (CI/CD, security testing):

### Vendor Test Keys
- **reCAPTCHA / hCaptcha:** Provide test site keys that always succeed/fail — use in non-production environments
- **Cloudflare Turnstile:** Define firewall rules to skip challenges for CI IP ranges
- **AWS WAF:** Rules can bypass challenge for VPC/mTLS clients

### Design Pattern
Abstract CAPTCHA behind an interface so CI environments skip it:

```python
class BotVerifier:
    async def verify(self, request_context) -> VerifyResult:
        """Check if request is from a bot."""
        ...

class MockBotVerifier(BotVerifier):
    """Always passes — used in CI/staging."""
    async def verify(self, request_context) -> VerifyResult:
        return VerifyResult(allowed=True, score=1.0)
```

For production, wire to real vendor. For CI/staging, inject mock. Config flags for selective enforcement per environment.

---

## Stealth Browser Tool Comparison

Per Perplexity research and arxiv.org/html/2606.14525v1:

| Tool | Platform | Approach | Effectiveness (2026) | Status |
|---|---|---|---|---|
| **puppeteer-extra-plugin-stealth** | Chromium | ~20 evasion patches | Widely used, heavily targeted by vendors | Established |
| **playwright-extra + stealth plugin** | Chromium | Similar patches for Playwright | Newer, still fingerprintable under careful inspection | Recommended for Ghost |
| **undetected-chromedriver** | Chromium/Selenium | Dynamic patches, custom Chrome builds | Works until vendors update, requires maintenance | Established |
| **camoufox** | Firefox | Stealth Firefox automation | Less common = less targeted, good fingerprint diversity | Alternative |
| **nodriver** | Chromium | No WebDriver stack at all | Reduces Selenium signatures, still has fingerprinting surface | Experimental |
| **curl_cffi** | HTTP client | TLS impersonation (JA3/JA4 spoofing) | Very effective for HTTP-only (not browser) requests | Already in Ghost |

> **Key finding:** Spoofing header-level signals unblocked ~75% of previously blocked sites (arxiv.org/html/2606.14525v1). Major vendors (Cloudflare, Akamai, HUMAN) use deeper fingerprints + TLS/JA3 + behavior for the remaining 25%.

---

## References

### Perplexity Research (June 2026)
- [1] arxiv.org/html/2606.14525v1 — Large-scale measurement of anti-bot detection scripts (~34% probe navigator.webdriver, ~75% unblocked by header spoofing)
- [2] steel.dev/blog/anti-bot-defense — Comprehensive anti-bot detection signal taxonomy
- [3] fingerprint.com/blog/bot-detection — Browser fingerprinting methodology
- [4] humansecurity.com/platform/solutions/bot-detection-mitigation/ — HUMAN (PerimeterX) detection approach
- [5] pmc.ncbi.nlm.nih.gov/articles/PMC7338186/ — Academic research on CAPTCHA security
- [6] entro.security/glossary/bot-security/ — Bot security terminology

### Brave Search Validation (June 2026)
- capsolver.com/blog/web-scraping/ai-browser-captcha-solver — AI browser + CAPTCHA solver integration guide
- capsolver.com/blog/web-scraping/automating-captcha-solving-in-headless-browsers — Headless browser CAPTCHA automation
- capsolver.com/blog/web-scraping/2026-ai-agent-captcha — 2026 guide to CAPTCHA solving for AI agents
- skyvern.com/blog/best-way-to-bypass-captcha-for-ai-browser-automation-september-2025/ — AI browser automation with built-in CAPTCHA solving
- docs.browserless.io/baas/bot-detection/captchas — Browserless CAPTCHA solving via CDP
- github.com/aydinnyunus/ai-captcha-bypass — Open-source AI CAPTCHA bypass with Selenium
- fast.io/resources/best-headless-browsers-ai-agents/ — Headless browser comparison for AI agents

### Academic / Research
- VLM accuracy on grid CAPTCHAs: >90% for standard categories (traffic signs, vehicles, crosswalks) per Perplexity synthesis of 2023-2026 research
- Key implication for CAPTCHA designers: "If a human can reliably solve your image grid, a modern VLM can likely do so as well" (Perplexity synthesis)

---

## Revision History

| Version | Date | Changes |
|---|---|---|
| v1.0 | 2026-06-20 | Initial design: three-layer strategy, CAPTCHA landscape, VLM pipeline, stealth comparison |

---

*Filed by: OpenCode Agent*
*Research date: 2026-06-20*
*Methodology: Perplexity deep research + Brave Search validation*
*Classification: Public*
