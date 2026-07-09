"""Browser stealth patches for Playwright to reduce automation detection.

Applies patches that address the most common detection vectors:
- navigator.webdriver flag (~34% of sites check this)
- Plugin/mime type arrays (headless has empty arrays)
- Chrome runtime properties (CDP artifacts)
- WebGL vendor/renderer strings
- Language and platform consistency
- Permissions API behavior

Reference: arxiv.org/html/2606.14525v1 — measurement study showing
header-level spoofing unblocks ~75% of blocked sites.
"""

from __future__ import annotations

# List of init scripts to inject via page.addInitScript()
# Each script runs in the page context before any site JS executes

STEALTH_SCRIPTS = [
    # 1. navigator.webdriver = false
    """
    Object.defineProperty(navigator, 'webdriver', {
        get: () => false,
    });
    """,

    # 2. Chrome runtime — remove CDP artifacts
    """
    // Remove Selenium/ChromeDriver artifacts
    delete window.cdc_adoQpoasnfa76pfcZLmcfl_Array;
    delete window.cdc_adoQpoasnfa76pfcZLmcfl_Promise;
    delete window.cdc_adoQpoasnfa76pfcZLmcfl_Symbol;

    // Add chrome runtime object (missing in headless)
    if (!window.chrome) {
        window.chrome = {};
    }
    if (!window.chrome.runtime) {
        window.chrome.runtime = {
            connect: function() {},
            sendMessage: function() {},
        };
    }
    """,

    # 3. navigator.plugins — headless has empty array
    """
    Object.defineProperty(navigator, 'plugins', {
        get: () => {
            const plugins = [
                { name: 'Chrome PDF Plugin', filename: 'internal-pdf-viewer', description: 'Portable Document Format' },
                { name: 'Chrome PDF Viewer', filename: 'mhjfbmdgcfjbbpaeojofohoefgiehjai', description: '' },
                { name: 'Native Client', filename: 'internal-nacl-plugin', description: '' },
            ];
            plugins.length = 3;
            return plugins;
        },
    });
    """,

    # 4. navigator.mimeTypes
    """
    Object.defineProperty(navigator, 'mimeTypes', {
        get: () => {
            const mimeTypes = [
                { type: 'application/pdf', suffixes: 'pdf', description: 'Portable Document Format' },
                { type: 'application/x-google-chrome-pdf', suffixes: 'pdf', description: 'Portable Document Format' },
            ];
            mimeTypes.length = 2;
            return mimeTypes;
        },
    });
    """,

    # 5. navigator.languages
    """
    Object.defineProperty(navigator, 'languages', {
        get: () => ['en-US', 'en'],
    });
    """,

    # 6. Permissions API — headless returns inconsistent results
    """
    const originalQuery = window.navigator.permissions.query;
    window.navigator.permissions.query = (parameters) => (
        parameters.name === 'notifications' ?
            Promise.resolve({ state: Notification.permission }) :
            originalQuery(parameters)
    );
    """,

    # 7. WebGL vendor/renderer — headless uses generic strings
    """
    const getParameter = WebGLRenderingContext.prototype.getParameter;
    WebGLRenderingContext.prototype.getParameter = function(parameter) {
        // UNMASKED_VENDOR_WEBGL
        if (parameter === 37445) {
            return 'Google Inc. (NVIDIA)';
        }
        // UNMASKED_RENDERER_WEBGL
        if (parameter === 37446) {
            return 'ANGLE (NVIDIA, NVIDIA GeForce GTX 1650 Direct3D11 vs_5_0 ps_5_0, D3D11)';
        }
        return getParameter.call(this, parameter);
    };
    """,

    # 8. iframe contentWindow — headless returns null for cross-origin
    """
    // Prevent detection via iframe.contentWindow being null
    const originalDescriptor = Object.getOwnPropertyDescriptor(HTMLIFrameElement.prototype, 'contentWindow');
    """,

    # 9. navigator.hardwareConcurrency — headless often reports different values
    """
    Object.defineProperty(navigator, 'hardwareConcurrency', {
        get: () => 8,
    });
    """,

    # 10. navigator.platform consistency
    """
    Object.defineProperty(navigator, 'platform', {
        get: () => 'Win32',
    });
    """,
]


async def apply_stealth(page) -> None:
    """Apply all stealth patches to a Playwright page.

    Call this BEFORE page.goto() to ensure patches are in place
    before any site JavaScript executes.

    Args:
        page: Playwright page object
    """
    for script in STEALTH_SCRIPTS:
        await page.add_init_script(script)


def get_stealth_context_options() -> dict:
    """Return Playwright browser context options that reduce detection.

    Use when creating a new browser context:
        context = browser.new_context(**get_stealth_context_options())
    """
    return {
        "user_agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/124.0.0.0 Safari/537.36"
        ),
        "viewport": {"width": 1920, "height": 1080},
        "device_scale_factor": 1,
        "is_mobile": False,
        "has_touch": False,
        "locale": "en-US",
        "timezone_id": "America/New_York",
        "color_scheme": "light",
        # Permissions
        "permissions": ["geolocation"],
        # Realistic screen
        "screen": {"width": 1920, "height": 1080},
    }
