# Installing GhostMCP

GhostMCP can be installed three ways depending on how you intend to run it:

| Path | Use when… | Entry point |
|------|-----------|-------------|
| **A. Client install** | You want GhostMCP's tools inside an MCP client (opencode, Claude Desktop, Cursor, VS Code Copilot) on your workstation. | `./install.sh` |
| **B. Docker Compose** | You want the full server stack (MCP server + internal SearXNG metasearch) running locally with one command. | `docker compose up -d` |
| **C. Container build & deploy** | You are building/publishing container images, running a persistent dev container, or deploying to Azure Container Instances (ACI). | `scripts/build-ghostmcp.sh` |

> **TL;DR** — Just want the tools in your IDE? Use **Path A**. Running a server?
> Use **Path B**. Building images or deploying to Azure? Use **Path C**.

---

## Prerequisites

- **Python 3.9+** (3.12 recommended; container images use 3.12-slim)
- One container runtime for Paths B/C: **Docker** *or* **Podman** (rootless)
- **Azure CLI (`az`)** — only for Azure ACR/ACI builds (Path C, `--azure`)

Core Python dependencies (installed automatically by the installers):

```
httpx>=0.27.0            # HTTP client
httpx[brotli]            # Brotli response decoding
cryptography>=41.0.0     # TLS/cert tooling
starlette / uvicorn      # HTTP server mode
websockets>=12.0         # Bridge client transport
phonenumbers>=8.13.0     # Phone intel
playwright>=1.40.0       # (optional) headless browser rendering
```

---

## Path A — Client install (`install.sh`)

Sets up GhostMCP for use with an MCP client on your machine. It is
non-destructive: it never edits your existing `opencode.json` or stores API
keys — it prints a config snippet for you to paste.

```bash
./install.sh                 # Basic: search + OSINT tools
./install.sh --render        # + headless Chromium (enables ghost_render)
./install.sh --full          # + Chromium + all optional deps
./install.sh --help
```

**What it does:**

1. Creates `~/.ghostmcp/client/` with the source and a dedicated `.venv`.
2. Installs Python dependencies into that venv (`httpx`, `phonenumbers`, …).
3. Optionally installs Playwright + Chromium (`--render` / `--full`).
4. Runs a functional smoke test.
5. Prints an `opencode.json` MCP config snippet to paste.

**What it does NOT do:** modify your `opencode.json`, store API keys, or
require root. Re-running upgrades in place while preserving your `.venv`.

Install location can be overridden: `./install.sh --install-dir /custom/path`.

---

## Path B — Docker Compose (local server stack)

Runs the MCP server together with a pre-configured internal SearXNG instance
(so `ghost_searxng` works out of the box).

```bash
docker compose up -d          # Start everything
docker compose ps             # Status
docker compose logs -f ghostmcp
docker compose down           # Stop
```

This starts:

- **ghostmcp** — the MCP server (port `8080`)
- **searxng** — internal metasearch (not exposed externally by default)

Environment variables (set in `docker-compose.yml` or a `.env` file):

```bash
GHOST_PARANOIA=cautious                 # OpSec: casual | cautious | ghost | midnight
GHOST_MIN_DELAY=2.0                     # Min seconds between requests
GHOST_SEARXNG_URL=http://searxng:8080   # Auto-configured

# Optional API keys:
SERPER_API_KEY=…      # Google search via Serper
GHOST_REGRID_KEY=…    # Property/parcel data via Regrid
VT_API_KEY=…          # VirusTotal
GHOST_HIBP_KEY=…      # Have I Been Pwned
```

---

## Path C — Container build & deploy (`scripts/build-ghostmcp.sh`)

`scripts/build-ghostmcp.sh` is the single entry point for building GhostMCP
container images, running a persistent dev container over SSH, and deploying to
Azure. **Run it from anywhere** — it locates the repo root itself.

### 1. Repo layout it expects

The script lives in `scripts/` and resolves the **repo root as its parent
directory**. All Docker build contexts are the repo root, and every Dockerfile
lives at the repo root:

```
GhostMCP/
├── scripts/
│   └── build-ghostmcp.sh      ← run this
├── Dockerfile                 ← app image (COPY ghostmcp/ tests/)
├── Dockerfile.base            ← OS + Python deps + Playwright/Chromium
├── Dockerfile.layer1-os       ← granular cache layers (OS)
├── Dockerfile.layer2-model    ← (model)
├── Dockerfile.layer3-pip      ← (pip deps)
├── Dockerfile.layer4-app      ← (app code)
├── Dockerfile.render          ← render sidecar
├── ghostmcp/                  ← application package
├── tests/
└── requirements.txt
```

Because it uses `BASH_SOURCE`, all of these are equivalent:

```bash
scripts/build-ghostmcp.sh build          # from repo root
../scripts/build-ghostmcp.sh build       # from a subdirectory
/abs/path/GhostMCP/scripts/build-ghostmcp.sh build   # from anywhere
```

Override the root explicitly with `GHOST_ROOT=/path/to/GhostMCP` if needed.

### 2. Runtime auto-detection

The script picks a container runtime automatically, in this priority order:

1. `--podman` flag → **podman** (forced, rootless, no sudo)
2. `--azure` flag → **Azure ACR** remote build (forced; requires `az`)
3. Windows (MSYS2) + `az` present → **Azure ACR** remote build
4. Docker daemon running → **docker** (invoked with `sudo`)
5. `podman` available → **podman** (rootless fallback)

The current selection is shown in `scripts/build-ghostmcp.sh help`.

### 3. Two-layer image model

Builds are split into a heavy **base** and a fast **app** layer:

- **base** — OS packages + Python deps + Playwright + Chromium. Slow, changes
  rarely. Build once, reuse.
- **app** — your `ghostmcp/` + `tests/` code on top of the base. Fast, rebuild
  every commit. Injects `GIT_COMMIT`, `GIT_BRANCH`, and `BUILD_TIME` build args.

```bash
scripts/build-ghostmcp.sh build base            # heavy base (slow, occasional)
scripts/build-ghostmcp.sh build                 # app layer only (fast, default)
scripts/build-ghostmcp.sh build all             # base then app
scripts/build-ghostmcp.sh build all --no-cache  # full rebuild, no cache
```

### 4. Local build with Podman

Rootless, no sudo required — recommended for local development:

```bash
scripts/build-ghostmcp.sh build base --podman   # first time (builds base)
scripts/build-ghostmcp.sh build --podman        # subsequent app rebuilds
```

> **Rootless podman note:** if you see
> `no subuid ranges found … in /etc/subuid`, your user isn't configured for
> rootless mode. Fix once:
> ```bash
> sudo usermod --add-subuids 100000-165535 --add-subgids 100000-165535 "$USER"
> podman system migrate
> ```

### 5. Persistent dev container (SSH workflow)

Run a long-lived container you can SSH into, sync code to, and test inside:

```bash
scripts/build-ghostmcp.sh run                   # start container (SSH on :2222)
scripts/build-ghostmcp.sh status                # show state / ports / uptime
scripts/build-ghostmcp.sh ssh                    # interactive SSH shell
scripts/build-ghostmcp.sh shell                  # bash via exec (no SSH)
scripts/build-ghostmcp.sh sync                    # push local ghostmcp/ + tests/ → container
scripts/build-ghostmcp.sh pull                    # pull container ghostmcp/ + tests/ → local
scripts/build-ghostmcp.sh test                    # run pytest inside the container
scripts/build-ghostmcp.sh mcp                     # verify MCP tools/list response
scripts/build-ghostmcp.sh logs                    # last 50 log lines
scripts/build-ghostmcp.sh restart                 # stop + run
scripts/build-ghostmcp.sh stop                    # stop and remove
```

The container publishes SSH on `GHOST_SSH_PORT` (default `2222`):
`ssh -p 2222 root@localhost`.

### 6. Azure ACR build + ACI deploy

Build images in Azure Container Registry and deploy to Azure Container
Instances. Requires the Azure CLI and the environment variables below.

```bash
scripts/build-ghostmcp.sh build all --azure     # build base + app in ACR
scripts/build-ghostmcp.sh deploy                 # deploy image to ACI
scripts/build-ghostmcp.sh teardown               # delete the ACI container group
```

`deploy` generates a temporary `deploy-ghostmcp.yaml` at the repo root (removed
automatically), wires ACR pull credentials, deploys into your VNet/subnet with a
private IP (ports 8080 + 22), and waits for the container to reach `Running`.

### 7. Full command reference

| Command | Description |
|---------|-------------|
| `build [base\|app\|all]` | Build image(s). Default target: `app`. |
| `run` | Start persistent container (background + SSH). |
| `stop` | Stop and remove the container. |
| `restart` | `stop` then `run`. |
| `status` | Show container state, ports, uptime. |
| `logs` | Last 50 log lines. |
| `ssh` | SSH into the running container. |
| `shell` | Interactive bash via `exec`. |
| `test` | Run the pytest suite inside the container. |
| `mcp` | Test the MCP `tools/list` response. |
| `sync` | Push local `ghostmcp/` + `tests/` into the container. |
| `pull` | Pull container `ghostmcp/` + `tests/` back to local. |
| `deploy` | Build + deploy to Azure Container Instances. |
| `teardown` | Delete the ACI container group. |
| `help` | Full usage, current runtime, and resolved env. |

Flags: `--podman` (force podman), `--azure` (force ACR), `--no-cache`.

### 8. Environment variables

| Variable | Default | Purpose |
|----------|---------|---------|
| `GHOST_ROOT` | parent of `scripts/` | Override repo root resolution. |
| `GHOST_IMAGE` | `ghostmcp:latest` | Local app image tag. |
| `GHOST_IMAGE_BASE` | `ghostmcp-base:latest` | Local base image tag. |
| `GHOST_CONTAINER` | `ghostmcp-dev` | Dev container name. |
| `GHOST_SSH_PORT` | `2222` | Host port mapped to container SSH (22). |
| `GHOST_ACR_NAME` | *(unset)* | Azure Container Registry name. Required for `--azure`. |
| `GHOST_ACR_IMAGE` | `ghostmcp` | ACR app image repo. |
| `GHOST_ACR_IMAGE_BASE` | `ghostmcp-base` | ACR base image repo. |
| `GHOST_SUBSCRIPTION` | *(unset)* | Azure subscription ID. Required for ACR/ACI. |
| `GHOST_RESOURCE_GROUP` | *(unset)* | Azure resource group. Required for ACI. |
| `GHOST_LOCATION` | `centralus` | Azure region for ACI. |
| `GHOST_VNET` | *(unset)* | VNet for the ACI deployment. |
| `GHOST_SUBNET` | *(unset)* | Subnet within the VNet. |
| `GHOST_CONTAINER_GROUP` | `ghostmcp-app` | ACI container group name. |

Azure deploys have **no built-in defaults** for subscription, resource group,
VNet, or subnet — they must be set explicitly. Podman/Docker builds need none of
these.

---

## MCP client configuration

After Path A (or when running the server), point your MCP client at GhostMCP.
Add to `opencode.json` / `claude_desktop_config.json` / equivalent:

```json
{
  "mcp": {
    "ghostmcp": {
      "type": "local",
      "command": ["python3", "-m", "ghostmcp"],
      "enabled": true,
      "environment": {
        "PYTHONPATH": "/path/to/GhostMCP",
        "GHOST_PARANOIA": "cautious",
        "GHOST_MIN_DELAY": "2.0",
        "SERPER_API_KEY": "optional-for-google-results",
        "VT_API_KEY": "optional-for-virustotal",
        "GHOST_HIBP_KEY": "optional-for-breach-lookups"
      }
    }
  }
}
```

Restart your MCP client after adding the configuration.

---

## IDE integration

GhostMCP is a standard MCP server, so any IDE with MCP support can use it. Two
connection styles work everywhere:

- **Direct (stdio)** — the IDE launches `python3 -m ghostmcp` locally. Simplest;
  best when the repo lives on the same machine as the IDE.
- **WebSocket bridge** — the IDE launches `client/ghost_client.py`, which
  connects to a running GhostMCP server (Docker Compose or Azure). Best when the
  server runs elsewhere, or you want the internal SearXNG stack. See
  `client/ghost_client.yaml.example`.

> Use the **absolute path** to the Python interpreter that has GhostMCP's
> dependencies installed (e.g. the venv created by `install.sh`:
> `~/.ghostmcp/client/.venv/bin/python3`). Relying on a bare `python3` often
> resolves to the wrong interpreter when an IDE spawns the process.

### VS Code (GitHub Copilot — Agent mode)

VS Code reads MCP servers from a dedicated `mcp.json` file. Create one of:

- **Workspace**: `.vscode/mcp.json` (commit or gitignore per team preference)
- **User (global)**: Command Palette → **MCP: Open User Configuration**

```jsonc
// .vscode/mcp.json
{
  "servers": {
    "ghostmcp": {
      "type": "stdio",
      "command": "/home/you/.ghostmcp/client/.venv/bin/python3",
      "args": ["-m", "ghostmcp"],
      "env": {
        "PYTHONPATH": "/path/to/GhostMCP",
        "GHOST_PARANOIA": "cautious",
        "GHOST_MIN_DELAY": "2.0",
        "SERPER_API_KEY": "",
        "VT_API_KEY": "",
        "GHOST_HIBP_KEY": ""
      }
    }
  }
}
```

Then:

1. Open the Chat view and switch the mode dropdown to **Agent**.
2. Click the **tools** icon — `ghostmcp` and its 29 tools should be listed.
3. Use **MCP: List Servers** from the Command Palette to start/stop/inspect it.

Prefer `settings.json`? The same server can live under an `"mcp"` key:

```jsonc
// settings.json  (Preferences: Open Settings (JSON))
{
  "mcp": {
    "servers": {
      "ghostmcp": {
        "type": "stdio",
        "command": "/home/you/.ghostmcp/client/.venv/bin/python3",
        "args": ["-m", "ghostmcp"],
        "env": { "PYTHONPATH": "/path/to/GhostMCP" }
      }
    }
  }
}
```

**Windows (MSYS2):** point `command` at the MSYS2 interpreter and use forward
slashes, e.g. `"C:/msys64/ucrt64/bin/python3.exe"`. To use the WebSocket bridge
instead, set `args` to `["C:/path/to/GhostMCP/client/ghost_client.py",
"--config", "C:/Users/you/.ghost_client.yaml"]`. See
`docs/windows-opencode-setup.md` for the full Windows walkthrough.

### PyCharm (and other JetBrains IDEs)

JetBrains AI Assistant / Junie support MCP servers, configured through the
settings UI rather than a fixed JSON file path.

1. **Settings → Tools → AI Assistant → Model Context Protocol (MCP)**
   (on some builds: the Junie MCP settings panel).
2. **Add** a new server and choose the **stdio / command** transport.
3. Fill in:
   - **Name:** `ghostmcp`
   - **Command:** absolute path to your Python, e.g.
     `/home/you/.ghostmcp/client/.venv/bin/python3`
   - **Arguments:** `-m ghostmcp`
   - **Environment variables:**
     `PYTHONPATH=/path/to/GhostMCP`, `GHOST_PARANOIA=cautious`,
     `GHOST_MIN_DELAY=2.0`, plus any API keys.
4. **Apply**, then open the AI Assistant chat and confirm the GhostMCP tools
   appear in the available-tools list.

Newer JetBrains builds also accept an "add from JSON" option using the common
`mcpServers` shape — handy for pasting a shared config:

```jsonc
{
  "mcpServers": {
    "ghostmcp": {
      "command": "/home/you/.ghostmcp/client/.venv/bin/python3",
      "args": ["-m", "ghostmcp"],
      "env": {
        "PYTHONPATH": "/path/to/GhostMCP",
        "GHOST_PARANOIA": "cautious"
      }
    }
  }
}
```

> **PyCharm interpreter tip:** you can point `command` at the Python from your
> project's configured interpreter (**Settings → Project → Python Interpreter**
> shows its path) as long as GhostMCP's dependencies are installed there.

### Troubleshooting IDE integration

- **Server won't start / "command not found":** use an absolute interpreter path;
  a bare `python3` frequently resolves to the wrong environment inside an IDE.
- **Import errors (`No module named ghostmcp`):** set `PYTHONPATH` to the repo
  root, or run from a venv that has GhostMCP installed/importable.
- **Tools don't appear:** confirm the client is in an MCP-capable mode (VS Code:
  Chat → **Agent**; JetBrains: AI Assistant chat), then restart the MCP server
  from the IDE.
- **Verify the server independently** before blaming the IDE:
  ```bash
  echo '{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}' \
    | /path/to/python3 -m ghostmcp
  ```
  This should print a JSON list of 29 tools.

---

## Verifying the install

```bash
# Run the test suite (client / source install)
python3 -m pytest tests/ -q

# List MCP tools (should report 29 tools)
echo '{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}' | python3 -m ghostmcp

# Inside a running dev container
scripts/build-ghostmcp.sh test
scripts/build-ghostmcp.sh mcp
```
