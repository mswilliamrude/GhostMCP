# GhostMCP — DevContainer Setup Stories

## Story 1: Install Python Dependencies in DevContainer

**As a** developer working on GhostMCP  
**I want** all project dependencies installed inside the devcontainer  
**So that** I can start coding without manual setup

**Acceptance Criteria:**
- [ ] `.devcontainer/devcontainer.json` references `mcr.microsoft.com/devcontainers/python` as base image
- [ ] All requirements from `requirements.txt` / `pyproject.toml` are installed via `postCreateCommand` or Dockerfile
- [ ] `python3 -c "import ghostmcp"` succeeds inside the container

---

## Story 2: Reach External Model Providers from the Container

**As a** developer who runs Ollama or other model providers on my host machine  
**I want** the devcontainer to reach those services via `host.docker.internal`  
**So that** I can develop and test against them without extra config

**Acceptance Criteria:**
- [ ] `runArgs` in `devcontainer.json` includes `--add-host=host.docker.internal:host-gateway`
- [ ] `curl http://host.docker.internal:11434/api/tags` from inside the container returns model list
- [ ] No additional network setup is required

---

## Story 3: Override Config for Local Development

**As a** developer who switches between local Ollama and cloud APIs (e.g., Perplexity)  
**I want** a git-ignored `devcontainer.local.json` that overlays on top of the base config  
**So that** I can change keys or endpoints without touching tracked code

**Acceptance Criteria:**
- [ ] `.devcontainer/devcontainer.local.json` exists and is listed in `.gitignore`
- [ ] `config.py` loads the base config and merges any keys from `devcontainer.local.json`
- [ ] Changing `OLLAMA_HOST` or `GHOST_PERPLEXITY_KEY` takes effect after container restart
- [ ] No tracked config files are modified

---

## Story 4: Auto-Verify Provider Connectivity on Container Start

**As a** developer opening GhostMCP  
**I want** a healthcheck that runs when the container is created  
**So that** I instantly know whether my configured model provider is reachable or misconfigured

**Acceptance Criteria:**
- [ ] A `postCreateCommand` script executes on first container open
- [ ] The script tests the configured provider and prints `"OK"` or `"FAIL"`
- [ ] On success, terminal displays `"AI Provider Connected!"`
- [ ] On failure, the message states which provider failed and what was checked

---

## Suggested Order (Dependencies)

| # | Story | Depends On |
|---|-------|------------|
| 1 | Install Python Dependencies | — |
| 2 | Reach External Providers | Story 1 |
| 3 | Override Config for Dev | — (can do anytime) |
| 4 | Auto-Verify Provider | Stories 2 + 3 |

Critical path: **1 → 2 → 4**. Story 3 is independent.
