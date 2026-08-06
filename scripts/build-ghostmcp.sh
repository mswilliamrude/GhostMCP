#!/bin/bash
# build-ghostmcp.sh — Build, run, test, and manage GhostMCP container
#
# Usage:
#   build-ghostmcp build              Build the Docker image
#   build-ghostmcp run                Start persistent container (background)
#   build-ghostmcp stop               Stop and remove container
#   build-ghostmcp restart            Stop + run
#   build-ghostmcp status             Show container status
#   build-ghostmcp logs               Show container logs
#   build-ghostmcp ssh                SSH into running container
#   build-ghostmcp test               Run test suite inside container
#   build-ghostmcp mcp                Test MCP tools/list response
#   build-ghostmcp shell              Interactive bash inside container
#   build-ghostmcp sync               Copy local ghostmcp/ into running container
#   build-ghostmcp pull               Copy container /app/ghostmcp/ to local ghostmcp/
#   build-ghostmcp deploy             Build + deploy to Azure Container Instances
#   build-ghostmcp teardown           Delete ACI container group
#
# This script lives in <repo>/scripts/ and resolves the repo root as its
# parent directory. All Docker build contexts are the repo root, and every
# Dockerfile (Dockerfile, Dockerfile.base, Dockerfile.layer*, Dockerfile.render)
# lives at the repo root.
#
# Environment:
#   GHOST_ROOT          Repo root override (default: parent of scripts/)
#   GHOST_IMAGE         Docker image name (default: ghostmcp:latest)
#   GHOST_CONTAINER     Container name (default: ghostmcp-dev)
#   GHOST_SSH_PORT      Local SSH port mapping (default: 2222)
#   GHOST_ACR           ACR server (set via GHOST_ACR_NAME env var)

set -euo pipefail

# --- Platform detection ---
detect_platform() {
    case "$(uname -s)" in
        MINGW*|MSYS*|CYGWIN*) echo "msys2" ;;
        Linux) echo "linux" ;;
        Darwin) echo "macos" ;;
        *) echo "unknown" ;;
    esac
}
PLATFORM=$(detect_platform)

# Check for Azure CLI
HAS_AZ=false
if command -v az &>/dev/null; then
    HAS_AZ=true
fi

# --- Container runtime detection ---
# Priority: --podman flag > --azure flag > az acr (Windows + Azure) > docker > podman
# Falls back to podman if docker isn't available (rootless, no sudo needed)
FORCE_PODMAN=false
FORCE_AZURE=false
for arg in "$@"; do
    case "$arg" in
        --podman) FORCE_PODMAN=true ;;
        --azure)  FORCE_AZURE=true ;;
    esac
done

detect_container_runtime() {
    if [ "$FORCE_PODMAN" = true ]; then
        if command -v podman &>/dev/null; then
            echo "podman"
        else
            echo "[ERROR] --podman requested but podman not found" >&2
            echo "none"
        fi
        return
    fi
    if [ "$FORCE_AZURE" = true ]; then
        if [ "$HAS_AZ" = true ]; then
            echo "az"  # Azure ACR build (forced)
        else
            echo "[ERROR] --azure requested but Azure CLI (az) not found" >&2
            echo "none"
        fi
        return
    fi
    if [ "$HAS_AZ" = true ] && [ "$PLATFORM" = "msys2" ]; then
        echo "az"  # Azure ACR builds from Windows
        return
    fi
    if command -v docker &>/dev/null; then
        # Check if docker actually works (daemon running, permissions ok)
        if sudo docker info &>/dev/null 2>&1; then
            echo "docker"
            return
        fi
        # Docker exists but daemon not running — try podman
        if command -v podman &>/dev/null; then
            echo "podman"
            return
        fi
        # Docker exists but broken, no podman fallback
        echo "docker"
        return
    fi
    if command -v podman &>/dev/null; then
        echo "podman"
        return
    fi
    echo "none"
}

CONTAINER_RUNTIME=$(detect_container_runtime)

# Set the runtime command — podman doesn't need sudo
case "$CONTAINER_RUNTIME" in
    docker) CTR="sudo docker" ;;
    podman) CTR="podman" ;;
    az)     CTR="sudo docker" ;;  # Local operations still use docker on az systems
    none)
        echo "[ERROR] No container runtime found."
        echo "        Install one of: docker, podman"
        echo "        On Fedora/RHEL: sudo dnf install podman"
        echo "        On Ubuntu/Debian: sudo apt install podman"
        exit 1
        ;;
esac

# --- Configuration ---
GHOST_IMAGE="${GHOST_IMAGE:-ghostmcp:latest}"
GHOST_IMAGE_BASE="${GHOST_IMAGE_BASE:-ghostmcp-base:latest}"
GHOST_CONTAINER="${GHOST_CONTAINER:-ghostmcp-dev}"
GHOST_SSH_PORT="${GHOST_SSH_PORT:-2222}"

# --- ACR / ACI configuration ---
# All values configurable via environment variables. No defaults for
# subscription, resource group, or network — must be set explicitly
# for Azure deployments. Podman builds don't need these.
GHOST_ACR_NAME="${GHOST_ACR_NAME:-}"
GHOST_ACR_SERVER="${GHOST_ACR_NAME:+${GHOST_ACR_NAME}.azurecr.io}"
GHOST_ACR_IMAGE="${GHOST_ACR_IMAGE:-ghostmcp}"
GHOST_ACR_IMAGE_BASE="${GHOST_ACR_IMAGE_BASE:-ghostmcp-base}"
GHOST_SUBSCRIPTION="${GHOST_SUBSCRIPTION:-}"
GHOST_RESOURCE_GROUP="${GHOST_RESOURCE_GROUP:-}"
GHOST_LOCATION="${GHOST_LOCATION:-centralus}"
GHOST_VNET="${GHOST_VNET:-}"
GHOST_SUBNET="${GHOST_SUBNET:-}"
GHOST_CONTAINER_GROUP="${GHOST_CONTAINER_GROUP:-ghostmcp-app}"

# --- Resolve repo root ---
# This script lives in <repo>/scripts/. The repo root is its parent directory.
# The root must contain the app Dockerfile and the ghostmcp/ package.
resolve_repo_root() {
    if [ -n "${GHOST_ROOT:-}" ]; then
        echo "$GHOST_ROOT"
        return
    fi
    local script_dir
    script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    local root
    root="$(cd "$script_dir/.." && pwd)"
    if [ -f "$root/Dockerfile" ] && [ -d "$root/ghostmcp" ]; then
        echo "$root"
        return
    fi
    # Fallback: check cwd (allows running from repo root directly)
    if [ -f "./Dockerfile" ] && [ -d "./ghostmcp" ]; then
        echo "$(pwd)"
        return
    fi
    echo ""
}

REPO_ROOT=$(resolve_repo_root)
if [ -z "$REPO_ROOT" ]; then
    echo "[ERROR] Cannot find GhostMCP repo root."
    echo "        This script expects to live in <repo>/scripts/ with the"
    echo "        Dockerfile and ghostmcp/ package at the repo root, or set"
    echo "        GHOST_ROOT=/path/to/GhostMCP"
    exit 1
fi

# Backward-compat alias: existing command bodies reference SRC_DIR.
SRC_DIR="$REPO_ROOT"

echo "[INFO] Repo root: $REPO_ROOT"

# --- Helper functions ---
container_running() {
    $CTR inspect -f '{{.State.Running}}' "$GHOST_CONTAINER" 2>/dev/null | grep -q "true"
}

container_exists() {
    $CTR inspect "$GHOST_CONTAINER" &>/dev/null
}

# --- Commands ---

cmd_build() {
    local target="${2:-app}"
    local no_cache_flag=""
    if [ "${3:-}" = "--no-cache" ] || [ "${2:-}" = "--no-cache" ]; then
        no_cache_flag="--no-cache"
        # If --no-cache was $2, default target to app
        if [ "${2:-}" = "--no-cache" ]; then target="app"; fi
    fi

    case "$target" in
        base)  _build_base "$no_cache_flag" ;;
        app)   _build_app "$no_cache_flag" ;;
        all)   _build_base "$no_cache_flag" && _build_app "$no_cache_flag" ;;
        *)     echo "[ERROR] Unknown build target: $target (use: base, app, all)"; exit 1 ;;
    esac
}

_build_base() {
    local no_cache_flag="${1:-}"
    if [ "$CONTAINER_RUNTIME" = "az" ]; then
        echo "[INFO] Building ${GHOST_ACR_IMAGE_BASE}:latest via ACR..."
        pushd "$SRC_DIR" >/dev/null
        az acr build \
            --registry "$GHOST_ACR_NAME" \
            --image "${GHOST_ACR_IMAGE_BASE}:latest" \
            --subscription "$GHOST_SUBSCRIPTION" \
            --platform "linux" \
            --file "Dockerfile.base" \
            ${no_cache_flag:+--no-cache} \
            .
        popd >/dev/null
        echo "[INFO] Base image built: ${GHOST_ACR_SERVER}/${GHOST_ACR_IMAGE_BASE}:latest"
    else
        echo "[INFO] Building base image locally: $GHOST_IMAGE_BASE (runtime: $CONTAINER_RUNTIME)"
        $CTR build -t "$GHOST_IMAGE_BASE" \
            -f "$SRC_DIR/Dockerfile.base" \
            ${no_cache_flag:+--no-cache} \
            "$SRC_DIR"
        echo "[INFO] Base built: $($CTR images "${GHOST_IMAGE_BASE%:*}" --format '{{.Size}}' 2>/dev/null || echo 'unknown')"
    fi
}

_build_app() {
    local no_cache_flag="${1:-}"
    local git_commit=$(git rev-parse --short HEAD 2>/dev/null || echo "unknown")
    local git_branch=$(git branch --show-current 2>/dev/null || echo "unknown")
    local build_time=$(date -u +%Y-%m-%dT%H:%M:%SZ)

    if [ "$CONTAINER_RUNTIME" = "az" ]; then
        echo "[INFO] Building ${GHOST_ACR_IMAGE}:latest via ACR (using ${GHOST_ACR_IMAGE_BASE}:latest)..."
        pushd "$SRC_DIR" >/dev/null
        az acr build \
            --registry "$GHOST_ACR_NAME" \
            --image "${GHOST_ACR_IMAGE}:latest" \
            --subscription "$GHOST_SUBSCRIPTION" \
            --platform "linux" \
            --file "Dockerfile" \
            --build-arg "ACR_SERVER=${GHOST_ACR_SERVER}/${GHOST_ACR_IMAGE_BASE}" \
            --build-arg "GIT_COMMIT=$git_commit" \
            --build-arg "GIT_BRANCH=$git_branch" \
            --build-arg "BUILD_TIME=$build_time" \
            --build-arg "CACHE_BUST=$(date +%s)" \
            ${no_cache_flag:+--no-cache} \
            .
        popd >/dev/null
        echo "[INFO] App image built: ${GHOST_ACR_SERVER}/${GHOST_ACR_IMAGE}:latest"
    else
        echo "[INFO] Building app image locally: $GHOST_IMAGE (runtime: $CONTAINER_RUNTIME)"
        $CTR build -t "$GHOST_IMAGE" \
            -f "$SRC_DIR/Dockerfile" \
            --build-arg "ACR_SERVER=${GHOST_IMAGE_BASE%:*}" \
            --build-arg "GIT_COMMIT=$git_commit" \
            --build-arg "GIT_BRANCH=$git_branch" \
            --build-arg "BUILD_TIME=$build_time" \
            --build-arg "CACHE_BUST=$(date +%s)" \
            ${no_cache_flag:+--no-cache} \
            "$SRC_DIR"
        echo "[INFO] App built: $($CTR images "${GHOST_IMAGE%:*}" --format '{{.Size}}' 2>/dev/null || echo 'unknown')"
    fi
}

cmd_run() {
    if container_running; then
        echo "[INFO] Container $GHOST_CONTAINER already running"
        echo "       SSH: ssh -p $GHOST_SSH_PORT root@localhost"
        return
    fi

    if container_exists; then
        echo "[INFO] Starting existing container $GHOST_CONTAINER"
        $CTR start "$GHOST_CONTAINER"
    else
        echo "[INFO] Creating and starting $GHOST_CONTAINER (runtime: $CONTAINER_RUNTIME)"
        $CTR run -d \
            --name "$GHOST_CONTAINER" \
            -p "${GHOST_SSH_PORT}:22" \
            -v /tmp/ghostmcp_ratelimit:/tmp/ghostmcp_ratelimit \
            --add-host=host.docker.internal:host-gateway \
            --restart unless-stopped \
            "$GHOST_IMAGE"
    fi

    # Wait for SSH to be ready
    echo -n "[INFO] Waiting for SSH..."
    for i in $(seq 1 10); do
        if ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
           -o ConnectTimeout=2 -p "$GHOST_SSH_PORT" root@localhost "true" 2>/dev/null; then
            echo " ready!"
            echo "[INFO] SSH: ssh -p $GHOST_SSH_PORT root@localhost"
            return
        fi
        echo -n "."
        sleep 1
    done
    echo " timeout (container may still be starting)"
}

cmd_stop() {
    if container_exists; then
        echo "[INFO] Stopping and removing $GHOST_CONTAINER"
        $CTR rm -f "$GHOST_CONTAINER"
    else
        echo "[INFO] Container $GHOST_CONTAINER not found"
    fi
}

cmd_restart() {
    cmd_stop
    sleep 1
    cmd_run
}

cmd_status() {
    echo "[INFO] === GhostMCP Container Status ==="
    echo "Runtime: $CONTAINER_RUNTIME ($CTR)"
    if container_running; then
        echo "State:     Running"
        echo "Container: $GHOST_CONTAINER"
        echo "Image:     $GHOST_IMAGE"
        echo "SSH:       ssh -p $GHOST_SSH_PORT root@localhost"
        echo ""
        echo "Ports:"
        $CTR port "$GHOST_CONTAINER" 2>/dev/null | sed 's/^/  /'
        echo ""
        echo "Uptime:"
        $CTR inspect -f '{{.State.StartedAt}}' "$GHOST_CONTAINER" | sed 's/^/  Started: /'
    elif container_exists; then
        echo "State:     Stopped"
        echo "Container: $GHOST_CONTAINER exists but is not running"
        echo "Run:       build-ghostmcp run"
    else
        echo "State:     Not created"
        echo "Build:     build-ghostmcp build"
        echo "Run:       build-ghostmcp run"
    fi
}

cmd_logs() {
    if container_exists; then
        $CTR logs --tail 50 "$GHOST_CONTAINER"
    else
        echo "[ERROR] Container $GHOST_CONTAINER not found"
        exit 1
    fi
}

cmd_ssh() {
    if ! container_running; then
        echo "[ERROR] Container $GHOST_CONTAINER is not running. Run: build-ghostmcp run"
        exit 1
    fi
    ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
        -p "$GHOST_SSH_PORT" root@localhost
}

cmd_test() {
    if ! container_running; then
        echo "[ERROR] Container $GHOST_CONTAINER is not running"
        exit 1
    fi
    echo "[INFO] Running test suite inside container..."
    ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
        -p "$GHOST_SSH_PORT" root@localhost \
        "cd /app && python3 -m pytest tests/ -v --tb=short"
}

cmd_mcp() {
    if ! container_running; then
        echo "[ERROR] Container $GHOST_CONTAINER is not running"
        exit 1
    fi
    echo "[INFO] Testing MCP tools/list..."
    echo '{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}' | \
        $CTR exec -i "$GHOST_CONTAINER" python3 -m ghostmcp 2>/dev/null | \
        python3 -c "
import json, sys
data = json.load(sys.stdin)
tools = data['result']['tools']
print(f'MCP Tools: {len(tools)}')
for t in tools:
    print(f'  - {t[\"name\"]}: {t[\"description\"][:60]}...')
"
}

cmd_shell() {
    if ! container_running; then
        echo "[ERROR] Container $GHOST_CONTAINER is not running"
        exit 1
    fi
    $CTR exec -it "$GHOST_CONTAINER" /bin/bash
}

cmd_sync() {
    if ! container_running; then
        echo "[ERROR] Container $GHOST_CONTAINER is not running"
        exit 1
    fi
    echo "[INFO] Syncing local ghostmcp/ → container /app/ghostmcp/"
    scp -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
        -P "$GHOST_SSH_PORT" -r "$SRC_DIR/ghostmcp/" root@localhost:/app/ghostmcp/
    echo "[INFO] Syncing local tests/ → container /app/tests/"
    scp -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
        -P "$GHOST_SSH_PORT" -r "$SRC_DIR/tests/" root@localhost:/app/tests/
    echo "[INFO] Sync complete. Run 'build-ghostmcp test' to verify."
}

cmd_pull() {
    if ! container_running; then
        echo "[ERROR] Container $GHOST_CONTAINER is not running"
        exit 1
    fi
    echo "[INFO] Pulling container /app/ghostmcp/ → local ghostmcp/"
    scp -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
        -P "$GHOST_SSH_PORT" -r root@localhost:/app/ghostmcp/ "$SRC_DIR/ghostmcp/"
    echo "[INFO] Pulling container /app/tests/ → local tests/"
    scp -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
        -P "$GHOST_SSH_PORT" -r root@localhost:/app/tests/ "$SRC_DIR/tests/"
    echo "[INFO] Pull complete. Review changes with 'git diff'."
}

cmd_deploy() {
    if [ "$HAS_AZ" != true ]; then
        echo "[ERROR] Azure CLI (az) not found. Install: https://aka.ms/installazurecli"
        exit 1
    fi

    echo "[INFO] Deploying GhostMCP to ACI ($GHOST_CONTAINER_GROUP)..."

    # Resolve subscription ID for subnet path
    local SUB_ID
    SUB_ID=$(az account show --subscription "$GHOST_SUBSCRIPTION" --query id -o tsv)
    if [ -z "$SUB_ID" ]; then
        echo "[ERROR] Failed to resolve subscription ID"
        exit 1
    fi
    local GHOST_SUBNET_ID="/subscriptions/${SUB_ID}/resourceGroups/${GHOST_RESOURCE_GROUP}/providers/Microsoft.Network/virtualNetworks/${GHOST_VNET}/subnets/${GHOST_SUBNET}"
    echo "[INFO] Subnet: $GHOST_SUBNET_ID"

    # Get ACR credentials
    local ACR_PW
    ACR_PW=$(az acr credential show --name "$GHOST_ACR_NAME" --subscription "$GHOST_SUBSCRIPTION" --query "passwords[0].value" -o tsv)

    local DEPLOY_YAML="$REPO_ROOT/deploy-ghostmcp.yaml"
    trap "rm -f '$DEPLOY_YAML'" RETURN

    cat > "$DEPLOY_YAML" <<EOF
apiVersion: 2021-09-01
location: ${GHOST_LOCATION}
name: ${GHOST_CONTAINER_GROUP}
type: Microsoft.ContainerInstance/containerGroups
properties:
  osType: Linux
  subnetIds:
    - id: ${GHOST_SUBNET_ID}
  imageRegistryCredentials:
    - server: ${GHOST_ACR_SERVER}
      username: ${GHOST_ACR_NAME}
      password: ${ACR_PW}
  containers:
    - name: ghostmcp
      properties:
        image: ${GHOST_ACR_SERVER}/${GHOST_ACR_IMAGE}:latest
        ports:
          - port: 8080
            protocol: TCP
          - port: 22
            protocol: TCP
        resources:
          requests:
            cpu: 1
            memoryInGB: 2
        environmentVariables:
          - name: GHOST_PARANOIA
            value: "cautious"
          - name: GHOST_MIN_DELAY
            value: "2.0"
          - name: GHOST_MODE
            value: "server"
  ipAddress:
    type: Private
    ports:
      - port: 8080
        protocol: TCP
      - port: 22
        protocol: TCP
EOF

    az container delete \
        --resource-group "$GHOST_RESOURCE_GROUP" \
        --subscription "$GHOST_SUBSCRIPTION" \
        --name "$GHOST_CONTAINER_GROUP" \
        --yes 2>/dev/null || true

    az container create \
        --resource-group "$GHOST_RESOURCE_GROUP" \
        --subscription "$GHOST_SUBSCRIPTION" \
        --file "$DEPLOY_YAML"

    echo "[INFO] Deployed. Waiting for container to start..."

    # Wait loop
    for i in $(seq 1 30); do
        state=$(az container show \
            --resource-group "$GHOST_RESOURCE_GROUP" \
            --subscription "$GHOST_SUBSCRIPTION" \
            --name "$GHOST_CONTAINER_GROUP" \
            --query 'instanceView.state' -o tsv 2>/dev/null)
        if [ "$state" = "Running" ]; then
            local ip=$(az container show \
                --resource-group "$GHOST_RESOURCE_GROUP" \
                --subscription "$GHOST_SUBSCRIPTION" \
                --name "$GHOST_CONTAINER_GROUP" \
                --query 'ipAddress.ip' -o tsv)
            echo "[INFO] GhostMCP running at $ip"
            return
        fi
        echo -n "."
        sleep 5
    done
    echo " timeout"
}

cmd_teardown() {
    if [ "$HAS_AZ" != true ]; then
        echo "[ERROR] Azure CLI (az) not found"
        exit 1
    fi
    echo "[INFO] Tearing down $GHOST_CONTAINER_GROUP..."
    az container delete \
        --resource-group "$GHOST_RESOURCE_GROUP" \
        --subscription "$GHOST_SUBSCRIPTION" \
        --name "$GHOST_CONTAINER_GROUP" \
        --yes
    echo "[INFO] Deleted."
}

# --- Main dispatch ---
# Strip runtime flags from args before dispatching
ARGS=()
for arg in "$@"; do
    case "$arg" in
        --podman|--azure) ;;  # consumed during runtime detection
        *) ARGS+=("$arg") ;;
    esac
done
set -- "${ARGS[@]:-help}"

case "${1:-help}" in
    build)    cmd_build "$@" ;;
    run)      cmd_run ;;
    stop)     cmd_stop ;;
    restart)  cmd_restart ;;
    status)   cmd_status ;;
    logs)     cmd_logs ;;
    ssh)      cmd_ssh ;;
    test)     cmd_test ;;
    mcp)      cmd_mcp ;;
    shell)    cmd_shell ;;
    sync)     cmd_sync ;;
    pull)     cmd_pull ;;
    deploy)   cmd_deploy ;;
    teardown)  cmd_teardown ;;
    help|*)
        echo "build-ghostmcp — Build, run, test, and manage GhostMCP container"
        echo ""
        echo "Usage: build-ghostmcp <command> [target] [options]"
        echo ""
        echo "Commands:"
        echo "  build [target]  Build container image (target: base, app, all. Default: app)"
        echo "  run             Start persistent container (background + SSH)"
        echo "  stop            Stop and remove container"
        echo "  restart         Stop + run"
        echo "  status          Show container status"
        echo "  logs            Show container logs (last 50 lines)"
        echo "  ssh             SSH into running container"
        echo "  test            Run test suite inside container"
        echo "  mcp             Test MCP tool listing"
        echo "  shell           Interactive bash inside container"
        echo "  sync            Push local ghostmcp/ + tests/ into container"
        echo "  pull            Pull container ghostmcp/ + tests/ to local"
        echo "  deploy          Deploy to Azure Container Instances"
        echo "  teardown        Delete ACI container group"
        echo ""
        echo "Options:"
        echo "  --podman        Force podman runtime (overrides auto-detection)"
        echo "  --azure         Force Azure ACR build (requires az CLI)"
        echo "  --no-cache      Build without layer cache"
        echo ""
        echo "Build targets:"
        echo "  base            OS + Python deps + Playwright + Chromium (slow, changes rarely)"
        echo "  app             App code only on top of base (fast, every commit)"
        echo "  all             Build base then app"
        echo ""
        echo "Runtime detection (current: $CONTAINER_RUNTIME):"
        echo "  1. --podman flag → podman (forced)"
        echo "  2. --azure flag → Azure ACR remote build (forced)"
        echo "  3. Windows + az CLI → Azure ACR remote build"
        echo "  4. docker daemon running → docker (with sudo)"
        echo "  5. podman available → podman (rootless, no sudo)"
        echo ""
        echo "Examples:"
        echo "  scripts/build-ghostmcp.sh build base            # Build heavy base image"
        echo "  scripts/build-ghostmcp.sh build                  # Rebuild app layer (fast)"
        echo "  scripts/build-ghostmcp.sh build all --no-cache   # Full rebuild, no cache"
        echo "  scripts/build-ghostmcp.sh build --podman         # Force podman for build"
        echo "  scripts/build-ghostmcp.sh build --azure          # Force Azure ACR build"
        echo "  scripts/build-ghostmcp.sh run --podman           # Run container with podman"
        echo ""
        echo "Platform: $PLATFORM | Runtime: $CONTAINER_RUNTIME | az cli: $HAS_AZ"
        echo ""
        echo "Environment:"
        echo "  GHOST_IMAGE=$GHOST_IMAGE"
        echo "  GHOST_IMAGE_BASE=$GHOST_IMAGE_BASE"
        echo "  GHOST_CONTAINER=$GHOST_CONTAINER"
        echo "  GHOST_SSH_PORT=$GHOST_SSH_PORT"
        echo "  GHOST_ACR_NAME=$GHOST_ACR_NAME"
        echo "  GHOST_ACR_IMAGE=$GHOST_ACR_IMAGE"
        echo "  GHOST_ACR_IMAGE_BASE=$GHOST_ACR_IMAGE_BASE"
        echo "  GHOST_SUBSCRIPTION=$GHOST_SUBSCRIPTION"
        echo "  GHOST_CONTAINER_GROUP=$GHOST_CONTAINER_GROUP"
        ;;
esac
