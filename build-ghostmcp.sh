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
#   build-ghostmcp sync               Copy local src/ into running container
#   build-ghostmcp pull               Copy container /app/src/ to local src/
#   build-ghostmcp deploy             Push to ACR and deploy (future)
#
# Environment:
#   GHOST_IMAGE         Docker image name (default: ghostmcp:latest)
#   GHOST_CONTAINER     Container name (default: ghostmcp-dev)
#   GHOST_SSH_PORT      Local SSH port mapping (default: 2222)
#   GHOST_ACR           ACR server (default: wdrcentralus.azurecr.io)

set -euo pipefail

# --- Configuration ---
GHOST_IMAGE="${GHOST_IMAGE:-ghostmcp:latest}"
GHOST_CONTAINER="${GHOST_CONTAINER:-ghostmcp-dev}"
GHOST_SSH_PORT="${GHOST_SSH_PORT:-2222}"
GHOST_ACR="${GHOST_ACR:-wdrcentralus.azurecr.io}"

# --- Resolve source directory ---
resolve_src_dir() {
    if [ -n "${GHOST_SRC:-}" ]; then
        echo "$GHOST_SRC"
        return
    fi
    local script_dir
    script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    if [ -f "$script_dir/Dockerfile" ] && [ -d "$script_dir/src" ]; then
        echo "$script_dir"
        return
    fi
    # Check cwd
    if [ -f "./Dockerfile" ] && [ -d "./src" ]; then
        echo "$(pwd)"
        return
    fi
    echo ""
}

SRC_DIR=$(resolve_src_dir)
if [ -z "$SRC_DIR" ]; then
    echo "[ERROR] Cannot find GhostMCP source directory."
    echo "        Run from the GhostMCP repo root or set GHOST_SRC=/path/to/GhostMCP"
    exit 1
fi

echo "[INFO] Working directory: $SRC_DIR"

# --- Helper functions ---
container_running() {
    sudo docker inspect -f '{{.State.Running}}' "$GHOST_CONTAINER" 2>/dev/null | grep -q "true"
}

container_exists() {
    sudo docker inspect "$GHOST_CONTAINER" &>/dev/null
}

# --- Commands ---

cmd_build() {
    echo "[INFO] Building $GHOST_IMAGE from $SRC_DIR"
    sudo docker build -t "$GHOST_IMAGE" "$SRC_DIR"
    echo "[INFO] Build complete: $(sudo docker images "$GHOST_IMAGE" --format '{{.Size}}')"
}

cmd_run() {
    if container_running; then
        echo "[INFO] Container $GHOST_CONTAINER already running"
        echo "       SSH: ssh -p $GHOST_SSH_PORT root@localhost"
        return
    fi

    if container_exists; then
        echo "[INFO] Starting existing container $GHOST_CONTAINER"
        sudo docker start "$GHOST_CONTAINER"
    else
        echo "[INFO] Creating and starting $GHOST_CONTAINER"
        sudo docker run -d \
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
        sudo docker rm -f "$GHOST_CONTAINER"
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
    if container_running; then
        echo "State:     Running"
        echo "Container: $GHOST_CONTAINER"
        echo "Image:     $GHOST_IMAGE"
        echo "SSH:       ssh -p $GHOST_SSH_PORT root@localhost"
        echo ""
        echo "Ports:"
        sudo docker port "$GHOST_CONTAINER" 2>/dev/null | sed 's/^/  /'
        echo ""
        echo "Uptime:"
        sudo docker inspect -f '{{.State.StartedAt}}' "$GHOST_CONTAINER" | sed 's/^/  Started: /'
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
        sudo docker logs --tail 50 "$GHOST_CONTAINER"
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
        sudo docker exec -i "$GHOST_CONTAINER" python3 -m src 2>/dev/null | \
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
    sudo docker exec -it "$GHOST_CONTAINER" /bin/bash
}

cmd_sync() {
    if ! container_running; then
        echo "[ERROR] Container $GHOST_CONTAINER is not running"
        exit 1
    fi
    echo "[INFO] Syncing local src/ → container /app/src/"
    scp -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
        -P "$GHOST_SSH_PORT" -r "$SRC_DIR/src/" root@localhost:/app/src/
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
    echo "[INFO] Pulling container /app/src/ → local src/"
    scp -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
        -P "$GHOST_SSH_PORT" -r root@localhost:/app/src/ "$SRC_DIR/src/"
    echo "[INFO] Pulling container /app/tests/ → local tests/"
    scp -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
        -P "$GHOST_SSH_PORT" -r root@localhost:/app/tests/ "$SRC_DIR/tests/"
    echo "[INFO] Pull complete. Review changes with 'git diff'."
}

cmd_deploy() {
    echo "[INFO] === Deploy to Azure Container Registry ==="
    echo ""
    echo "Steps:"
    echo "  1. az acr login --name $GHOST_ACR"
    echo "  2. docker tag $GHOST_IMAGE ${GHOST_ACR}/ghostmcp:latest"
    echo "  3. docker push ${GHOST_ACR}/ghostmcp:latest"
    echo ""
    echo "Not implemented yet — run these manually when ready for release."
    echo "Or add ACI deployment YAML here (same pattern as build-unimind.sh)."
}

# --- Main dispatch ---
case "${1:-help}" in
    build)    cmd_build ;;
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
    help|*)
        echo "build-ghostmcp — Build, run, test, and manage GhostMCP container"
        echo ""
        echo "Usage: build-ghostmcp <command>"
        echo ""
        echo "Commands:"
        echo "  build     Build Docker image"
        echo "  run       Start persistent container (background + SSH)"
        echo "  stop      Stop and remove container"
        echo "  restart   Stop + run"
        echo "  status    Show container status"
        echo "  logs      Show container logs (last 50 lines)"
        echo "  ssh       SSH into running container"
        echo "  test      Run test suite inside container"
        echo "  mcp       Test MCP tool listing"
        echo "  shell     Interactive bash inside container"
        echo "  sync      Push local src/ + tests/ into container"
        echo "  pull      Pull container src/ + tests/ to local"
        echo "  deploy    Show ACR deployment instructions"
        echo ""
        echo "Environment:"
        echo "  GHOST_IMAGE=$GHOST_IMAGE"
        echo "  GHOST_CONTAINER=$GHOST_CONTAINER"
        echo "  GHOST_SSH_PORT=$GHOST_SSH_PORT"
        echo "  GHOST_ACR=$GHOST_ACR"
        ;;
esac
