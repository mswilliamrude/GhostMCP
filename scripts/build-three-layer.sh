#!/usr/bin/env bash
# GhostMCP Three-Layer Docker Build Script
# 
# Usage:
#   ./build-three-layer.sh base     # System deps + pip (changes rarely)
#   ./build-three-layer.sh render   # Playwright + Chromium (changes monthly)
#   ./build-three-layer.sh app      # Source code only (every commit)
#   ./build-three-layer.sh all      # Full rebuild: base → render → app
#
# Layer dependency: base → render → app
# Only rebuild the layer that changed + everything above it.
#
# When to rebuild each:
#   base:   requirements.txt changed, new system dep added
#   render: Chromium security patch, Playwright version bump
#   app:    Any source code change (fast — just COPY)

set -euo pipefail

# Configuration — override with env vars
ACR_SERVER="${ACR_SERVER:-ghostmcp}"
GIT_COMMIT=$(git rev-parse --short HEAD 2>/dev/null || echo "unknown")
GIT_BRANCH=$(git rev-parse --abbrev-ref HEAD 2>/dev/null || echo "unknown")
BUILD_TIME=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
NO_CACHE="${NO_CACHE:-}"
TAG="${TAG:-latest}"

# Parse flags
while [[ $# -gt 0 ]]; do
    case "$1" in
        --no-cache) NO_CACHE="--no-cache"; shift ;;
        --no-tag) TAG=""; shift ;;
        --tag) TAG="$2"; shift 2 ;;
        base|render|app|all) ACTION="$1"; shift ;;
        *) echo "Unknown arg: $1"; exit 1 ;;
    esac
done

ACTION="${ACTION:-all}"

build_base() {
    echo "=== Building BASE layer (system + pip) ==="
    echo "    This layer changes when: requirements.txt is modified"
    echo ""
    docker build \
        ${NO_CACHE} \
        -f Dockerfile.base \
        -t "${ACR_SERVER}-base:${TAG:-latest}" \
        .
    echo "=== BASE complete ==="
}

build_render() {
    echo "=== Building RENDER layer (Playwright + Chromium) ==="
    echo "    This layer changes when: Chromium needs update (~monthly)"
    echo "    Depends on: ${ACR_SERVER}-base:latest"
    echo ""
    docker build \
        ${NO_CACHE} \
        -f Dockerfile.render \
        --build-arg "ACR_SERVER=${ACR_SERVER}-base" \
        -t "${ACR_SERVER}-render:${TAG:-latest}" \
        .
    echo "=== RENDER complete ==="
}

build_app() {
    echo "=== Building APP layer (source code) ==="
    echo "    This changes on: every commit (fast — just COPY)"
    echo "    Depends on: ${ACR_SERVER}-base:latest (or ${ACR_SERVER}-render:latest)"
    echo ""
    docker build \
        -f Dockerfile \
        --build-arg "ACR_SERVER=${ACR_SERVER}-base" \
        --build-arg "GIT_COMMIT=${GIT_COMMIT}" \
        --build-arg "GIT_BRANCH=${GIT_BRANCH}" \
        --build-arg "BUILD_TIME=${BUILD_TIME}" \
        -t "${ACR_SERVER}:${TAG:-latest}" \
        ${TAG:+-t "${ACR_SERVER}:${GIT_COMMIT}"} \
        .
    echo "=== APP complete (${GIT_COMMIT}) ==="
}

case "$ACTION" in
    base)
        build_base
        ;;
    render)
        build_render
        ;;
    app)
        build_app
        ;;
    all)
        build_base
        build_render
        build_app
        ;;
esac

echo ""
echo "Build complete: ${ACTION}"
echo "  Commit: ${GIT_COMMIT}"
echo "  Branch: ${GIT_BRANCH}"
echo "  Time:   ${BUILD_TIME}"
