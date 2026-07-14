# GhostMCP Task Runner

## Development

test:
    uv run pytest tests/ -v

lint:
    uv run ruff check .

format:
    uv run ruff format .

run:
    uv run python -m ghostmcp

clean:
    rm -rf .pytest_cache .ruff_cache .venv
    find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true

## Project

lock:
    uv lock
    @echo "Syncing generated requirements.txt..."

sync:
    uv sync --locked --all-groups
