# Contributing to GhostMCP

Thanks for contributing! GhostMCP uses a lightweight **trunk-based** workflow:
short-lived branches → pull request → green CI → squash-merge to `main`.

---

## TL;DR

```bash
git checkout main && git pull                 # start from latest main
git checkout -b feat/short-description         # short-lived branch
# ...make changes, commit...
python3 -m pytest tests/ -q                    # run tests locally
git push -u origin feat/short-description
gh pr create                                   # open a PR (CI runs automatically)
# ...address review + CI...
# squash-merge via GitHub, delete the branch
```

Never push directly to `main` — it's protected and requires a PR with passing CI.

---

## Branching

- Branch off `main`. Keep branches **short-lived** and focused on one change.
- Naming: `type/short-description`, e.g.
  - `feat/searxng-metasearch`
  - `fix/render-cert-bypass`
  - `docs/api-keys-reference`
  - `chore/ci-cache`
  - `test/breach-isolation`
- Don't push to someone else's branch. If `main` moved, the branch owner
  syncs their own branch (`git merge main` or rebase) — see *Keeping in sync*.

## Commits

- Use clear, conventional-style subjects: `type(scope): summary`
  (`feat`, `fix`, `docs`, `test`, `chore`, `refactor`, `ci`, `build`).
- Explain **why** in the body, not just what. Reference issues/PRs where useful.
- Make sure your git identity is set so authorship is clean:
  ```bash
  git config --global user.name "Your Name"
  git config --global user.email "you@example.com"
  ```

## Pull requests

- Open a PR against `main`. Fill out the PR template.
- **CI must be green** before merge (the `test` check is required).
- Prefer **Squash and merge** to keep `main` history linear; delete the branch
  after merging.
- Keep PRs reviewably small. Split unrelated changes into separate PRs
  (e.g. don't bundle a feature with an unrelated test-flake fix).

## Keeping in sync

If `main` advanced while you worked:

```bash
git checkout main && git pull
git checkout your-branch
git merge main          # or: git rebase main
# resolve conflicts, re-run tests, push
```

---

## Development setup

Two supported paths — either works.

### Option A — pip / venv (matches CI and the container build)

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
pip install pytest pytest-asyncio
# optional, for render/login/browser tests:
pip install curl_cffi && playwright install chromium
```

### Option B — uv + devcontainer

The `.devcontainer/` uses [`uv`](https://docs.astral.sh/uv/) with `pyproject.toml`
+ `uv.lock`. Open the repo in a devcontainer, or:

```bash
uv sync            # install deps from the lockfile
uv run pytest tests/ -q
```

> `requirements.txt` is a **generated mirror** of `pyproject.toml`'s runtime
> dependencies, kept for the legacy container build and `install.sh`. If you
> change dependencies, update **both** (`uv lock` regenerates the lockfile;
> mirror the runtime pins into `requirements.txt`).

---

## Running things

```bash
# Run the test suite
python3 -m pytest tests/ -q

# List MCP tools over stdio (should report the current tool count)
echo '{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}' | python3 -m ghostmcp

# Container build / dev container / Azure deploy (see INSTALL.md)
scripts/build-ghostmcp.sh help
```

If you have `just`:

```bash
just test      # uv run pytest tests/ -v
just lint      # uv run ruff check .
just format    # uv run ruff format .
just run       # uv run python -m ghostmcp
```

## Tests

- Tests live in `tests/`. Add tests for new behavior and bug fixes.
- Prefer **hermetic** tests: no live network. Mock HTTP (`httpx`) and browser
  (Playwright) calls.
- Watch for **test isolation**: this codebase has some module-level global
  state (engine rate-limiter, the CLIP classifier's model/lock). Reset such
  state in fixtures so tests don't depend on ordering. Don't assume
  `time.monotonic()` is "large" — its zero-point is arbitrary (CI runners have
  low uptime).
- The full suite must pass in CI (Ubuntu, Python 3.12, Playwright installed).

---

## Security — do NOT commit secrets

- **No API keys, tokens, passwords, or private keys** in code, tests, docs, or
  commit history. Use environment variables (`SERPER_API_KEY`, `GHOST_HIBP_KEY`,
  …) and document the **name**, never a real value.
- The repo has **secret scanning + push protection** enabled — a push
  containing a detected secret will be blocked.
- Local secrets belong in git-ignored files (`.env`, `~/.ghost_client.yaml`).
  Never add a real config; commit `*.example` files instead.
- If you ever commit a secret by accident: rotate it immediately, then remove it
  from history — don't just delete it in a later commit.

## Reporting bugs / requesting features

Open a GitHub Issue. For security-sensitive reports, avoid public issues and
contact the maintainer directly.

---

By contributing, you agree your contributions are licensed under the same terms
as the project.
