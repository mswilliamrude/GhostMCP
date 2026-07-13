#!/usr/bin/env bash
set -e

# --- Shell Aesthetics (Oh My Bash) ---
if [ ! -d "$HOME/.oh-my-bash" ]; then
  bash -lc "$(curl -fsSL https://raw.githubusercontent.com/ohmybash/oh-my-bash/master/tools/install.sh)" "" --unattended
fi
touch "$HOME/.bashrc"
echo 'OSH_THEME="agnoster"' >> "$HOME/.bashrc"
grep -q 'source $HOME/.oh-my-bash' "$HOME/.bashrc" || echo 'source $HOME/.oh-my-bash/oh-my-bash.sh' >> "$HOME/.bashrc"

# --- Python Environment ---
uv sync --locked --all-groups
. /workspaces/.venv/bin/activate
