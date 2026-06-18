# Setting up opencode with MSYS2 and GhostMCP on Windows

Running advanced CLI agents and local MCP proxies on Windows can be tricky due to how Windows handles paths, shell environments, and multiple Python installations. This guide covers how to bridge **opencode**, **MSYS2**, and the **GhostMCP local proxy** for a seamless, high-speed development environment.

## 1. Prerequisites

*   **MSYS2**: Installed at `C:\msys64`. We highly recommend using the **UCRT64** environment for modern, native Windows compatibility.
*   **Python 3**: Installed within the MSYS2 environment (e.g., via `pacman -S mingw-w64-ucrt-x86_64-python mingw-w64-ucrt-x86_64-python-pip`).

> **The Golden Rule of Windows Python:**
> Never rely on the generic `python` or `python3` commands in your `opencode.jsonc` configuration. Depending on how opencode launches the process, it might resolve to the Windows Store wrapper or a different system Python, bypassing your MSYS2 environment completely. Always use **absolute paths** to your Python executable to guarantee you are loading the correct dependencies.

## 2. Installing Proxy Dependencies in MSYS2

The `ghost_client.py` proxy requires `httpx`, `websockets`, and `pyyaml`.

Open your MSYS2 UCRT64 terminal and install these modules using `pip`. Because you are running this inside MSYS2, they will be installed into the MSYS2 Python environment:

```bash
# Inside MSYS2 UCRT64 terminal
python3 -m pip install httpx websockets pyyaml
```

## 3. Configuring opencode for the GhostMCP Proxy

To use GhostMCP's lightning-fast WebSocket local proxy, you must configure `opencode.jsonc` (usually located at `~/.config/opencode/opencode.jsonc`).

Because we installed the modules into the MSYS2 environment in the previous step, we must tell opencode to use the exact MSYS2 Python executable.

Add or update the `GhostMCP-ws` configuration block:

```jsonc
{
  "mcp": {
    "GhostMCP-ws": {
      "type": "local",
      "command": [
        // USE ABSOLUTE PATH TO MSYS2 UCRT64 PYTHON
        "C:/msys64/ucrt64/bin/python3.exe",
        "C:/path/to/GhostMCP/ghost_client.py",
        "--proxy",
        "--config",
        "C:/Users/<User>/.ghost_client.yaml"
      ],
      "enabled": true
    }
  }
}
```

*Note: If you ever decide to use a standard Windows Python installation instead of MSYS2's Python, ensure you update this path (e.g., `C:/Users/<User>/AppData/Local/Programs/Python/Python312/python.exe`) and run the `pip install` command using that specific executable.*

## 4. Teaching opencode to use MSYS2 (The Bash Skill)

By default, opencode on Windows uses PowerShell. To allow opencode to run Unix-like commands (like `ls`, `grep`, `git`, or shell scripts) safely, you need to provide it with an MSYS2 Skill.

Create a file at `~/.config/opencode/skills/msys2-bash/SKILL.md`:

```markdown
# Skill: msys2-bash

# MSYS2 Bash Shell (UCRT64)

This system has MSYS2 installed at `C:\msys64`. All bash/shell commands must be run through MSYS2's UCRT64 environment.

## How to run shell commands

Use `cmd.exe /c` to set the `MSYSTEM` environment variable and invoke MSYS2 bash:

`powershell
cmd.exe /c "set MSYSTEM=UCRT64 && c:\msys64\usr\bin\bash.exe --login -c `"<your command here>`""
`

### Notes
- Always use `--login` so that MSYS2's `/etc/profile` runs and sets up `PATH` correctly.
- Do NOT use `-i` (interactive) when running non-interactively.
- `MSYSTEM=UCRT64` selects the UCRT64 subsystem.
- Escape inner quotes as needed.
```

With this skill loaded, opencode will understand how to properly wrap and execute terminal commands natively through your MSYS2 environment!
