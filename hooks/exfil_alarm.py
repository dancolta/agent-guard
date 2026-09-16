#!/usr/bin/env python3
"""claude-guard: PermissionDenied hook.

Fires after Claude Code's auto-mode classifier has already denied a tool call.
If the denied call looks like data exfiltration (a network tool combined with a
secret path, or an encode-and-pipe), this hook:

  1. writes a freeze flag for the session (~/.claude/guard/frozen/<session_id>)
  2. shows a macOS dialog with full context and an Unfreeze button

circuit_breaker.py blocks every later tool call in a frozen session.
Denials that do not look like exfiltration are ignored. Nothing is logged.
This hook never blocks by itself and always exits 0.
"""
import json
import os
import re
import subprocess
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from guardctx import describe, dialog_safe  # noqa: E402

HOME = os.path.expanduser("~")
FROZEN_DIR = os.path.join(HOME, ".claude", "guard", "frozen")

NET = re.compile(
    r"\b(curl|wget|nc|ncat|socat|ssh|scp|sftp|rsync|openssl s_client|/dev/tcp|"
    r"python3? -c .*(socket|urllib|requests|http\.client)|"
    r"node -e .*(fetch|http|net)\.)", re.S)
SECRETS = re.compile(
    r"(\.ssh/|\.claude\.json|\.mcp\.json|\.credentials\.json|hosts\.yml|"
    r"Cookies|Keychains|Login Data|chrome-profile|\.env\b|\.netrc|\.npmrc|"
    r"\.aws/|\.kube/|id_rsa|id_ed25519|\.pem\b|security find-)", re.I)
ENCODE_PIPE = re.compile(r"\b(base64|xxd|openssl (enc|base64))\b.*\|", re.S)
SHELL_TOOLS = {"Bash", "PowerShell", "Monitor"}


def looks_like_exfil(tool, tool_input):
    text = json.dumps(tool_input, default=str)
    if tool in SHELL_TOOLS:
        cmd = str(tool_input.get("command", ""))
        return (bool(NET.search(cmd) and SECRETS.search(cmd))
                or bool(ENCODE_PIPE.search(cmd))), cmd
    if tool.startswith("mcp__") or tool == "WebFetch":
        return bool(SECRETS.search(text)) and len(text) > 200, text
    return False, text


def main():
    try:
        data = json.load(sys.stdin)
    except Exception:
        return 0
    sid = str(data.get("session_id", "")) or "unknown"
    if not re.fullmatch(r"[A-Za-z0-9_.-]{1,128}", sid):
        return 0
    tool = str(data.get("tool_name", "?"))
    tool_input = data.get("tool_input", {}) or {}
    exfil, shown = looks_like_exfil(tool, tool_input)
    if not exfil:
        return 0

    flag = os.path.join(FROZEN_DIR, sid)
    reason = (f"{time.strftime('%Y-%m-%d %H:%M')}\n{describe(data)}\n"
              f"Blocked tool: {tool}\n\n{shown[:600]}")
    try:
        os.makedirs(FROZEN_DIR, mode=0o700, exist_ok=True)
        with open(flag, "w", encoding="utf-8") as f:
            f.write(reason + "\n")
        os.chmod(flag, 0o600)
    except Exception:
        pass

    script = (
        'set r to display dialog "An agent tried something that looks like data '
        f'exfiltration. That session is frozen.\\n\\n{dialog_safe(reason)}" '
        'with title "Claude agent alarm" buttons {"Keep frozen", "Unfreeze"} '
        'default button "Keep frozen" with icon stop\n'
        'if button returned of r is "Unfreeze" then do shell script '
        f'"rm -f " & quoted form of "{flag}"'
    )
    try:
        subprocess.Popen(["/usr/bin/osascript", "-e", script], start_new_session=True,
                         stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                         stderr=subprocess.DEVNULL)
    except Exception:
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
