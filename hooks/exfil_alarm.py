#!/usr/bin/env python3
"""claude-guard: PermissionDenied hook.

Fires after Claude Code's auto-mode classifier has already denied a tool call.
If the denied call looks like data exfiltration (a network sink combined with a
secret path, or an encode-and-pipe into a network sink), this hook:

  1. writes a freeze flag for the session (~/.claude/guard/frozen/<session_id>)
  2. shows a macOS dialog with full context and an Unfreeze button

circuit_breaker.py blocks every later tool call in a frozen session. Denials
that do not look like exfiltration are ignored. Nothing is logged; the flag
file (0600) holds the blocked command until the session is unfrozen.
This hook never blocks by itself and always exits 0.
"""
import json
import os
import re
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from guardctx import describe, dialog_safe, run_applescript, valid_sid  # noqa: E402

HOME = os.path.expanduser("~")
GUARD_DIR = os.path.join(HOME, ".claude", "guard")
FROZEN_DIR = os.path.join(GUARD_DIR, "frozen")

W = r"(?![\w-])"  # token boundary that also rejects ssh-keygen, ncdu, etc.
NET = re.compile(
    r"(\b(curl|wget|nc|ncat|socat|ssh|scp|sftp|rsync|telnet|s3cmd|gsutil|lftp)" + W + r"|"
    r"\bopenssl s_client|/dev/tcp/|"
    r"\bgit push\b|\bgh (gist|release) (create|upload)\b|"
    r"\baws s3 (cp|sync|mv)\b|\bgcloud storage\b|\baz storage\b|"
    r"\bpython3?\s+(-c\s*|-\s|<<)|\bnode\s+-e\b|\bphp -r\b|\bruby -e\b|\bperl -e\b)", re.S)
SECRETS = re.compile(
    r"(\.ssh/|\.claude\.json|\.mcp\.json|\.credentials\.json|\.claude/projects/|"
    r"\.config/gh/|\.aws/|\.kube/|\.config/gcloud/|\.docker/config\.json|"
    r"\.git-credentials|\.netrc|\.npmrc|\.pypirc|\.gitconfig|_history\b|"
    r"\.env(?!\.example)\b|id_rsa|id_ed25519|id_ecdsa|\.pem\b|\.p12\b|"
    r"Library/(Cookies|Keychains|Messages)/|chrome-profile|/Cookies\b|Login Data|"
    r"security find-)", re.I)
ENCODE_PIPE = re.compile(
    r"\b(base64|xxd|openssl (enc|base64))\b(?!.*\s-d\b).*\|\s*"
    r"(curl|wget|nc|ncat|socat|ssh|openssl s_client)\b", re.S)
LOCAL_URL = re.compile(
    r"\b(curl|wget)\b[^|;&]*?(https?://)?(localhost|127\.0\.0\.1|0\.0\.0\.0|\[::1\])(:\d+)?\S*", re.I)
SHELL_TOOLS = {"Bash", "PowerShell", "Monitor"}
MCP_SECRET_PATH = re.compile(
    r"(~|/Users/[^/\s\"']+|/home/[^/\s\"']+)/(\.ssh|\.aws|\.kube|\.claude\.json|\.mcp\.json|"
    r"\.claude/projects|\.config/gh|\.netrc|\.npmrc|\.env\b|Library/(Cookies|Keychains|Messages))", re.I)


def looks_like_exfil(tool, tool_input):
    text = json.dumps(tool_input, default=str)
    if tool in SHELL_TOOLS:
        cmd = str(tool_input.get("command", ""))
        if re.match(r"\s*ssh-(keygen|add|copy-id|agent)\b", cmd):
            return False, cmd
        # a curl/wget whose only targets are local is not a network sink
        stripped = LOCAL_URL.sub(" ", cmd)
        return (bool(NET.search(stripped) and SECRETS.search(cmd))
                or bool(ENCODE_PIPE.search(cmd))), cmd
    if tool.startswith("mcp__") or tool == "WebFetch":
        return MCP_SECRET_PATH.search(text) is not None, text
    return False, text


def write_flag(sid, reason):
    """Returns True if the flag was written to a sane location."""
    try:
        if os.path.lexists(GUARD_DIR) and (os.path.islink(GUARD_DIR) or not os.path.isdir(GUARD_DIR)):
            return False
        os.makedirs(FROZEN_DIR, mode=0o700, exist_ok=True)
        if os.path.islink(FROZEN_DIR) or not os.path.isdir(FROZEN_DIR):
            return False
        flag = os.path.join(FROZEN_DIR, sid)
        if os.path.islink(flag):
            return False
        fd = os.open(flag, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(reason + "\n")
        return True
    except Exception:
        return False


def main():
    try:
        data = json.load(sys.stdin)
        if not isinstance(data, dict):
            return 0
    except Exception:
        return 0
    sid = str(data.get("session_id", ""))
    if not valid_sid(sid):
        return 0
    tool = str(data.get("tool_name", "?"))
    tool_input = data.get("tool_input") or {}
    if not isinstance(tool_input, dict):
        tool_input = {"command": str(tool_input)}
    exfil, shown = looks_like_exfil(tool, tool_input)
    if not exfil:
        return 0

    reason = (f"{time.strftime('%Y-%m-%d %H:%M')}\n{describe(data)}\n"
              f"Blocked tool: {tool}\n\n{shown[:600]}")
    flag = os.path.join(FROZEN_DIR, sid)
    written = write_flag(sid, reason)
    state = "That session is frozen." if written else \
        "Could not freeze it: ~/.claude/guard looks tampered with. Check it now."
    script = (
        'set r to display dialog "An agent tried something that looks like data '
        f'exfiltration. {state}\\n\\n{dialog_safe(reason)}\\n\\n'
        f'Manual unfreeze: rm ~/.claude/guard/frozen/{sid}" '
        'with title "Claude agent alarm" buttons {"Keep frozen", "Unfreeze"} '
        'default button "Keep frozen" with icon stop\n'
        'if button returned of r is "Unfreeze" then do shell script '
        f'"rm -f " & quoted form of "{flag}"\n'
    )
    run_applescript(script, detach=True)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except SystemExit:
        raise
    except BaseException:  # noqa: BLE001
        sys.exit(0)
