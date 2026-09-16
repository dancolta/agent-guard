"""PermissionDenied hook body (Claude Code only).

Claude's auto-mode classifier denies a call, this fires afterwards. If the
denied call looks like data exfiltration, freeze the session and show the alarm.
Codex has no PermissionDenied event; there the same detection runs inside
circuit_breaker.run() on PreToolUse instead. Never blocks; always exits 0.
"""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from context import clean_text, describe, valid_sid  # noqa: E402
from platform_backend import backend  # noqa: E402
import policy  # noqa: E402

HOME = os.path.expanduser("~")
FROZEN_DIR = os.path.join(HOME, ".claude", "guard", "frozen")


def _write_flag(sid, reason):
    try:
        os.makedirs(FROZEN_DIR, mode=0o700, exist_ok=True)
        if os.path.islink(FROZEN_DIR) or not os.path.isdir(FROZEN_DIR):
            return False
        flag = os.path.join(FROZEN_DIR, sid)
        if os.path.islink(flag):
            return False
        flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        fd = os.open(flag, flags, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(reason + "\n")
        return True
    except Exception:
        return False


def run():
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
    tin = data.get("tool_input") or {}
    if not isinstance(tin, dict):
        tin = {"command": str(tin)}
    is_exfil, shown = policy.exfil(tool, tin)
    if not is_exfil:
        return 0
    reason = f"{describe(data)}\nBlocked tool: {tool}\n\n{str(shown)[:600]}"
    written = _write_flag(sid, reason)
    flag = os.path.join(FROZEN_DIR, sid)
    tail = "" if written else "\n\n(could not write freeze flag; check ~/.claude/guard)"
    body = clean_text(
        "An agent tried something that looks like data exfiltration. "
        "That session is frozen.\n\n" + reason +
        f"\n\nManual unfreeze: rm {flag}" + tail, limit=1400)
    try:
        backend().alarm("Agent guard alarm", body, "Keep frozen", "Unfreeze", flag)
    except Exception:
        pass
    return 0


def main():
    try:
        return run()
    except SystemExit:
        raise
    except BaseException:  # noqa: BLE001
        return 0


if __name__ == "__main__":
    sys.exit(main())
