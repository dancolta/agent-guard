#!/usr/bin/env python3
"""claude-guard: PreToolUse hook, matcher "*".

1. Frozen session: if exfil_alarm.py flagged this session, block every tool
   call (exit 2) until the user clicks Unfreeze or deletes the flag.

2. Guarded actions: creating/updating/deleting Claude Code scheduled tasks, or
   editing files under ~/.claude/scheduled-tasks/. The user gets one macOS
   dialog per session. Allow = that session may perform guarded actions for
   GRANT_SECONDS. The grant is stored in the login Keychain, which an agent
   cannot write when `Bash(security:*)` is denied. No answer within
   DIALOG_SECONDS = deny. A denied guarded action exits 2 with a message the
   model can act on.

Exit 0 = proceed. Exit 2 = block (stderr goes to the model).
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
GUARDED_DIRS = [os.path.join(HOME, ".claude", "scheduled-tasks") + os.sep]
GUARDED_TOOLS = {
    "mcp__scheduled-tasks__create_scheduled_task",
    "mcp__scheduled-tasks__update_scheduled_task",
    "mcp__scheduled-tasks__delete_scheduled_task",
}
FILE_TOOLS = {"Edit", "Write", "NotebookEdit", "MultiEdit"}
KC_SERVICE = "claude-guard-unlock"
GRANT_SECONDS = 30 * 60
DIALOG_SECONDS = 120
SID_RE = re.compile(r"[A-Za-z0-9_.-]{1,128}")


def run(cmd, timeout=10):
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout,
                          stdin=subprocess.DEVNULL)


def grant_valid(sid):
    try:
        r = run(["/usr/bin/security", "find-generic-password",
                 "-s", KC_SERVICE, "-a", sid, "-w"])
        if r.returncode != 0:
            return False
        return 0 <= time.time() - float(r.stdout.strip()) < GRANT_SECONDS
    except Exception:
        return False


def grant_store(sid):
    try:
        run(["/usr/bin/security", "add-generic-password", "-U",
             "-s", KC_SERVICE, "-a", sid, "-w", str(time.time())])
    except Exception:
        pass


def ask(context, tool, detail):
    body = dialog_safe(f"{context}\n\nWants to change scheduled tasks via {tool}:\n{detail}")
    script = (
        f'display dialog "{body}\\n\\nAllow covers this session for '
        f'{GRANT_SECONDS // 60} minutes. Deny unless you asked for this." '
        'with title "Claude guard" buttons {"Deny", "Allow"} default button "Deny" '
        f'with icon caution giving up after {DIALOG_SECONDS}'
    )
    try:
        out = run(["/usr/bin/osascript", "-e", script], timeout=DIALOG_SECONDS + 10).stdout
        if "gave up:true" in out:
            return "timeout"
        return "allow" if "button returned:Allow" in out else "deny"
    except Exception:
        return "deny"


def is_guarded(tool, tool_input):
    if tool in GUARDED_TOOLS:
        return True
    if tool in FILE_TOOLS:
        p = tool_input.get("file_path") or tool_input.get("notebook_path") or ""
        if not p:
            return False
        p = os.path.realpath(os.path.expanduser(str(p)))
        return any(p.startswith(d) for d in GUARDED_DIRS)
    return False


def main():
    try:
        data = json.load(sys.stdin)
    except Exception:
        return 0
    sid = str(data.get("session_id", ""))
    tool = str(data.get("tool_name", ""))
    tool_input = data.get("tool_input", {}) or {}

    if sid and SID_RE.fullmatch(sid) and os.path.exists(os.path.join(FROZEN_DIR, sid)):
        sys.stderr.write(
            "This session is frozen: an earlier tool call looked like data exfiltration. "
            "Stop and tell the user to click Unfreeze on the alarm dialog.\n")
        return 2

    if not is_guarded(tool, tool_input):
        return 0
    if not SID_RE.fullmatch(sid):
        sys.stderr.write("Blocked by Claude guard: session id missing.\n")
        return 2
    if grant_valid(sid):
        return 0

    if tool in GUARDED_TOOLS:
        keys = ("taskId", "title", "schedule", "cronExpression", "enabled")
        detail = json.dumps({k: tool_input.get(k) for k in keys if k in tool_input})
        if "prompt" in tool_input:
            detail += "\nprompt: " + str(tool_input["prompt"])[:250]
    else:
        detail = f"file: {tool_input.get('file_path') or tool_input.get('notebook_path')}"
        if "new_string" in tool_input:
            detail += "\nchange: " + str(tool_input["new_string"])[:250]

    if ask(describe(data), tool, detail) == "allow":
        grant_store(sid)
        return 0
    sys.stderr.write(
        "Blocked by Claude guard: changes to scheduled tasks need the user to click Allow "
        "on the macOS dialog. Tell the user what you wanted to change and stop.\n")
    return 2


if __name__ == "__main__":
    sys.exit(main())
