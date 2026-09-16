#!/usr/bin/env python3
"""claude-guard: PreToolUse hook, matcher "*".

1. Frozen session: if exfil_alarm.py flagged this session, block every tool
   call (exit 2) until the user clicks Unfreeze or deletes the flag.

2. Guarded actions (persistence): creating/updating/deleting/running Claude
   Code scheduled tasks, file-tool edits under GUARDED_DIRS, and Bash commands
   whose text touches those places (or LaunchAgents, crontab, shell rc files,
   the guard's own state, or the Keychain grant). The user gets one macOS
   dialog per session. Allow = that session may perform guarded actions for
   GRANT_SECONDS. No answer within DIALOG_SECONDS = deny.

The grant is stored in the login Keychain. That keeps it out of reach of the
model's file tools and of prompt-injected *tool calls*; it is not a barrier
against a shell the agent already controls (same uid). The classifier, the
deny list and the Bash tripwire below make that forgery visible instead.

Fail closed: any crash, malformed input or tampered guard state exits 2.
Exit 0 = proceed. Exit 2 = block (stderr goes to the model).
"""
import json
import os
import re
import subprocess
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from guardctx import (describe, dialog_safe, norm_path, real_path,  # noqa: E402
                      run_applescript, valid_sid)

HOME = os.path.expanduser("~")
GUARD_DIR = os.path.join(HOME, ".claude", "guard")
FROZEN_DIR = os.path.join(GUARD_DIR, "frozen")
GUARDED_DIRS = [
    os.path.join(HOME, ".claude", "scheduled-tasks"),
    os.path.join(HOME, ".claude", "commands"),
    os.path.join(HOME, ".claude", "agents"),
    os.path.join(HOME, "Library", "LaunchAgents"),
]
GUARDED_TOOLS = {
    "mcp__scheduled-tasks__create_scheduled_task",
    "mcp__scheduled-tasks__update_scheduled_task",
    "mcp__scheduled-tasks__delete_scheduled_task",
    "mcp__scheduled-tasks__run_scheduled_task",
}
FILE_TOOLS = {"Edit", "Write", "NotebookEdit", "MultiEdit"}
SHELL_TOOLS = {"Bash", "Monitor", "PowerShell"}
# Bash text that reaches persistence or the guard itself. Reads/executions of
# skills are deliberately not matched (unattended tasks run scripts there).
BASH_TRIPWIRE = re.compile(
    r"(scheduled-tasks|LaunchAgents|LaunchDaemons|\bcrontab\b|"
    r"launchctl\s+(bootstrap|load|submit|enable)|"
    r"\.claude/(hooks|guard|commands|agents)\b|"
    r"\.(zshrc|zprofile|zshenv|bashrc|bash_profile|profile)\b|"
    r"claude-guard-unlock|add-generic-password|chflags\s+nouchg)", re.I)
KC_SERVICE = "claude-guard-unlock"
GRANT_SECONDS = 30 * 60
DIALOG_SECONDS = 120

_GUARDED_NORM = [norm_path(d) + os.sep for d in GUARDED_DIRS]
_GUARDED_REAL = [real_path(d) + os.sep for d in GUARDED_DIRS]


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
    body = dialog_safe(f"{context}\n\nWants to change persistence via {tool}:\n{detail}")
    script = (
        f'display dialog "{body}\\n\\nAllow covers this session for '
        f'{GRANT_SECONDS // 60} minutes. Deny unless you asked for this." '
        'with title "Claude guard" buttons {"Deny", "Allow"} default button "Deny" '
        f'with icon caution giving up after {DIALOG_SECONDS}\n'
    )
    out = run_applescript(script, timeout=DIALOG_SECONDS + 10)
    if "gave up:true" in out:
        return "timeout"
    return "allow" if "button returned:Allow" in out else "deny"


def under_guarded(path, base):
    n = norm_path(path, base)
    r = real_path(path, base)
    return (any(n.startswith(d) for d in _GUARDED_NORM)
            or any(r.startswith(d) for d in _GUARDED_REAL))


def is_guarded(tool, tool_input, base):
    if tool in GUARDED_TOOLS:
        return True
    if tool in FILE_TOOLS:
        p = tool_input.get("file_path") or tool_input.get("notebook_path") or ""
        return bool(p) and under_guarded(p, base)
    if tool in SHELL_TOOLS:
        return BASH_TRIPWIRE.search(str(tool_input.get("command", ""))) is not None
    return False


def frozen_state(sid):
    """'ok' | 'frozen' | 'tampered'"""
    if not os.path.lexists(GUARD_DIR):
        return "ok"
    if os.path.islink(GUARD_DIR) or not os.path.isdir(GUARD_DIR):
        return "tampered"
    if not os.path.lexists(FROZEN_DIR):
        return "ok"
    if os.path.islink(FROZEN_DIR) or not os.path.isdir(FROZEN_DIR):
        return "tampered"
    flag = os.path.join(FROZEN_DIR, sid)
    if os.path.lexists(flag):
        return "tampered" if os.path.islink(flag) else "frozen"
    return "ok"


def main():
    try:
        data = json.load(sys.stdin)
        if not isinstance(data, dict):
            raise ValueError
    except Exception:
        sys.stderr.write("claude-guard: unreadable hook input; blocking.\n")
        return 2
    sid = str(data.get("session_id", ""))
    tool = str(data.get("tool_name", ""))
    tool_input = data.get("tool_input") or {}
    if not isinstance(tool_input, dict):
        tool_input = {"command": str(tool_input)}
    base = str(data.get("cwd") or os.getcwd())

    if valid_sid(sid):
        state = frozen_state(sid)
        if state == "frozen":
            sys.stderr.write(
                "This session is frozen: an earlier tool call looked like data exfiltration. "
                "Stop and tell the user to click Unfreeze on the alarm dialog, or to run: "
                f"rm ~/.claude/guard/frozen/{sid}\n")
            return 2
        if state == "tampered":
            sys.stderr.write(
                "claude-guard state under ~/.claude/guard has been tampered with "
                "(symlink or non-directory). Blocking. Ask the user to inspect it.\n")
            return 2

    if not is_guarded(tool, tool_input, base):
        return 0
    if not valid_sid(sid):
        sys.stderr.write("Blocked by Claude guard: session id missing.\n")
        return 2
    if grant_valid(sid):
        return 0

    if tool in GUARDED_TOOLS:
        keys = ("taskId", "title", "schedule", "cronExpression", "enabled")
        detail = json.dumps({k: tool_input.get(k) for k in keys if k in tool_input})
        if "prompt" in tool_input:
            detail += "\nprompt: " + str(tool_input["prompt"])[:250]
    elif tool in SHELL_TOOLS:
        detail = "command: " + str(tool_input.get("command", ""))[:300]
    else:
        detail = f"file: {tool_input.get('file_path') or tool_input.get('notebook_path')}"
        if "new_string" in tool_input:
            detail += "\nchange: " + str(tool_input["new_string"])[:250]
        elif "content" in tool_input:
            detail += "\ncontent: " + str(tool_input["content"])[:250]

    if ask(describe(data), tool, detail) == "allow":
        grant_store(sid)
        return 0
    sys.stderr.write(
        "Blocked by Claude guard: this action changes persistence (scheduled tasks, "
        "launch agents, shell rc, guard state) and needs the user to click Allow on the "
        "macOS dialog. Tell the user what you wanted to change and stop.\n")
    return 2


if __name__ == "__main__":
    try:
        sys.exit(main())
    except SystemExit:
        raise
    except BaseException as e:  # noqa: BLE001
        sys.stderr.write(f"claude-guard hook crashed ({type(e).__name__}); blocking.\n")
        sys.exit(2)
