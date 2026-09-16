"""PreToolUse hook body (Claude Code and Codex CLI).

On every tool call, in order:
  1. frozen session      -> block (exit 2)
  2. secret-path read     -> block (belt-and-suspenders where the runtime has no
                             path deny list; on Claude the deny list already
                             covers this, so it rarely fires)
  3. exfil-shaped call    -> freeze + alarm + block  (this is how detection works
                             on Codex, which has no PermissionDenied event)
  4. persistence change   -> one dialog per session; Allow grants 30 min

Fail closed: bad input, crash or tampered state -> exit 2.
"""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from context import clean_text, describe, valid_sid  # noqa: E402
from platform_backend import backend  # noqa: E402
import policy  # noqa: E402

HOME = os.path.expanduser("~")
GUARD_DIR = os.path.join(HOME, ".claude", "guard")
FROZEN_DIR = os.path.join(GUARD_DIR, "frozen")
DIALOG_SECONDS = 120


def _frozen_state(sid):
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


def _freeze_and_alarm(sid, tool, shown, data):
    reason = (f"{describe(data)}\nBlocked tool: {tool}\n\n{str(shown)[:600]}")
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


def run():
    try:
        data = json.load(sys.stdin)
        if not isinstance(data, dict):
            raise ValueError
    except Exception:
        sys.stderr.write("agent-guard: unreadable hook input; blocking.\n")
        return 2
    sid = str(data.get("session_id", ""))
    tool = str(data.get("tool_name", ""))
    tin = data.get("tool_input") or {}
    if not isinstance(tin, dict):
        tin = {"command": str(tin)}
    base = str(data.get("cwd") or os.getcwd())

    # 1. frozen / tampered
    if valid_sid(sid):
        st = _frozen_state(sid)
        if st == "frozen":
            sys.stderr.write(
                "This session is frozen: an earlier call looked like data exfiltration. "
                f"Stop; the user must click Unfreeze or run: rm ~/.claude/guard/frozen/{sid}\n")
            return 2
        if st == "tampered":
            sys.stderr.write("agent-guard: ~/.claude/guard tampered with; blocking.\n")
            return 2

    # 2. secret-path read
    if policy.secret_read(tool, tin):
        sys.stderr.write(
            "Blocked by agent-guard: reading a secret path (keys, tokens, cookies, "
            "history). Do not read it; tell the user what you needed and why.\n")
        return 2

    # 3. exfil shape -> freeze
    is_exfil, shown = policy.exfil(tool, tin)
    if is_exfil:
        if valid_sid(sid):
            _freeze_and_alarm(sid, tool, shown, data)
        sys.stderr.write(
            "Blocked by agent-guard: this looks like data exfiltration (network sink + "
            "secret). The session is frozen. Stop and tell the user.\n")
        return 2

    # 4. persistence -> dialog
    if not policy.is_guarded(tool, tin, base):
        return 0
    if not valid_sid(sid):
        sys.stderr.write("Blocked by agent-guard: session id missing.\n")
        return 2
    bk = backend()
    if bk.grant_get(sid):
        return 0
    body = clean_text(
        f"{describe(data)}\n\nWants to change persistence via {tool}:\n"
        f"{policy.guard_detail(tool, tin)}\n\n"
        "Allow covers this session for 30 minutes. Deny unless you asked for this.")
    verdict = "deny"
    try:
        verdict = bk.ask("Agent guard", body, "Deny", "Allow", DIALOG_SECONDS)
    except Exception:
        verdict = "deny"
    if verdict == "allow":
        bk.grant_set(sid)
        return 0
    sys.stderr.write(
        "Blocked by agent-guard: this changes persistence (scheduled tasks, launch "
        "agents, shell rc, agent config) and needs the user to click Allow. "
        "Tell the user what you wanted to change and stop.\n")
    return 2


def main():
    try:
        return run()
    except SystemExit:
        raise
    except BaseException as e:  # noqa: BLE001
        sys.stderr.write(f"agent-guard hook crashed ({type(e).__name__}); blocking.\n")
        return 2


if __name__ == "__main__":
    sys.exit(main())
