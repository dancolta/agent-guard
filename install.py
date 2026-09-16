#!/usr/bin/env python3
"""Install or remove claude-guard.

    python3 install.py            # install hooks + merge deny rules
    python3 install.py --uninstall

Idempotent. Copies hooks/ to ~/.claude/hooks/claude-guard/, registers them in
~/.claude/settings.json, merges deny.json into permissions.deny, and turns on
autoMode.classifyAllShell. A backup of settings.json is written next to it.
Run it yourself, not through an agent: once installed, agents can no longer
edit settings.json or the hooks directory (that is the point).
"""
import json
import os
import shutil
import stat
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
HOME = os.path.expanduser("~")
CLAUDE = os.path.join(HOME, ".claude")
SETTINGS = os.path.join(CLAUDE, "settings.json")
DEST = os.path.join(CLAUDE, "hooks", "claude-guard")
FILES = ["guardctx.py", "exfil_alarm.py", "circuit_breaker.py"]
MARK = "claude-guard"


def hook_entry(script, timeout):
    return {"matcher": "*", "hooks": [{"type": "command",
                                       "command": os.path.join(DEST, script),
                                       "timeout": timeout}]}


def is_ours(entry):
    return any(MARK in str(h.get("command", "")) for h in entry.get("hooks", []))


def load_settings():
    if not os.path.exists(SETTINGS):
        return {}
    with open(SETTINGS, encoding="utf-8") as f:
        return json.load(f)


def save_settings(d):
    if os.path.exists(SETTINGS):
        shutil.copy2(SETTINGS, SETTINGS + f".bak-{time.strftime('%Y%m%d-%H%M%S')}")
    tmp = SETTINGS + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(d, f, indent=2)
        f.write("\n")
    os.replace(tmp, SETTINGS)
    os.chmod(SETTINGS, 0o600)


def install():
    os.makedirs(DEST, exist_ok=True)
    for name in FILES:
        src = os.path.join(HERE, "hooks", name)
        dst = os.path.join(DEST, name)
        shutil.copy2(src, dst)
        os.chmod(dst, stat.S_IRWXU)
    d = load_settings()
    hooks = d.setdefault("hooks", {})
    pre = [e for e in hooks.get("PreToolUse", []) if not is_ours(e)]
    pre.insert(0, hook_entry("circuit_breaker.py", 150))
    hooks["PreToolUse"] = pre
    den = [e for e in hooks.get("PermissionDenied", []) if not is_ours(e)]
    den.append(hook_entry("exfil_alarm.py", 20))
    hooks["PermissionDenied"] = den

    with open(os.path.join(HERE, "deny.json"), encoding="utf-8") as f:
        wanted = json.load(f)["deny"]
    perms = d.setdefault("permissions", {})
    deny = perms.setdefault("deny", [])
    added = [r for r in wanted if r not in deny]
    deny.extend(added)
    d.setdefault("autoMode", {})["classifyAllShell"] = True
    save_settings(d)
    print(f"hooks installed to {DEST}")
    print(f"deny rules added: {len(added)} (total {len(deny)})")
    print("autoMode.classifyAllShell = true")
    print("Restart Claude Code sessions to pick up the hooks.")


def uninstall():
    d = load_settings()
    hooks = d.get("hooks", {})
    for ev in ("PreToolUse", "PermissionDenied"):
        if ev in hooks:
            hooks[ev] = [e for e in hooks[ev] if not is_ours(e)]
            if not hooks[ev]:
                del hooks[ev]
    with open(os.path.join(HERE, "deny.json"), encoding="utf-8") as f:
        wanted = set(json.load(f)["deny"])
    perms = d.get("permissions", {})
    if "deny" in perms:
        perms["deny"] = [r for r in perms["deny"] if r not in wanted]
    save_settings(d)
    shutil.rmtree(DEST, ignore_errors=True)
    shutil.rmtree(os.path.join(CLAUDE, "guard"), ignore_errors=True)
    print("claude-guard removed. classifyAllShell left as is.")


if __name__ == "__main__":
    if sys.platform != "darwin":
        sys.exit("claude-guard uses macOS dialogs and Keychain; macOS only.")
    if "--uninstall" in sys.argv:
        uninstall()
    else:
        install()
