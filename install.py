#!/usr/bin/env python3
"""Install or remove claude-guard.

    python3 install.py            # install hooks + merge deny rules
    python3 install.py --uninstall

Idempotent. Copies hooks/ to ~/.claude/hooks/claude-guard/ (files locked with
chflags uchg), registers them in ~/.claude/settings.json with an absolute
interpreter path, merges deny.json into permissions.deny, and turns on
autoMode.classifyAllShell. Backs up settings.json only when it changes.
Uninstall removes exactly the rules this installer added (recorded in a
manifest), nothing you set yourself.

Run it yourself, not through an agent: once installed, agents can no longer
edit settings.json or the hooks directory (that is the point).
"""
import json
import os
import shlex
import shutil
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
HOME = os.path.expanduser("~")
CLAUDE = os.path.join(HOME, ".claude")
SETTINGS = os.path.join(CLAUDE, "settings.json")
DEST = os.path.join(CLAUDE, "hooks", "claude-guard")
MANIFEST = os.path.join(DEST, "installed.json")
FILES = ["guardctx.py", "exfil_alarm.py", "circuit_breaker.py"]
PY = sys.executable


def die(msg):
    sys.exit(f"claude-guard: {msg}")


def hook_entry(script, timeout):
    cmd = f"{shlex.quote(PY)} -B {shlex.quote(os.path.join(DEST, script))}"
    return {"matcher": "*", "hooks": [{"type": "command", "command": cmd, "timeout": timeout}]}


LEGACY = {"circuit_breaker.py", "exfil_alarm.py", "circuit-breaker.py", "exfil-alarm.py"}


def is_ours(entry):
    try:
        for h in entry.get("hooks", []):
            cmd = str(h.get("command", ""))
            if DEST in cmd or os.path.basename(cmd.split()[-1] if cmd.split() else "") in LEGACY:
                return True
        return False
    except Exception:
        return False


def load_settings():
    if not os.path.exists(SETTINGS):
        return {}
    try:
        with open(SETTINGS, encoding="utf-8") as f:
            d = json.load(f)
    except Exception as e:
        die(f"{SETTINGS} is not valid JSON ({e}); fix it first")
    if not isinstance(d, dict):
        die(f"{SETTINGS} must be a JSON object")
    hooks = d.get("hooks", {})
    if hooks is not None and not isinstance(hooks, dict):
        die("settings.json: 'hooks' must be an object")
    for ev, lst in (hooks or {}).items():
        if not isinstance(lst, list):
            die(f"settings.json: hooks.{ev} must be a list")
    perms = d.get("permissions", {})
    if perms is not None and not isinstance(perms, dict):
        die("settings.json: 'permissions' must be an object")
    if (perms or {}).get("deny") is not None and not isinstance(perms["deny"], list):
        die("settings.json: permissions.deny must be a list")
    return d


def save_settings(d):
    new = json.dumps(d, indent=2) + "\n"
    if os.path.exists(SETTINGS):
        with open(SETTINGS, encoding="utf-8") as f:
            old = f.read()
        if old == new:
            return False
        shutil.copy2(SETTINGS, SETTINGS + f".bak-{time.strftime('%Y%m%d-%H%M%S')}")
    tmp = SETTINGS + ".tmp"
    if os.path.lexists(tmp):
        os.remove(tmp)
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(new)
    os.replace(tmp, SETTINGS)
    os.chmod(SETTINGS, 0o600)
    return True


def chflags(flag, paths):
    subprocess.run(["/usr/bin/chflags", flag] + list(paths), check=False,
                   capture_output=True)


def install():
    r = subprocess.run([PY, "-c", "import json,sys;print(sys.version_info[:2])"],
                       capture_output=True, text=True)
    if r.returncode != 0:
        die(f"interpreter {PY} does not run")
    if sys.version_info < (3, 6):
        die("Python 3.6+ required")

    if os.path.isdir(DEST):
        chflags("nouchg", [os.path.join(DEST, f) for f in FILES if os.path.exists(os.path.join(DEST, f))])
    os.makedirs(DEST, mode=0o700, exist_ok=True)
    for name in FILES:
        shutil.copy2(os.path.join(HERE, "hooks", name), os.path.join(DEST, name))
        os.chmod(os.path.join(DEST, name), 0o500)
    shutil.rmtree(os.path.join(DEST, "__pycache__"), ignore_errors=True)

    d = load_settings()
    hooks = d.setdefault("hooks", {}) or {}
    d["hooks"] = hooks
    hooks["PreToolUse"] = [e for e in hooks.get("PreToolUse", []) if not is_ours(e)]
    hooks["PreToolUse"].append(hook_entry("circuit_breaker.py", 150))
    hooks["PermissionDenied"] = [e for e in hooks.get("PermissionDenied", []) if not is_ours(e)]
    hooks["PermissionDenied"].append(hook_entry("exfil_alarm.py", 20))

    with open(os.path.join(HERE, "deny.json"), encoding="utf-8") as f:
        wanted = json.load(f)["deny"]
    perms = d.setdefault("permissions", {}) or {}
    d["permissions"] = perms
    deny = perms.setdefault("deny", []) or []
    perms["deny"] = deny
    previously = set()
    if os.path.exists(MANIFEST):
        try:
            with open(MANIFEST, encoding="utf-8") as f:
                previously = set(json.load(f).get("added", []))
        except Exception:
            pass
    added = [r for r in wanted if r not in deny]
    deny.extend(added)
    added_total = sorted(previously | set(added))
    d.setdefault("autoMode", {})["classifyAllShell"] = True
    changed = save_settings(d)

    with open(MANIFEST, "w", encoding="utf-8") as f:
        json.dump({"added": added_total, "installed": time.strftime("%Y-%m-%d %H:%M:%S"),
                   "python": PY}, f, indent=2)
    chflags("uchg", [os.path.join(DEST, f) for f in FILES])

    print(f"hooks installed to {DEST} (locked with chflags uchg)")
    print(f"interpreter: {PY}")
    print(f"deny rules added now: {len(added)}; total deny rules: {len(deny)}")
    print("autoMode.classifyAllShell = true")
    print("settings.json " + ("updated (backup written)" if changed else "already up to date"))
    print("Restart open Claude Code sessions to pick up the hooks.")


def uninstall():
    d = load_settings()
    hooks = d.get("hooks") or {}
    for ev in ("PreToolUse", "PermissionDenied"):
        if ev in hooks:
            hooks[ev] = [e for e in hooks[ev] if not is_ours(e)]
            if not hooks[ev]:
                del hooks[ev]
    added = set()
    if os.path.exists(MANIFEST):
        try:
            with open(MANIFEST, encoding="utf-8") as f:
                added = set(json.load(f).get("added", []))
        except Exception:
            pass
    perms = d.get("permissions") or {}
    if isinstance(perms.get("deny"), list):
        perms["deny"] = [r for r in perms["deny"] if r not in added]
    save_settings(d)
    if os.path.isdir(DEST):
        chflags("nouchg", [os.path.join(DEST, f) for f in FILES if os.path.exists(os.path.join(DEST, f))])
    shutil.rmtree(DEST, ignore_errors=True)
    shutil.rmtree(os.path.join(CLAUDE, "guard"), ignore_errors=True)
    subprocess.run(["/usr/bin/security", "delete-generic-password", "-s", "claude-guard-unlock"],
                   capture_output=True)
    print(f"claude-guard removed; {len(added)} deny rules it had added were dropped. "
          "classifyAllShell left as is.")


if __name__ == "__main__":
    if sys.platform != "darwin":
        die("uses macOS dialogs and Keychain; macOS only.")
    if os.geteuid() == 0:
        die("run as your own user, not root/sudo.")
    if "--uninstall" in sys.argv:
        uninstall()
    else:
        install()
