#!/usr/bin/env python3
"""Install or remove agent-guard for Claude Code and/or Codex CLI, on
macOS / Linux / Windows.

    python3 install.py                 # auto-detect installed agents
    python3 install.py --agent claude
    python3 install.py --agent codex
    python3 install.py --agent both
    python3 install.py --uninstall

Run it yourself, not through an agent: once installed, agents can no longer
edit their own settings or the guard's files.

- Copies guard/*.py to <config>/hooks/agent-guard/ (locked read-only).
- Claude Code: registers PreToolUse (circuit_breaker) + PermissionDenied
  (exfil_alarm) in ~/.claude/settings.json, merges deny.json into
  permissions.deny, sets autoMode.classifyAllShell = true.
- Codex CLI: writes ~/.codex/hooks/agent-guard.hooks.json (PreToolUse ->
  circuit_breaker; Codex has no PermissionDenied, so the breaker also does
  exfil detection), enables [features] hooks in config.toml, and prints the
  recommended sandbox lines (Codex has no path deny list).
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
PY = sys.executable or "python3"
GUARD_FILES = ["__init__.py", "context.py", "policy.py",
               "platform_backend.py", "circuit_breaker.py", "exfil_alarm.py"]
WIN = os.name == "nt"


def die(m):
    sys.exit(f"agent-guard: {m}")


def copy_pkg(dest):
    bk = _backend()
    if os.path.isdir(dest):
        bk.unlock([os.path.join(dest, f) for f in GUARD_FILES])
    os.makedirs(dest, exist_ok=True)
    for f in GUARD_FILES:
        shutil.copy2(os.path.join(HERE, "guard", f), os.path.join(dest, f))
    shutil.rmtree(os.path.join(dest, "__pycache__"), ignore_errors=True)
    bk.lock([os.path.join(dest, f) for f in GUARD_FILES])


def _backend():
    sys.path.insert(0, os.path.join(HERE, "guard"))
    from platform_backend import backend
    return backend()


def hook_cmd(dest, script):
    return f"{shlex.quote(PY)} -B {shlex.quote(os.path.join(dest, script))}"


# ------------------------------------------------------------------ Claude
def claude_install():
    cfg = os.path.join(HOME, ".claude")
    if not os.path.isdir(cfg):
        print("Claude Code: ~/.claude not found, skipping.")
        return False
    dest = os.path.join(cfg, "hooks", "agent-guard")
    copy_pkg(dest)
    settings = os.path.join(cfg, "settings.json")
    d = _load_json(settings)
    hooks = d.setdefault("hooks", {}) or {}
    d["hooks"] = hooks

    def ours(e):
        return any("agent-guard" in str(h.get("command", "")) for h in e.get("hooks", []))
    entry = lambda cmd, t: {"matcher": "*", "hooks": [  # noqa: E731
        {"type": "command", "command": cmd, "timeout": t}]}
    hooks["PreToolUse"] = [e for e in hooks.get("PreToolUse", []) if not ours(e)]
    hooks["PreToolUse"].append(entry(hook_cmd(dest, "circuit_breaker.py") + " --runtime claude", 150))
    hooks["PermissionDenied"] = [e for e in hooks.get("PermissionDenied", []) if not ours(e)]
    hooks["PermissionDenied"].append(entry(hook_cmd(dest, "exfil_alarm.py"), 20))

    with open(os.path.join(HERE, "deny.json"), encoding="utf-8") as f:
        wanted = json.load(f)["deny"]
    perms = d.setdefault("permissions", {}) or {}
    d["permissions"] = perms
    deny = perms.setdefault("deny", []) or []
    perms["deny"] = deny
    added = [r for r in wanted if r not in deny]
    deny.extend(added)
    d.setdefault("autoMode", {})["classifyAllShell"] = True
    _save_json(settings, d)
    _manifest(dest, added)
    print(f"Claude Code: hooks in {dest}; {len(added)} deny rules added; "
          "classifyAllShell = true.")
    return True


# ------------------------------------------------------------------- Codex
def codex_install():
    cfg = os.path.join(HOME, ".codex")
    if not os.path.isdir(cfg):
        print("Codex CLI: ~/.codex not found, skipping.")
        return False
    dest = os.path.join(cfg, "hooks", "agent-guard")
    copy_pkg(dest)
    hj = os.path.join(cfg, "hooks", "agent-guard.hooks.json")
    handler = {"type": "command",
               "command": hook_cmd(dest, "circuit_breaker.py") + " --runtime codex",
               "timeout": 150}
    handler["commandWindows"] = (
        f'"{PY}" -B "{os.path.join(dest, "circuit_breaker.py")}" --runtime codex')
    doc = {"description": "agent-guard: block exfil, reads of secrets, and "
           "unapproved persistence changes",
           "hooks": {"PreToolUse": [{"matcher": "*", "hooks": [handler]}]}}
    with open(hj, "w", encoding="utf-8") as f:
        json.dump(doc, f, indent=2)
    _enable_codex_feature(os.path.join(cfg, "config.toml"))
    print(f"Codex CLI: hooks in {dest}; PreToolUse registered in {hj}.")
    print("Codex has no path deny list; add these lines to ~/.codex/config.toml "
          "for real containment (see codex-sandbox.toml):")
    print('  sandbox_mode = "workspace-write"')
    print('  [sandbox_workspace_write]\n  network_access = false')
    print('  [shell_environment_policy]\n  inherit = "core"')
    return True


def _enable_codex_feature(path):
    txt = ""
    if os.path.exists(path):
        with open(path, encoding="utf-8") as f:
            txt = f.read()
    if "hooks = true" in txt.replace(" ", " "):
        return
    shutil.copy2(path, path + f".bak-{time.strftime('%Y%m%d-%H%M%S')}") if os.path.exists(path) else None
    with open(path, "a", encoding="utf-8") as f:
        f.write("\n# agent-guard: enable lifecycle hooks (older Codex used "
                "codex_hooks = true)\n[features]\nhooks = true\n")


# --------------------------------------------------------------- shared io
def _load_json(path):
    if not os.path.exists(path):
        return {}
    try:
        with open(path, encoding="utf-8") as f:
            d = json.load(f)
    except Exception as e:
        die(f"{path} is not valid JSON ({e}); fix it first")
    if not isinstance(d, dict):
        die(f"{path} must be a JSON object")
    return d


def _save_json(path, d):
    new = json.dumps(d, indent=2) + "\n"
    if os.path.exists(path):
        with open(path, encoding="utf-8") as f:
            if f.read() == new:
                return
        shutil.copy2(path, path + f".bak-{time.strftime('%Y%m%d-%H%M%S')}")
    tmp = path + ".tmp"
    if os.path.lexists(tmp):
        os.remove(tmp)
    with open(tmp, "w", encoding="utf-8") as f:
        f.write(new)
    if not WIN:
        os.chmod(tmp, 0o600)
    os.replace(tmp, path)


def _manifest(dest, added):
    prev = set()
    m = os.path.join(dest, "installed.json")
    if os.path.exists(m):
        try:
            with open(m, encoding="utf-8") as f:
                prev = set(json.load(f).get("added", []))
        except Exception:
            pass
    _backend().unlock([m])
    with open(m, "w", encoding="utf-8") as f:
        json.dump({"added": sorted(prev | set(added)),
                   "installed": time.strftime("%Y-%m-%d %H:%M:%S"), "python": PY}, f, indent=2)


# ----------------------------------------------------------------- remove
def uninstall():
    bk = _backend()
    for cfg, is_claude in ((os.path.join(HOME, ".claude"), True),
                           (os.path.join(HOME, ".codex"), False)):
        dest = os.path.join(cfg, "hooks", "agent-guard")
        if is_claude and os.path.exists(os.path.join(cfg, "settings.json")):
            d = _load_json(os.path.join(cfg, "settings.json"))
            hooks = d.get("hooks") or {}
            for ev in ("PreToolUse", "PermissionDenied"):
                if ev in hooks:
                    hooks[ev] = [e for e in hooks[ev]
                                 if not any("agent-guard" in str(h.get("command", ""))
                                            for h in e.get("hooks", []))]
                    if not hooks[ev]:
                        del hooks[ev]
            added = set()
            mp = os.path.join(dest, "installed.json")
            if os.path.exists(mp):
                try:
                    with open(mp, encoding="utf-8") as f:
                        added = set(json.load(f).get("added", []))
                except Exception:
                    pass
            perms = d.get("permissions") or {}
            if isinstance(perms.get("deny"), list):
                perms["deny"] = [r for r in perms["deny"] if r not in added]
            _save_json(os.path.join(cfg, "settings.json"), d)
        if not is_claude:
            hj = os.path.join(cfg, "hooks", "agent-guard.hooks.json")
            if os.path.exists(hj):
                os.remove(hj)
        if os.path.isdir(dest):
            bk.unlock([os.path.join(dest, f) for f in GUARD_FILES])
            shutil.rmtree(dest, ignore_errors=True)
    shutil.rmtree(os.path.join(HOME, ".claude", "guard"), ignore_errors=True)
    bk.grant_clear_all()
    print("agent-guard removed (deny rules it added were dropped).")


def main():
    args = sys.argv[1:]
    if not WIN and hasattr(os, "geteuid") and os.geteuid() == 0:
        die("run as your own user, not root/sudo.")
    if sys.version_info < (3, 6):
        die("Python 3.6+ required")
    if "--uninstall" in args:
        return uninstall()
    agent = "auto"
    if "--agent" in args:
        agent = args[args.index("--agent") + 1]
    did = False
    if agent in ("auto", "both", "claude"):
        did = claude_install() or did
    if agent in ("auto", "both", "codex"):
        did = codex_install() or did
    if not did:
        die("no supported agent found (~/.claude or ~/.codex). Use --agent to force.")
    print("Restart open agent sessions to load the hooks.")


if __name__ == "__main__":
    main()
