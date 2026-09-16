"""Shared, agent- and OS-neutral decision logic.

Two questions the hooks ask this module:
  is_guarded(...)  -> does this call create persistence? (needs a dialog)
  exfil(...)       -> does this call look like data exfiltration? (freeze)
  secret_read(...) -> does this Bash command read a secret path? (block)

Tool-name normalisation covers both runtimes:
  Claude Code : Bash, Read, Edit, Write, MultiEdit, NotebookEdit, mcp__...
  Codex CLI   : Bash / shell, apply_patch (aliases Edit/Write), mcp__...
"""
import os
import re

from context import norm_path, real_path

HOME = os.path.expanduser("~")

GUARDED_DIRS = [
    os.path.join(HOME, ".claude", "scheduled-tasks"),
    os.path.join(HOME, ".claude", "commands"),
    os.path.join(HOME, ".claude", "agents"),
    os.path.join(HOME, ".codex", "prompts"),
    os.path.join(HOME, "Library", "LaunchAgents"),
]
GUARDED_TOOLS = {
    "mcp__scheduled-tasks__create_scheduled_task",
    "mcp__scheduled-tasks__update_scheduled_task",
    "mcp__scheduled-tasks__delete_scheduled_task",
    "mcp__scheduled-tasks__run_scheduled_task",
}
FILE_TOOLS = {"Edit", "Write", "MultiEdit", "NotebookEdit", "apply_patch"}
SHELL_TOOLS = {"Bash", "shell", "PowerShell", "Monitor"}
READ_TOOLS = {"Read"}

# Bash text that reaches persistence or the guard/agent config itself.
BASH_PERSIST = re.compile(
    r"(scheduled-tasks|LaunchAgents|LaunchDaemons|\bcrontab\b|"
    r"schtasks|Register-ScheduledTask|New-Service|"
    r"launchctl\s+(bootstrap|load|submit|enable)|"
    r"\.(claude|codex)/(hooks|guard|commands|agents|prompts)\b|"
    r"\.(zshrc|zprofile|zshenv|bashrc|bash_profile|profile)\b|PowerShell.*profile|"
    r"agent-guard-unlock|add-generic-password|chflags\s+nouchg|chattr\s+-i)", re.I)

# --- exfil heuristic: a network sink AND a secret, or an encode->network pipe ---
_W = r"(?![\w-])"
NET = re.compile(
    r"(\b(curl|wget|nc|ncat|socat|ssh|scp|sftp|rsync|telnet|s3cmd|gsutil|lftp)" + _W + r"|"
    r"\bopenssl s_client|/dev/tcp/|Invoke-WebRequest|Invoke-RestMethod|\biwr\b|\bcurl\.exe|"
    r"\bgit push\b|\bgh (gist|release) (create|upload)\b|"
    r"\baws s3 (cp|sync|mv)\b|\bgcloud storage\b|\baz storage\b|"
    r"\bpython3?\s+(-c\s*|-\s|<<)|\bnode\s+-e\b|\bphp -r\b|\bruby -e\b|\bperl -e\b)", re.S)
SECRETS = re.compile(
    r"(\.ssh/|\.claude\.json|\.mcp\.json|\.codex/auth|\.credentials\.json|\.claude/projects/|"
    r"\.config/gh/|\.aws/|\.kube/|\.config/gcloud/|\.docker/config\.json|"
    r"\.git-credentials|\.netrc|\.npmrc|\.pypirc|\.gitconfig|_history\b|"
    r"\.env(?!\.example)\b|id_rsa|id_ed25519|id_ecdsa|\.pem\b|\.p12\b|"
    r"Library/(Cookies|Keychains|Messages)/|AppData.*(Login Data|Cookies)|"
    r"chrome-profile|/Cookies\b|Login Data|security find-)", re.I)
ENCODE_PIPE = re.compile(
    r"\b(base64|xxd|openssl (enc|base64)|certutil -encode)\b(?!.*\s-d\b).*(\||Out-File|>)\s*"
    r"(curl|wget|nc|ncat|socat|ssh|openssl s_client|Invoke-)", re.S)
LOCAL_URL = re.compile(
    r"\b(curl|wget|iwr|Invoke-WebRequest|Invoke-RestMethod)\b[^|;&]*?"
    r"(https?://)?(localhost|127\.0\.0\.1|0\.0\.0\.0|\[::1\])(:\d+)?\S*", re.I)
SSH_KEYTOOLS = re.compile(r"\s*ssh-(keygen|add|copy-id|agent)\b")
# Bash file-read verbs that would exfiltrate a secret by reading it out.
READ_VERB = re.compile(
    r"\b(cat|bat|less|more|head|tail|sed|awk|grep|rg|strings|xxd|od|hexdump|"
    r"cp|scp|rsync|tar|zip|dd|sqlite3|plutil|defaults read|Get-Content|gc|type)\b", re.I)

_GN = [norm_path(d) + os.sep for d in GUARDED_DIRS]
_GR = [real_path(d) + os.sep for d in GUARDED_DIRS]


def _under_guarded(path, base):
    n, r = norm_path(path, base), real_path(path, base)
    return any(n.startswith(d) for d in _GN) or any(r.startswith(d) for d in _GR)


def is_guarded(tool, tin, base):
    if tool in GUARDED_TOOLS:
        return True
    if tool in FILE_TOOLS:
        p = tin.get("file_path") or tin.get("notebook_path") or tin.get("path") or ""
        return bool(p) and _under_guarded(p, base)
    if tool in SHELL_TOOLS:
        return BASH_PERSIST.search(str(tin.get("command", ""))) is not None
    return False


def _slashes(s):
    """Normalise Windows backslashes so unix-style SECRETS patterns match."""
    return str(s).replace("\\", "/")


def exfil(tool, tin):
    """Return (bool, shown_text)."""
    text = _dump(tin)
    if tool in SHELL_TOOLS:
        cmd = str(tin.get("command", ""))
        if SSH_KEYTOOLS.match(cmd):
            return False, cmd
        stripped = LOCAL_URL.sub(" ", cmd)
        return (bool(NET.search(stripped) and SECRETS.search(_slashes(cmd)))
                or bool(ENCODE_PIPE.search(cmd))), cmd
    if tool.startswith("mcp__") or tool == "WebFetch":
        return (SECRETS.search(_slashes(text)) is not None and len(text) > 40), text
    return False, text


def secret_read(tool, tin):
    """A Bash command (or Read tool) that reads a secret path. Used where the
    runtime has no path deny list of its own (Codex)."""
    if tool in READ_TOOLS:
        p = str(tin.get("file_path") or tin.get("path") or "")
        return SECRETS.search(_slashes(p)) is not None
    if tool in SHELL_TOOLS:
        cmd = str(tin.get("command", ""))
        return bool(READ_VERB.search(cmd) and SECRETS.search(_slashes(cmd)))
    return False


def guard_detail(tool, tin):
    if tool in GUARDED_TOOLS:
        keys = ("taskId", "title", "schedule", "cronExpression", "enabled")
        d = {k: tin.get(k) for k in keys if k in tin}
        s = _dump(d)
        if "prompt" in tin:
            s += "\nprompt: " + str(tin["prompt"])[:250]
        return s
    if tool in SHELL_TOOLS:
        return "command: " + str(tin.get("command", ""))[:300]
    p = tin.get("file_path") or tin.get("notebook_path") or tin.get("path")
    s = f"file: {p}"
    for k in ("new_string", "content"):
        if k in tin:
            s += f"\n{k}: " + str(tin[k])[:200]
            break
    return s


def _dump(o):
    import json
    try:
        return json.dumps(o, default=str)
    except Exception:
        return str(o)
