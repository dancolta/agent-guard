"""Session context and small cross-platform string/path helpers.

Never raises; every lookup degrades to "". Works for both Claude Code and
Codex CLI hook payloads (they share session_id / tool_name / tool_input /
cwd / transcript_path on stdin).
"""
import glob
import json
import os
import re
import unicodedata

HOME = os.path.expanduser("~")
# Claude Desktop stores session titles here; absent for Codex/CLI, degrades to "".
CLAUDE_SESS_DIR = os.path.join(
    HOME, "Library", "Application Support", "Claude", "claude-code-sessions")
MAX_SESSION_FILE = 2_000_000
SID_RE = re.compile(r"(?!\.{1,2}$)[A-Za-z0-9_.\-]{1,128}")


def valid_sid(sid):
    return bool(sid) and SID_RE.fullmatch(sid) is not None


def session_title(sid):
    if not valid_sid(sid) or not os.path.isdir(CLAUDE_SESS_DIR):
        return ""
    try:
        for f in glob.glob(os.path.join(CLAUDE_SESS_DIR, "*", "*", "*.json")):
            try:
                if os.path.getsize(f) > MAX_SESSION_FILE:
                    continue
                with open(f, encoding="utf-8") as fh:
                    raw = fh.read()
                if sid not in raw:
                    continue
                d = json.loads(raw)
                if d.get("cliSessionId") == sid and d.get("title"):
                    return str(d["title"])[:120]
            except Exception:
                continue
    except Exception:
        pass
    return ""


def first_prompt(transcript_path, limit=140):
    if not transcript_path or not str(transcript_path).endswith(".jsonl"):
        return ""
    try:
        with open(transcript_path, encoding="utf-8") as fh:
            for _ in range(300):
                line = fh.readline()
                if not line:
                    break
                if '"type":"user"' not in line and '"type": "user"' not in line:
                    continue
                j = json.loads(line)
                c = j.get("message", {}).get("content", "")
                if isinstance(c, list):
                    c = next((x.get("text", "") for x in c
                              if isinstance(x, dict) and x.get("type") == "text"), "")
                c = " ".join(str(c).split())
                if c and not c.startswith("<"):
                    return c[:limit]
    except Exception:
        pass
    return ""


def describe(data):
    """Multi-line context block for dialogs."""
    sid = str(data.get("session_id", ""))
    title = session_title(sid) or "(untitled session)"
    cwd = str(data.get("cwd", ""))
    asked = first_prompt(str(data.get("transcript_path", "")))
    lines = [f"Session: {title}   [{sid[:8]}]", f"Folder: {cwd}"]
    if asked:
        lines.append(f"Asked to: {asked}")
    return "\n".join(lines)


def clean_text(text, limit=900):
    """Strip control chars; cap length. Dialog back-ends do their own escaping."""
    text = str(text).replace("\x00", "")
    text = "".join(ch for ch in text if ch >= " " or ch in "\n\t")
    return text[:limit]


def _norm(p, base, resolve):
    p = os.path.expanduser(str(p))
    if not os.path.isabs(p):
        p = os.path.join(base or os.getcwd(), p)
    p = os.path.realpath(p) if resolve else os.path.normpath(p)
    p = unicodedata.normalize("NFC", p)
    return os.path.normcase(p)  # case-folds on Windows/macOS, no-op on Linux


def norm_path(p, base=None):
    return _norm(p, base, resolve=False)


def real_path(p, base=None):
    return _norm(p, base, resolve=True)
