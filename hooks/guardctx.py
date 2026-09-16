"""Shared helpers for the claude-guard hooks.

Resolves a human-readable description of the session that triggered a hook:
Desktop-app session title (when available), working folder and the first
user request from the transcript. Never raises; every lookup degrades to "".
"""
import glob
import json
import os
import re
import subprocess
import unicodedata

HOME = os.path.expanduser("~")
SESS_DIR = os.path.join(HOME, "Library", "Application Support", "Claude", "claude-code-sessions")
MAX_SESSION_FILE = 2_000_000  # bytes; skip anything bigger
SID_RE = re.compile(r"(?!\.{1,2}$)[A-Za-z0-9_.-]{1,128}")


def valid_sid(sid):
    return bool(sid) and SID_RE.fullmatch(sid) is not None


def session_title(sid):
    """Title the Claude Desktop app assigned to this CLI session, or ""."""
    if not valid_sid(sid):
        return ""
    try:
        for f in glob.glob(os.path.join(SESS_DIR, "*", "*", "*.json")):
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
    """First human message in the session transcript, whitespace-collapsed."""
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


def dialog_safe(text, limit=900):
    """Make text safe to embed inside an AppleScript string literal."""
    text = str(text).replace("\x00", "")
    return text.replace("\\", "/").replace('"', "'")[:limit]


def run_applescript(script, timeout=None, detach=False):
    """Run AppleScript from stdin so its text never appears in `ps` output.

    Returns stdout (str) when not detached, "" otherwise. Never raises.
    """
    try:
        if detach:
            p = subprocess.Popen(["/usr/bin/osascript", "-"], stdin=subprocess.PIPE,
                                 stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                 start_new_session=True)
            p.stdin.write(script.encode("utf-8"))
            p.stdin.close()
            return ""
        r = subprocess.run(["/usr/bin/osascript", "-"], input=script, capture_output=True,
                           text=True, timeout=timeout)
        return r.stdout
    except Exception:
        return ""


def norm_path(p, base=None):
    """Absolute, unicode-normalised, case-folded path (no symlink resolution)."""
    p = os.path.expanduser(str(p))
    if not os.path.isabs(p):
        p = os.path.join(base or os.getcwd(), p)
    p = os.path.normpath(p)
    return unicodedata.normalize("NFC", p).casefold()


def real_path(p, base=None):
    """Like norm_path but with symlinks resolved."""
    p = os.path.expanduser(str(p))
    if not os.path.isabs(p):
        p = os.path.join(base or os.getcwd(), p)
    return unicodedata.normalize("NFC", os.path.realpath(p)).casefold()
