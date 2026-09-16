"""Shared helpers for the claude-guard hooks.

Resolves a human-readable description of the session that triggered a hook:
Desktop-app session title (when available), working folder and the first
user request from the transcript. Never raises; every lookup degrades to "".
"""
import glob
import json
import os

HOME = os.path.expanduser("~")
SESS_DIR = os.path.join(HOME, "Library", "Application Support", "Claude", "claude-code-sessions")
MAX_SESSION_FILE = 2_000_000  # bytes; skip anything bigger


def session_title(sid):
    """Title the Claude Desktop app assigned to this CLI session, or ""."""
    if not sid:
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
    if not transcript_path:
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
    return text.replace("\\", "/").replace('"', "'")[:limit]
