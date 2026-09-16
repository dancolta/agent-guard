# claude-guard

Guardrails for running Claude Code agents unattended on a Mac, without a human
pressing Allow all day.

It does three things:

1. **Never list.** A `permissions.deny` set that stops agents from reading your
   secrets, cookies and transcripts, from editing their own rules and hooks,
   from using `sudo`, Keychain or AppleScript, and from flipping their own
   permission mode or connectors. Deny beats allow in every mode, including
   auto and bypass.
2. **Guard dialog.** Changing scheduled tasks (persistence) triggers one macOS
   dialog per session showing who is asking and what changes. Allow covers that
   session for 30 minutes. A poisoned web page can type a magic phrase; it
   cannot click a native dialog.
3. **Exfil alarm.** When the auto-mode classifier denies a command that looks
   like data exfiltration (network tool + secret path, or an encode-and-pipe),
   the session freezes and a red dialog shows session title, folder, original
   request and the exact command, with an Unfreeze button. Nothing is logged.

No prompts are added to normal work. Sessions stay in `auto` mode; the only new
interaction is the guard dialog, and only when an agent touches scheduled tasks.

## Requirements

- macOS (uses `osascript` dialogs and the login Keychain)
- Claude Code with `permissions.defaultMode: "auto"` (the alarm listens to the
  classifier's `PermissionDenied` event; in other modes it simply never fires)
- Python 3, already present on macOS

## Install

```bash
git clone https://github.com/dancolta/claude-guard
cd claude-guard
python3 install.py
```

Run it yourself in a terminal, not through an agent. After install, agents
cannot edit `~/.claude/settings.json` or `~/.claude/hooks/`, so any future
change to the guard also has to come from you. Restart open sessions.

`install.py` copies the hooks to `~/.claude/hooks/claude-guard/`, registers
them, merges `deny.json` into your deny list without duplicates, turns on
`autoMode.classifyAllShell` so no allow rule skips the classifier, and backs up
`settings.json` next to itself.

Remove everything with `python3 install.py --uninstall`.

## What it does not do

- It does not sandbox Bash. Pair it with Claude Code's built-in sandbox
  (`sandbox.enabled`) for network and filesystem containment.
- It does not see inside scripts. A deny on `Bash(security:*)` stops the
  literal command, not a Python subprocess. That is what the classifier and the
  sandbox are for.
- It does not cover MCP servers' own network access.
- It is not a substitute for running untrusted-content pipelines under a
  separate macOS user account.

## Files

| file | role |
|---|---|
| `hooks/circuit_breaker.py` | PreToolUse, matcher `*`: freeze check + guard dialog |
| `hooks/exfil_alarm.py` | PermissionDenied, matcher `*`: exfil heuristic + alarm dialog |
| `hooks/guardctx.py` | session title / folder / first request lookup |
| `deny.json` | the never list, edit before installing |
| `install.py` | idempotent installer and uninstaller |

State lives only in `~/.claude/guard/frozen/<session_id>` while a session is
frozen, and in a Keychain item `claude-guard-unlock` while a grant is active.

## Tuning

- Guarded paths and tools: `GUARDED_DIRS`, `GUARDED_TOOLS` in `circuit_breaker.py`.
- Grant length: `GRANT_SECONDS`. Dialog timeout: `DIALOG_SECONDS` (unattended
  sessions get an automatic deny when it expires).
- Exfil heuristic: `NET`, `SECRETS`, `ENCODE_PIPE` in `exfil_alarm.py`.

## License

MIT
