# claude-guard

Guardrails for running Claude Code agents unattended on a Mac, without a human
pressing Allow all day.

It does three things:

1. **Never list.** A `permissions.deny` set that stops agents from reading your
   secrets, cookies and transcripts, from editing their own rules and hooks,
   from using `sudo`, Keychain or AppleScript, and from flipping their own
   permission mode or connectors. Deny beats allow in every mode, including
   auto and bypass.
2. **Guard dialog.** Anything that creates persistence (scheduled tasks,
   launch agents, shell rc files, `~/.claude/commands` and `agents`, the
   guard's own state) triggers one macOS dialog per session showing who is
   asking and what changes. Allow covers that session for 30 minutes. It
   watches the file tools, the scheduled-task MCP tools and Bash command text.
3. **Exfil alarm.** When the auto-mode classifier denies a command that looks
   like data exfiltration (network sink + secret path, or an encode-and-pipe
   into a network sink), the session freezes and a red dialog shows session
   title, folder, original request and the exact command, with an Unfreeze
   button.

No prompts are added to normal work. Sessions stay in `auto` mode; the only
new interaction is the guard dialog, and only when an agent touches
persistence.

## Requirements

- macOS (uses `osascript` dialogs and the login Keychain)
- Claude Code with `permissions.defaultMode: "auto"` (the alarm listens to the
  classifier's `PermissionDenied` event; in other modes it never fires, the
  never list and guard dialog still work)
- Python 3.6+ on PATH or Command Line Tools installed. The installer records
  the absolute interpreter path, so later PATH changes don't matter.

## Install

```bash
git clone https://github.com/dancolta/claude-guard
cd claude-guard
python3 install.py
```

Run it yourself in a terminal, not through an agent. After install, agents
cannot edit `~/.claude/settings.json` or `~/.claude/hooks/`, so any future
change to the guard also has to come from you. Restart open sessions.

`install.py` copies the hooks to `~/.claude/hooks/claude-guard/` and locks them
with `chflags uchg`, registers them with an absolute interpreter path, merges
`deny.json` into your deny list without duplicates, turns on
`autoMode.classifyAllShell` so no allow rule skips the classifier, and backs up
`settings.json` when it changes. Removal (`python3 install.py --uninstall`)
drops only the rules it added.

## Honest limits

- **Same uid.** Hooks, deny rules and the Keychain grant all live in the same
  user account as the agent. They stop prompt-injected *tool calls*; a shell
  the agent already runs can, in principle, forge the grant with
  `/usr/bin/security` or overwrite the hook after `chflags nouchg`. Both are
  denied by rule and flagged by the Bash tripwire, so the classifier sees
  them; they are not physically impossible. Real containment is Claude Code's
  sandbox (`sandbox.enabled`) or a separate macOS user for untrusted pipelines.
- **Text, not semantics.** A deny on `Bash(security:*)` stops the literal
  command, not a Python subprocess. The classifier and sandbox cover that.
- **Freeze stops tool calls, not running processes.** A background job
  started before the freeze keeps running.
- **Dialogs can be clicked by GUI automation.** `mcp__computer-use__*` is
  denied for that reason; keep other GUI-automation tools out of agent reach.
- **Skills are not guarded** (`~/.claude/skills`). Unattended tasks commonly
  write there. A scheduled task that invokes a skill executes whatever that
  skill says, so treat skill edits as persistence and review them.
- **Fail-closed by design.** If the hook crashes, its interpreter is missing
  or its state dir is tampered with, the circuit breaker blocks and says so.
  A headless session (ssh, no GUI) gets no dialog: guarded actions are denied,
  and a freeze is cleared with `rm ~/.claude/guard/frozen/<session_id>`.
- **Nothing is logged.** While a session is frozen, its flag file
  (`0600`) holds the blocked command so the dialog can show it; the dialog
  text is passed to `osascript` over stdin, not argv.

## Files

| file | role |
|---|---|
| `hooks/circuit_breaker.py` | PreToolUse, matcher `*`: freeze check + guard dialog |
| `hooks/exfil_alarm.py` | PermissionDenied, matcher `*`: exfil heuristic + alarm dialog |
| `hooks/guardctx.py` | context lookup, AppleScript helper, path normalisation |
| `deny.json` | the never list, edit before installing |
| `install.py` | idempotent installer and uninstaller |

State: `~/.claude/guard/frozen/<session_id>` while frozen; a Keychain item
`claude-guard-unlock` per granted session (30 min).

## Tuning

- Guarded paths, tools and Bash patterns: `GUARDED_DIRS`, `GUARDED_TOOLS`,
  `BASH_TRIPWIRE` in `circuit_breaker.py`.
- Grant length: `GRANT_SECONDS`. Dialog timeout: `DIALOG_SECONDS` (unattended
  sessions get an automatic deny when it expires).
- Exfil heuristic: `NET`, `SECRETS`, `ENCODE_PIPE`, `MCP_SECRET_PATH` in
  `exfil_alarm.py`.

## License

MIT
