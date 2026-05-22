# Design: Distinct Audio Alerts for Claude Code Completion Events

**Date:** 2026-05-22
**Status:** Approved (ready for implementation plan)

## Goal

Play a distinct sound when Claude Code finishes work, differentiating four
native lifecycle "completion" hook events so the sound itself tells the user
*what* finished. Behavior is driven by an editable settings file (the
`.claude/*.local.md` plugin-settings pattern).

## Events and default sounds

| Hook event      | Meaning                                             | Default sound (`C:\Windows\Media\`) |
|-----------------|-----------------------------------------------------|-------------------------------------|
| `Stop`          | Main agent finished its turn (normal completion)    | `Windows Notify.wav`                |
| `StopFailure`   | Turn ended in failure/error                         | `Windows Critical Stop.wav`         |
| `SubagentStop`  | A dispatched subagent (Task/Agent) completed        | `Windows Notify System Generic.wav` |
| `TaskCompleted` | A TodoWrite task-list item was marked completed     | `chimes.wav`                        |

## Approach

**Approach A — self-contained bash script + direct PowerShell playback.**
No dependency on the webhook-audio-tracker daemon. Reuses the proven playback
technique from `development/services/mcp/webhook-audio-tracker/audioManager.js`:
`powershell -NoProfile -c "(New-Object Media.SoundPlayer '<path>').PlaySync()"`.

Rejected alternatives:
- **B (curl the webhook server):** requires the daemon to be running; silent
  failure when it is down is invisible and hard to debug.
- **C (call the `play_audio_cue` MCP tool):** impossible — hooks run shell
  commands and cannot invoke MCP tools.

## Components

1. **`~/.claude/scripts/audio-alert.sh`** — the only logic. Invoked as
   `audio-alert.sh <EventName>`.
2. **`~/.claude/audio-alerts.local.md`** — global settings file shipped with the
   recommended defaults.
3. **`<project>/.claude/audio-alerts.local.md`** — optional per-project override
   (not created by default).
4. **Four hook registrations** in `~/.claude/settings.json` replacing the
   current `exit 0` stubs for `Stop`, `StopFailure`, `SubagentStop`,
   `TaskCompleted`. Each registered with `async: true`.

## Settings file schema (flat frontmatter)

```markdown
---
enabled: true
media_dir: "C:/Windows/Media"
sound_Stop: "Windows Notify.wav"
sound_StopFailure: "Windows Critical Stop.wav"
sound_SubagentStop: "Windows Notify System Generic.wav"
sound_TaskCompleted: "chimes.wav"
---
# Audio Alerts
# Set enabled: false to mute all alerts.
# Set any sound_* value to "off" (or empty) to silence that one event.
# Changes to sound mappings take effect on the next event (no restart).
# Adding/removing the hooks in settings.json requires a Claude Code restart.
```

Flat `sound_<Event>` keys (not a nested `events:` map) keep bash parsing to a
single `grep`/`sed` per key.

## Data flow

```
event fires
  -> settings.json runs:  bash audio-alert.sh <EventName>   (async)
  -> script resolves settings file:
       per-project .claude/audio-alerts.local.md  (if present, used in full)
       else ~/.claude/audio-alerts.local.md
       else built-in defaults baked into the script
  -> if enabled != true            -> exit 0 (silent)
  -> look up sound_<EventName>
  -> if value is "off"/empty        -> exit 0 (silent)
  -> validate filename + media_dir  (whitelist; see Security)
  -> join media_dir + filename; if missing fall back to ding.wav, else silent
  -> play via PowerShell Media.SoundPlayer
```

The project dir is taken from the `$CLAUDE_PROJECT_DIR` environment variable
that Claude Code exposes to hooks.

## Decisions

- **Override = full replace.** A per-project settings file, when present, fully
  replaces the global one (no per-key merge). Predictable and simple.
- **Built-in defaults in the script.** If no settings file exists anywhere, the
  recommended mapping applies, so alerts work out-of-box. The shipped global
  file exists to make the config visible and editable.
- **`async: true` on all four hooks** so audio playback never blocks the
  session. Windows Media sounds are < 2s.

## Error handling

- Missing settings file -> built-in defaults.
- `enabled` not `true` -> silent exit 0.
- `sound_<Event>` set to `off` or empty -> silent exit 0 for that event only.
- Named `.wav` not found in `media_dir` -> fall back to `ding.wav`; if that is
  also missing -> silent.
- Unknown / empty / unrecognized event argument -> silent exit 0.
- The hook must never error out or block the session because of a sound.

## Security

The `.wav` filename and `media_dir` come from a user-editable file and are
embedded into a PowerShell `-c` string, so they are an injection surface.

- **Whitelist the filename** to `^[A-Za-z0-9 ._-]+$` (letters, digits, space,
  dot, underscore, hyphen). Reject quotes, semicolons, parentheses, backticks,
  `$`, and path separators (`/`, `\`). A rejected value -> silent exit, no
  playback.
- **Validate `media_dir`** against an allowed prefix (default `C:/Windows/Media`)
  or at minimum reject shell/PowerShell metacharacters.
- Single-quote-escape the final path before embedding (`'` -> `''`) as
  defense-in-depth, consistent with `audioManager.js`.
- The event-name argument is supplied by `settings.json` (not user input) but is
  still matched against the known set `{Stop, StopFailure, SubagentStop,
  TaskCompleted}`; anything else exits silently.

## Git hygiene

The home directory is a git repository. Add `*.local.md` (or
`audio-alerts.local.md`) to the relevant `.gitignore` so the settings file is
not committed. Document the same `.gitignore` entry for per-project use.

## Testing (manual — it is audio)

1. `bash ~/.claude/scripts/audio-alert.sh Stop` -> hear `Windows Notify.wav`.
2. Repeat for `StopFailure`, `SubagentStop`, `TaskCompleted` -> each distinct.
3. Set `enabled: false` -> all four produce silence.
4. Set `sound_Stop: off` -> `Stop` silent, the other three still play.
5. Set `sound_Stop` to an invalid value (e.g. `a'; calc; '`) -> silent, no
   command executed (confirms injection guard).
6. Create a per-project `audio-alerts.local.md` with a different `sound_Stop`
   -> confirm the per-project value wins.
7. After registering hooks and restarting: finish a turn -> hear `Stop`; trigger
   a subagent -> hear `SubagentStop`.

## Out of scope (YAGNI)

- Volume control (`Media.SoundPlayer` has no volume API; the old audioManager
  notes this).
- Sound queue / overlap prevention (cues are short; overlap is acceptable).
- Custom non-Windows-Media sound packs (the path is configurable, but no asset
  bundling).
