# Telegram Codex Broker + Agents

This setup lets you send prompts from Telegram to **desktop/laptop Codex sessions** and fetch output.

## Roles
- **broker.ps1** (desktop): Telegram bot + dispatcher
- **agent.ps1** (each machine): accepts commands and feeds a local Codex console session
- **codex_console.ps1** (each machine): launches Codex in a visible console with transcript

## Desktop Setup (broker + agent)
1. Fill `broker.env` and `agent.env`.
2. Start Codex console (required for console mode):

```powershell
pwsh -NoProfile -File .\codex_console.ps1
```

3. Start the agent (leave running):

```powershell
pwsh -NoProfile -File .\agent.ps1
```

4. Start the broker:

```powershell
pwsh -NoProfile -File .\broker.ps1
```

## Laptop Setup (agent only)
- Copy `agent.ps1`, `runner.ps1`, and `codex_console.ps1` to the laptop (same folder).
- Edit `agent.env`:
  - `AGENT_NAME=lap`
  - `AGENT_SECRET` must match the broker’s `AGENT_SECRET`
  - `CODEX_WINDOW_TITLE` must match the title used by `codex_console.ps1`
- Start Codex console:

```powershell
pwsh -NoProfile -File .\codex_console.ps1
```

- Start the agent:

```powershell
pwsh -NoProfile -File .\agent.ps1
```

## Telegram Commands
Use `<target>` as `pc` or `lap` (from `TARGET_*` in `broker.env`).

- `<target> codex <prompt>` — send prompt to the active Codex console session
- `<target> codexlast [lines]` — tail the Codex transcript

Optional job runner (less used):
- `<target> run <cmd>`
- `<target> last [lines]`
- `<target> tail <jobId> [lines]`
- `<target> get <jobId>`

If you omit `<target>`, broker uses `DEFAULT_TARGET`.

## Notes
- Console mode requires a visible Codex console window (can be minimized).
- The console window title is set by `codex_console.ps1` (default: `CODEX_BRIDGE`).
- Transcript file default: `logs\codex_console.log`.
- Logs live in `logs/` on each agent.
- Keep `AGENT_SECRET` the same on broker + agents.
