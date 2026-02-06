# Telegram Codex Broker + Agents

This setup lets you send prompts from Telegram to **desktop/laptop Codex sessions** and fetch output.

## Roles
- **broker.ps1** (desktop): Telegram bot + dispatcher
- **agent.ps1** (each machine): accepts commands and runs Codex in headless exec mode
- **codex_console.ps1** (optional): launches Codex in a visible console with transcript (fallback mode)

## Desktop Setup (broker + agent)
1. Fill `broker.env` and `agent.env`.
2. Start the agent (leave running):

```powershell
pwsh -NoProfile -File .\agent.ps1
```

3. Start the broker:

```powershell
pwsh -NoProfile -File .\broker.ps1
```

## Laptop Setup (agent only)
- Copy `agent.ps1` and `runner.ps1` to the laptop (same folder).
- Edit `agent.env`:
  - `AGENT_NAME=lap`
  - `AGENT_SECRET` must match the broker’s `AGENT_SECRET`
  - `CODEX_MODE=exec` (default) for headless mode
- Start the agent:

```powershell
pwsh -NoProfile -File .\agent.ps1
```

## Telegram Commands
Use `<target>` as `pc` or `lap` (from `TARGET_*` in `broker.env`).

- `<target> codex <prompt>` — send prompt to the active Codex session
- `<target> codexlast [lines]` — tail the Codex output
- `<target> codexsession` — show stored Codex thread id
- `<target> codexmodel [model] [reset]` — show or set the Codex model (optional `reset` clears the thread id)
- `<target> codexjob` — show current Codex job status (async mode)
- `<target> codexcancel` — cancel the running Codex job (async mode)
- `<target> codexuse <thread_id>` — resume a specific thread id
- `<target> codexreset` — clear stored thread id
- `<target> codexfresh <prompt>` — start a fresh thread for this prompt

Optional job runner (less used):
- `<target> run <cmd>`
- `<target> last [lines]`
- `<target> tail <jobId> [lines]`
- `<target> get <jobId>`

If you omit `<target>`, broker uses `DEFAULT_TARGET`.

## Notes
- Headless exec mode is default (`CODEX_MODE=exec`) and does not require a window.
  - Set `CODEX_CWD` to your preferred non‑repo directory (default is `C:\dev\tri`).
  - Set `CODEX_MODEL` if you want to force a specific model (otherwise Codex CLI default is used).
  - Set `CODEX_ASYNC=1` to queue Codex runs so the agent stays responsive (default: on).
- Console mode is optional: set `CODEX_MODE=console` and start `codex_console.ps1`.
- Logs live in `logs/` on each agent.
- Keep `AGENT_SECRET` the same on broker + agents.
- If `CODEX_APPEND_SESSION=1`, the agent appends the real Codex thread id, model, perms, and cwd to every response.
- Broker auto-clears any webhook on startup and refuses to run if another broker is already active.
- Multi-line Telegram messages are treated as separate commands (one per line).

## Voice-to-text (optional)
You can send a Telegram voice message and have it transcribed and routed as a command.

Set `STT_CMD` in `broker.env` (or `broker.env.example`) to a command that prints the transcript to stdout.
Use `{input}` as a placeholder for the downloaded audio file path.

Example (whisper.cpp):
```
STT_CMD=whisper.exe -m C:\models\ggml-base.en.bin -f {input} -otxt -of C:\dev\tri\ops\telebot\logs\stt
```

If the transcribed text does not start with a known command or target, it will be treated as:
`<DEFAULT_TARGET> codex <transcript>`.

Optional:
- `STT_TIMEOUT_SEC` (default 120)
- `VOICE_TARGET` (forces a target, e.g. `pc` or `lap`)

## Update + restart (optional)
If you want a one‑shot updater that pulls latest, reapplies secrets, and restarts:

1) Create a local secret file (not committed):

```
AGENT_SECRET=your_shared_secret
```

Save it at:

`C:\dev\tri\ops\telebot\secret.env`

2) Run the updater:

```
pwsh -NoProfile -File C:\dev\tri\ops\telebot\update_and_start.ps1
```

You can also set `CODEXBRIDGE_AGENT_SECRET` or `TELEBOT_AGENT_SECRET` env vars instead of a file.
