# Telegram Codex Broker + Agents

This setup lets you send commands from Telegram to a local agent that runs `codex exec` (and optionally a visible Codex console).

## Roles
- `broker.ps1`: Telegram bot + dispatcher
- `agent.ps1`: accepts commands and runs Codex in headless exec mode (plus optional job runner)
- `codex_console.ps1` (optional): launches Codex in a visible console with transcript (console mode)

Recommended topology is **per-machine**:
- One Telegram bot token per machine (avoids `getUpdates` polling collisions)
- Each machine runs its own `broker.ps1` + `agent.ps1`
- Broker dispatches to the local agent by default (even if you do not configure any `TARGET_*`)

Router mode (one broker dispatching to multiple agents) is still supported via `TARGET_*` (see `broker.env.router.example`).

## Setup (Per Machine Broker)
1. Create local env files (these are `.gitignore`d):
- Copy `agent.env.example` -> `agent.env`
- Copy `broker.env.example` -> `broker.env`

2. Ensure `AGENT_SECRET` matches in both files.

3. Start the agent (leave running):

```powershell
pwsh -NoProfile -File .\agent.ps1
```

4. Start the broker:

```powershell
pwsh -NoProfile -File .\broker.ps1
```

## Telegram Commands
Target prefix is optional:
- `[<target>] codex <prompt>`: send prompt to the active Codex thread
- `[<target>] codexnew <prompt>`: fresh thread for this prompt (no resume)
- `[<target>] codexfresh <prompt>`: reset thread then run prompt
- `[<target>] codexlast [lines]`: tail the last Codex output
- `[<target>] codexsession`: show stored Codex thread id
- `[<target>] codexmodel [model] [reset]`: show or set the Codex model (optional `reset` clears the thread id)
- `[<target>] codexjob`: show current Codex job status (async mode)
- `[<target>] codexcancel` (alias: `cancel`): cancel the running Codex job (async mode)
- `[<target>] codexuse <thread_id>`: resume a specific thread id (alias: `codexresume`)
- `[<target>] codexreset`: clear stored thread id
- `[<target>] status`: show agent status

Default: if the message does not start with a known command/target, it is treated as:
`<DEFAULT_TARGET> codex <text>`.

Convenience: `[<target>] codex status|job|cancel|last|session` are treated as control commands (not prompts).

Async QoL:
- If `CODEX_ASYNC=1`, the broker immediately acknowledges with a job id and automatically posts the final Codex output when the job completes (no need to poll `codexlast`).

Optional job runner (less used):
- `[<target>] run <cmd>`
- `[<target>] last [lines]`
- `[<target>] tail <jobId> [lines]`
- `[<target>] get <jobId>`

If you omit `<target>`, broker uses `DEFAULT_TARGET`.

## Notes
- Headless exec mode is default (`CODEX_MODE=exec`) and does not require a window.
- Set `CODEX_CWD` to your preferred working directory.
- Set `CODEX_MODEL` and `CODEX_REASONING_EFFORT` to force model selection.
- Set `CODEX_ASYNC=1` to queue Codex runs so the agent stays responsive.
- Console mode is optional: set `CODEX_MODE=console` and start `codex_console.ps1`.
  - In console mode, `codexnew <prompt>` restarts the console window first, then sends the prompt (fresh session).
- Logs live in `logs/` on each agent.
- Keep `AGENT_SECRET` the same on broker + agents.
- If `CODEX_APPEND_SESSION=1`, the agent appends the Codex thread id, model, perms, and cwd to every response.
- Broker clears any webhook on startup and refuses to run if another broker is already active.
- Multi-line Telegram messages are treated as separate commands (one per line).
- If a target agent is offline, the broker fails fast (see `AGENT_CONNECT_TIMEOUT_SEC` in `broker.env`).

## Voice-to-Text (Optional)
You can send a Telegram voice message and have it transcribed and routed as a command.

Set `STT_CMD` in `broker.env` to a command that prints the transcript to stdout.
Use `{input}` as a placeholder for the downloaded audio file path.

Example (whisper.cpp):
```
STT_CMD=whisper.exe -m C:\models\ggml-base.en.bin -f {input} -otxt -of C:\dev\unity_clean\CodexBridge\logs\stt
```

Optional:
- `STT_TIMEOUT_SEC` (default 120)
- `VOICE_TARGET` (forces a target, e.g. `pc` or `lap`)

If the transcribed text does not start with a known command or target, it will be treated as:
`<DEFAULT_TARGET> codex <transcript>`.

## Update + Restart (Optional)
If you want a one-shot updater that pulls latest, reapplies secrets, and restarts:

1) Create a local secret file (not committed):
```
AGENT_SECRET=your_shared_secret
```

Save it at:
`C:\dev\unity_clean\CodexBridge\secret.env`

2) Run the updater:
```powershell
pwsh -NoProfile -File C:\dev\unity_clean\CodexBridge\update_and_start.ps1
```

You can also set `CODEXBRIDGE_AGENT_SECRET` or `TELEBOT_AGENT_SECRET` env vars instead of a file.

By default the updater starts the agent, and starts the broker whenever `broker.env` has `TG_BOT_TOKEN` set.
Override with:
```powershell
pwsh -NoProfile -File .\update_and_start.ps1 -Role agent
pwsh -NoProfile -File .\update_and_start.ps1 -Role broker
pwsh -NoProfile -File .\update_and_start.ps1 -Role both
```

On laptops, broker autostart is disabled by default. Override with:
- `set TELEBOT_AUTOSTART=1` then run the script, or
- `pwsh -NoProfile -File .\update_and_start.ps1 -Force`

