# secretwall

Keep AI coding agents away from your `.env` files, keys and other secrets.

One command sets up Claude Code, Codex CLI, GitHub Copilot CLI, Cursor, Gemini CLI and
Windsurf to block:

- opening a secret file (`.env`, `*.pem`, `credentials.json`, `~/.ssh/id_rsa`, ...)
- shell commands that would print one (`cat .env`, `grep -r API_KEY .`, `git show HEAD:.env`)
- commands that print every environment variable (`env`, `printenv`) or a secret one (`echo $OPENAI_API_KEY`)
- commands that print credentials (`gh auth token`, `docker compose config`, `kubectl get secret -o yaml`)

It also writes the ignore files for JetBrains, Aider, Cline and Roo Code.

## Install

```sh
pipx install secretwall      # or: uv tool install secretwall
```

Or run it without installing: `uvx secretwall init`

## Use

```sh
cd your-project
secretwall init      # find secret files, set up your AI agents
secretwall doctor    # test that blocking works
secretwall leaks     # check if an agent has already seen your secrets
secretwall check "cat .env | head"   # would this be blocked?
secretwall remove    # take it out again
```

Commit `.secretwall/` and the agent config files so everyone on the project is protected.
The hook is one Python file with no dependencies. It runs on Python 3.9 or newer.

## Limits

secretwall stops accidental reads, not an attacker. A tricky command can still get
through. For a hard wall, also turn on your agent's sandbox. Windows is untested.

## License

MIT
