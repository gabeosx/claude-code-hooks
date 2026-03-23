# claude-code-hooks

Risk-aware Claude Code hooks for any project. Provides automatic permission decisions, context window monitoring, GSD update checks, and a configurable status line.

---

## What this is

Claude Code's default permission model prompts you for every tool call it isn't certain about. These hooks replace that with a risk-based classifier that auto-allows safe operations (reads, builds, git commands, in-repo scripts) and only prompts for genuinely risky ones (destructive operations, sensitive file access, inline interpreter execution, commands outside a git repo).

A `hook.log` is written for every tool call, including a `[WHITELIST CANDIDATE]` tag on anything that prompted but probably should have auto-allowed. That log is the input to the contribution workflow.

### Hooks included

| File | Event | Purpose |
|---|---|---|
| `pre_tool_use.py` | `PreToolUse` | Risk classifier — auto-allow or prompt |
| `gsd-check-update.js` | `SessionStart` | Check for GSD framework updates in background |
| `gsd-context-monitor.js` | `PostToolUse` | Inject context-window warnings into the agent's conversation |
| `gsd-statusline.js` | `StatusLine` | Show model, current task, working directory, context bar |
| `smoke_test.py` | (test) | Regression suite for the risk classifier |

---

## Install

### Option A — run the install script (recommended)

```bash
git clone https://github.com/gabeosx/claude-code-hooks.git
cd claude-code-hooks
./install.sh /path/to/your/project
```

The script:
- Creates `.claude/hooks/` in the target project
- Copies all hook files into it
- Merges hook wiring and allow rules into `.claude/settings.json`, preserving any existing keys
- Adds `hook.log` and `settings.local.json` to the project's `.gitignore`

Then start a new Claude Code session to pick up the changes.

### Option B — symlink (keeps hooks auto-updated)

```bash
git clone https://github.com/gabeosx/claude-code-hooks.git ~/claude-code-hooks
ln -s ~/claude-code-hooks/hooks /path/to/your/project/.claude/hooks
```

Then manually merge `settings.json` into `.claude/settings.json`.

---

## How the risk-aware permission hook works

`pre_tool_use.py` receives each tool call as JSON on stdin before Claude Code executes it. It exits `0` to auto-allow (no prompt) or `1` to ask (show the normal permission prompt).

### Decision rules

| Condition | Decision |
|---|---|
| Read-only tools (`Read`, `Glob`, `Grep`, `LS`) | Allow |
| `git *` commands | Allow |
| Safe read commands (`cat`, `grep`, `find`, `ls`, `head`, …) | Allow |
| Safe read command on a sensitive path (`.env`, `.pem`, `/.ssh/`, …) | Ask |
| `rm -rf` on cache/build dirs (`./dist`, `./node_modules`, `/tmp`, …) | Allow |
| `rm -rf` on other paths | Ask |
| Build/lint/test commands (`npm`, `tsc`, `vitest`, `pytest`, …) | Allow |
| Dev-ops commands (`lsof`, `ps`, `kill`, `sleep`, …) inside a git repo | Allow |
| Interpreter (`python`, `node`, `bash`) running an in-repo script | Allow |
| Interpreter with `-c`/`-e` (inline eval) or external script path | Ask |
| Destructive patterns (`shred`, `dd if=`, `mkfs`, …) | Ask |
| Anything else inside a git repo | Allow |
| Anything else outside a git repo | Ask |

Compound commands (`&&`, `||`, `|`, `;`, newlines) are split into atomic segments and each segment is scored independently — the whole command asks if any segment asks.

### Log format

```
2026-03-23T14:30:01 | ALLOW | Bash                 | git status                                                   | git command
[WHITELIST CANDIDATE] 2026-03-23T14:31:05 | ASK   | Bash                 | gh repo create gabeosx/foo --public                          | unclassified command outside git repo
```

---

## Personal overrides

Create `.claude/settings.local.json` in your project to add allow rules that apply only to you without affecting the committed `settings.json`:

```json
{
  "permissions": {
    "allow": [
      "Bash(gh *)"
    ]
  }
}
```

This file is gitignored and never committed.

---

## Contributing: the `[WHITELIST CANDIDATE]` workflow

1. After a session, scan the log for candidates:
   ```bash
   grep '\[WHITELIST CANDIDATE\]' .claude/hooks/hook.log
   ```

2. If a command should have auto-allowed, open a PR using the **Whitelist request** issue template in this repo.

3. The PR must include a regression test case in `smoke_test.py` (`expected: "allow"`).

4. All files under `hooks/` and `settings.json` require review by `@gabeosx` via CODEOWNERS.

5. CI runs `python3 hooks/smoke_test.py` on every PR that touches `hooks/` or `settings.json`. The PR is blocked if any existing `ALLOW` case regresses.

---

## CI

`.github/workflows/smoke-test.yml` runs the full regression suite on every PR that touches the hook logic. No deployment required — it's pure Python with no external dependencies.
