#!/usr/bin/env python3
"""
Risk-aware PreToolUse hook for Claude Code.

Exit 0 → auto-allow (no prompt)
Exit 1 → ask (show normal permission prompt)

Log format: .claude/hooks/hook.log
"""

import json
import os
import re
import shlex
import sys
from datetime import datetime
from pathlib import Path

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

LOG_PATH = Path(__file__).parent / "hook.log"

# Redirections: 2>/dev/null, >/dev/null, 1>&2, 2>&1, >>file, etc.
# Strip these before tokenising so they never look like command arguments.
_REDIRECT_RE = re.compile(r'\s*\d*(?:>>?&?\d*|>&\d*)/?\S*')

# npm run output header lines — not shell commands, just noise.
# Line 1: "scim-sql-server@0.1.0 dev:all"  (pkg@version scriptname)
# Line 2: "> node --env-file=.env ..."      (the script being run, prefixed with >)
_NPM_HEADER_LINE_RE = re.compile(r'^\s*(?:[^\s@]+@\S+\s+\S|>)')


def log(decision: str, tool: str, detail: str, reason: str) -> None:
    prefix = "[WHITELIST CANDIDATE] " if decision == "ask" else ""
    timestamp = datetime.now().strftime("%Y-%m-%dT%H:%M:%S")
    line = f"{prefix}{timestamp} | {decision.upper():5} | {tool:20} | {detail[:60]:60} | {reason}\n"
    try:
        with LOG_PATH.open("a") as f:
            f.write(line)
    except Exception:
        pass  # never block a tool call because logging failed


def in_git_repo() -> bool:
    """Return True if cwd is inside a git repository."""
    return git_repo_root() is not None


# ---------------------------------------------------------------------------
# Shell parsing helpers
# ---------------------------------------------------------------------------

def split_on_operators(command: str) -> list[str]:
    """
    Split *command* on &&, ||, |, ;, and newlines while respecting shell
    quoting.

    Walks the string character-by-character tracking single/double-quote
    state so that operators inside quoted strings are never treated as
    separators.  The operators themselves are discarded; only the atomic
    command segments are returned.

    ;  and \\n are treated as equivalent to && — sequential command
    separators with no conditional logic.
    """
    segments: list[str] = []
    current: list[str] = []
    in_single = False
    in_double = False
    i = 0

    while i < len(command):
        c = command[i]

        if c == "'" and not in_double:
            in_single = not in_single
            current.append(c)
            i += 1
        elif c == '"' and not in_single:
            in_double = not in_double
            current.append(c)
            i += 1
        elif c == '\\' and not in_single:
            # Consume escaped character (preserve both chars verbatim)
            current.append(c)
            if i + 1 < len(command):
                current.append(command[i + 1])
                i += 2
            else:
                i += 1
        elif not in_single and not in_double:
            two = command[i:i + 2]
            if two in ('&&', '||'):
                seg = ''.join(current).strip()
                if seg:
                    segments.append(seg)
                current = []
                i += 2
            elif c == '|':
                seg = ''.join(current).strip()
                if seg:
                    segments.append(seg)
                current = []
                i += 1
            elif c in (';', '\n'):
                # ; and newline are sequential separators, same as &&
                seg = ''.join(current).strip()
                if seg:
                    segments.append(seg)
                current = []
                i += 1
            else:
                current.append(c)
                i += 1
        else:
            current.append(c)
            i += 1

    seg = ''.join(current).strip()
    if seg:
        segments.append(seg)
    return segments


def strip_redirections(s: str) -> str:
    """Remove shell redirections from a segment string."""
    return _REDIRECT_RE.sub('', s).strip()


def tokenize(seg: str) -> list[str]:
    """
    Return shlex tokens for *seg* after stripping redirections.

    Falls back to a naive split if shlex raises (e.g. deliberately
    mismatched quotes in an attacker-controlled log injection).
    """
    clean = strip_redirections(seg)
    try:
        return shlex.split(clean)
    except ValueError:
        return clean.split()


def preprocess_command(command: str) -> str:
    """
    Normalize a raw command string before operator splitting.

    1. Remove npm run output header lines.  When `npm run <script>` executes,
       npm prints two lines before the script runs:
         scim-sql-server@0.1.0 dev:all        ← pkg@version scriptname
         > node --env-file=.env ...            ← script content, prefixed with >
       These are terminal output metadata, not shell commands.  Stripping
       them prevents the hook from attempting to parse npm internals.

    2. Newlines that remain after filtering are replaced with ; so that
       split_on_operators() treats multi-line command strings correctly.
       (split_on_operators already splits on ; as a sequential separator.)
    """
    if '\n' not in command:
        return command
    filtered = [
        line for line in command.split('\n')
        if not _NPM_HEADER_LINE_RE.match(line)
    ]
    return ';'.join(line for line in filtered if line.strip())


# ---------------------------------------------------------------------------
# Rule sets
# ---------------------------------------------------------------------------

SAFE_READ_CMDS = {
    "cat", "head", "tail", "grep", "find", "ls", "stat",
    "wc", "diff", "echo", "less", "more", "file", "which",
    "type", "pwd", "env", "printenv", "du", "df",
}

BUILD_CMDS = {
    "tsc", "eslint", "mypy", "ruff", "jest", "pytest",
    "cargo", "go", "npm", "npx", "pnpm", "yarn",
    "make", "mvn", "gradle",
    "vitest", "mocha",
}

# Interpreter commands are scored by their script-path argument, not the
# interpreter name itself — python -c "..." is not the same as python ./script.py
INTERPRETER_CMDS = {"python", "python3", "node", "ts-node", "ruby", "bash"}

GIT_CMDS = {"git"}

# Dev-ops utilities: process inspection, pipe helpers, timing, and process
# control.  These are standard tools in any development workflow and are
# always safe within a git repo context.
SAFE_DEVOPS_CMDS = {
    "lsof", "ps", "pgrep",       # process / socket inspection (read-only)
    "xargs",                      # pipe helper — safety is determined by the
                                  # piped command, not xargs itself
    "sleep", "wait",              # timing / synchronization
    "kill", "pkill", "killall",   # process termination (dev-ops, not destructive
                                  # to files or data)
}

READ_ONLY_TOOLS = {"Read", "Glob", "Grep", "LS"}

SENSITIVE_PATTERNS = (
    ".env", ".pem", ".key", ".p12", ".pfx", ".crt",
    "id_rsa", "id_ed25519", "id_ecdsa",
    "/.ssh/", "/.aws/", "/.gnupg/", "/keychain",
    "credentials", "secrets.json", "secret.json",
)

DESTRUCTIVE_PATTERNS = ("shred", "truncate", "mkfs", "dd if=", "wipefs")


def is_sensitive_path(path_str: str) -> bool:
    low = path_str.lower()
    return any(p in low for p in SENSITIVE_PATTERNS)


def git_repo_root() -> Path | None:
    """Return the root of the current git repo, or None if not in one."""
    path = Path.cwd()
    for candidate in [path, *path.parents]:
        if (candidate / ".git").exists():
            return candidate
    return None


def script_in_repo(script_arg: str) -> bool:
    """Return True if script_arg resolves to a path inside the git repo."""
    root = git_repo_root()
    if root is None:
        return False
    try:
        resolved = Path(script_arg).resolve()
        resolved.relative_to(root)
        return True
    except (ValueError, OSError):
        return False


# ---------------------------------------------------------------------------
# Per-tool decision logic
# ---------------------------------------------------------------------------

def score_segment(seg: str) -> tuple[str, str]:
    """
    Score a single atomic command segment — no pipes, no &&, no || — using
    shlex tokenisation (after stripping redirections) so that quoted args and
    shell metacharacters inside strings don't confuse the classifier.
    """
    seg = seg.strip()
    if not seg:
        return "allow", "empty segment"

    tokens = tokenize(seg)
    if not tokens:
        return "allow", "empty segment after tokenization"

    # Strip leading `cd <dir>` prefix — cd has no side effects.
    # If the whole segment is just `cd` or `cd <dir>`, allow immediately.
    if tokens[0].lstrip("(") == "cd":
        if len(tokens) <= 2:
            return "allow", "cd has no side effects"
        # Strip `cd <dir>` and score whatever follows
        tokens = tokens[2:]
        seg = shlex.join(tokens)

    # Base command: basename of first token, strip any leading subshell `(`
    cmd0 = tokens[0].lstrip("(").split("/")[-1]

    # Outright destructive patterns — string-match on segment
    for pat in DESTRUCTIVE_PATTERNS:
        if pat in seg:
            return "ask", f"destructive pattern: {pat}"

    # Sensitive file access — string-match on segment (catches paths in args)
    if cmd0 in SAFE_READ_CMDS and is_sensitive_path(seg):
        return "ask", "read-only cmd but sensitive path"

    # Git commands — always safe (reversible)
    if cmd0 in GIT_CMDS:
        return "allow", "git command"

    # Pure read-only commands
    if cmd0 in SAFE_READ_CMDS:
        return "allow", "read-only command"

    # rm -rf safety: allow on cache/build dirs, ask on src dirs
    if cmd0 == "rm":
        is_recursive = any(
            tok.startswith("-") and not tok.startswith("--") and any(c in tok for c in "rR")
            for tok in tokens[1:]
        )
        if is_recursive:
            safe_targets = (
                "./dist", "./build", "./out", "./.next", "./node_modules",
                "/tmp", "/var/folders", "/private/tmp",
                ".cache", "__pycache__", ".pytest_cache",
            )
            if any(t in seg for t in safe_targets):
                return "allow", "rm -rf on cache/build path"
            return "ask", "rm -rf on non-cache path"
        return "allow", "non-recursive rm"

    # Interpreter commands — allow only when running an in-repo script file;
    # block inline execution (python -c / node -e / bash -c) and external paths.
    if cmd0 in INTERPRETER_CMDS:
        _inline_flags = {"-c", "-e", "--eval", "--exec"}
        script = None
        for tok in tokens[1:]:
            if tok in _inline_flags:
                script = None
                break
            if not tok.startswith("-"):
                script = tok
                break
        if script and script_in_repo(script):
            return "allow", "interpreter running in-repo script"
        return "ask", "interpreter with no in-repo script (use -c flag or external path)"

    # Build/lint/test commands
    if cmd0 in BUILD_CMDS:
        return "allow", "build/lint/test command"

    # Dev-ops utilities (process inspection, pipe helpers, timing, process control)
    if cmd0 in SAFE_DEVOPS_CMDS:
        if in_git_repo():
            return "allow", "dev-ops command inside git repo"
        return "ask", "dev-ops command outside git repo"

    # Network commands
    if cmd0 in NETWORK_CMDS:
        if in_git_repo():
            return "allow", "network call inside git repo"
        return "ask", "network call outside git repo"

    # Everything else inside a git repo: allow
    if in_git_repo():
        return "allow", "inside git repo"

    return "ask", "unclassified command outside git repo"


def decide_bash(tool_input: dict) -> tuple[str, str]:
    """
    Score a full Bash command by decomposing it into atomic segments.

    Uses split_on_operators() to split on &&, ||, and | while respecting
    shell quoting, then scores each segment with score_segment().
    All segments must be safe for the command to auto-allow.
    """
    command = preprocess_command(tool_input.get("command", ""))

    segments = split_on_operators(command)
    if not segments:
        return "allow", "empty command"

    for seg in segments:
        decision, reason = score_segment(seg)
        if decision != "allow":
            return decision, reason

    return "allow", "all segments safe"


def decide_edit_write(tool_input: dict) -> tuple[str, str]:
    path = tool_input.get("file_path", tool_input.get("path", ""))

    if is_sensitive_path(path):
        return "ask", "sensitive file path"

    if in_git_repo():
        return "allow", "file edit inside git repo"

    return "ask", "file edit outside git repo"


NETWORK_CMDS = {"curl", "wget", "fetch", "http", "https"}


def decide(tool_name: str, tool_input: dict) -> tuple[str, str]:
    # Always-safe read-only tools
    if tool_name in READ_ONLY_TOOLS:
        return "allow", "read-only tool"

    # Bash needs real analysis (network commands handled inside decide_bash)
    if tool_name == "Bash":
        return decide_bash(tool_input)

    # File mutation tools
    if tool_name in ("Edit", "Write", "NotebookEdit"):
        return decide_edit_write(tool_input)

    # Agent spawning — inside git repo is fine
    if tool_name == "Agent":
        if in_git_repo():
            return "allow", "agent inside git repo"
        return "ask", "agent outside git repo"

    # Everything else: allow inside git repo, ask outside
    if in_git_repo():
        return "allow", f"tool {tool_name} inside git repo"

    return "ask", f"unclassified tool {tool_name} outside git repo"


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    """
    Entry point.  Wrapped in a top-level try/except so that any unexpected
    crash is written to hook.log with an [ERROR] prefix before exiting 1
    (ask).  Failures are never silently swallowed.
    """
    try:
        try:
            payload = json.load(sys.stdin)
        except Exception:
            # Can't parse — don't block, just ask
            log("ask", "unknown", "failed to parse stdin", "json parse error")
            sys.exit(1)

        tool_name = payload.get("tool_name", payload.get("tool", "unknown"))
        tool_input = payload.get("tool_input", payload.get("input", {}))

        # Build a short detail string for logging
        command = tool_input.get("command", "")
        file_path = tool_input.get("file_path", tool_input.get("path", ""))
        detail = command or file_path or json.dumps(tool_input)[:80]

        decision, reason = decide(tool_name, tool_input)
        log(decision, tool_name, detail, reason)

        sys.exit(0 if decision == "allow" else 1)

    except SystemExit:
        raise  # propagate sys.exit() calls unchanged
    except Exception as exc:  # noqa: BLE001
        # Hook crashed unexpectedly — log the error and fail safe (ask)
        timestamp = datetime.now().strftime("%Y-%m-%dT%H:%M:%S")
        line = f"[ERROR] {timestamp} | CRASH | {type(exc).__name__}: {exc}\n"
        try:
            with LOG_PATH.open("a") as f:
                f.write(line)
        except Exception:
            pass
        sys.exit(1)


if __name__ == "__main__":
    main()
