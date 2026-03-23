#!/usr/bin/env bash
# install.sh — Install claude-code-hooks into any project
#
# Usage:
#   ./install.sh              # installs into current working directory
#   ./install.sh /path/to/project
#
# What it does:
#   1. Copies all hook files into .claude/hooks/
#   2. Merges hook wiring and allow rules from settings.json into .claude/settings.json
#   3. Adds hook.log and settings.local.json to .gitignore
#   4. Prints a summary of what was installed

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="${1:-$(pwd)}"

echo ""
echo "Installing claude-code-hooks into: $PROJECT_DIR"
echo ""

# ── 1. Create .claude/hooks/ ──────────────────────────────────────────────────
HOOKS_DIR="$PROJECT_DIR/.claude/hooks"
mkdir -p "$HOOKS_DIR"

# ── 2. Copy hook files ────────────────────────────────────────────────────────
HOOKS=(
  "pre_tool_use.py"
  "smoke_test.py"
  "gsd-check-update.js"
  "gsd-context-monitor.js"
  "gsd-statusline.js"
)

echo "Hook files:"
for f in "${HOOKS[@]}"; do
  cp "$SCRIPT_DIR/hooks/$f" "$HOOKS_DIR/$f"
  echo "  ✓ .claude/hooks/$f"
done

# ── 3. Merge settings.json ────────────────────────────────────────────────────
SETTINGS_FILE="$PROJECT_DIR/.claude/settings.json"
SOURCE_SETTINGS="$SCRIPT_DIR/settings.json"

echo ""
echo "Settings:"

python3 - "$SOURCE_SETTINGS" "$SETTINGS_FILE" <<'EOF'
import json, sys, os

source_path = sys.argv[1]
target_path = sys.argv[2]

with open(source_path) as f:
    source = json.load(f)

# Load existing or start fresh
if os.path.exists(target_path):
    with open(target_path) as f:
        try:
            target = json.load(f)
        except json.JSONDecodeError:
            target = {}
    existed = True
else:
    target = {}
    existed = False

# Merge hooks: add hook entries that aren't already present (match by command string)
for event, event_config in source.get("hooks", {}).items():
    if "hooks" not in target:
        target["hooks"] = {}
    if event not in target["hooks"]:
        target["hooks"][event] = event_config
    else:
        # Collect existing command strings for this event
        existing_cmds = set()
        for entry in target["hooks"][event]:
            for h in entry.get("hooks", []):
                if "command" in h:
                    existing_cmds.add(h["command"])
        # Add any source entries whose commands aren't already present
        for entry in event_config:
            for h in entry.get("hooks", []):
                if h.get("command") not in existing_cmds:
                    target["hooks"][event].append(entry)
                    break

# Merge statusLine: only set if not already configured
if "statusLine" not in target:
    target["statusLine"] = source["statusLine"]

# Merge permissions.allow: union of both lists, preserving order, no duplicates
source_allows = source.get("permissions", {}).get("allow", [])
if source_allows:
    if "permissions" not in target:
        target["permissions"] = {}
    if "allow" not in target["permissions"]:
        target["permissions"]["allow"] = []
    existing_set = set(target["permissions"]["allow"])
    added = []
    for rule in source_allows:
        if rule not in existing_set:
            target["permissions"]["allow"].append(rule)
            existing_set.add(rule)
            added.append(rule)

with open(target_path, "w") as f:
    json.dump(target, f, indent=2)
    f.write("\n")

if existed:
    print(f"  ✓ Merged into existing {target_path}")
else:
    print(f"  ✓ Created {target_path}")
EOF

# ── 4. Update .gitignore ──────────────────────────────────────────────────────
GITIGNORE="$PROJECT_DIR/.gitignore"
echo ""
echo ".gitignore:"

add_to_gitignore() {
  local entry="$1"
  if [ -f "$GITIGNORE" ] && grep -qF "$entry" "$GITIGNORE" 2>/dev/null; then
    echo "  - $entry (already present)"
  else
    echo "$entry" >> "$GITIGNORE"
    echo "  ✓ Added $entry"
  fi
}

add_to_gitignore "hook.log"
add_to_gitignore "settings.local.json"

# ── 5. Summary ────────────────────────────────────────────────────────────────
echo ""
echo "Done. ${#HOOKS[@]} hooks installed."
echo ""
echo "Next step: start a new Claude Code session to pick up the changes."
echo "The hooks take effect on next session start — they are not applied"
echo "to sessions that were already open when you ran this script."
echo ""
