#!/bin/bash
# Akira Installer - installs Akira skills into your AI environment
# Usage: bash install.sh

set -e

AKIRA_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CLAUDE_SKILLS_DIR="$HOME/.claude/skills"
SKILL_COUNT=$(ls -d "$AKIRA_DIR/skills"/*/ 2>/dev/null | wc -l | tr -d ' ')

echo ""
echo "  Akira Pentest Skill Suite - Installer"
echo "  ======================================"
echo ""

# Claude Code install
echo "Installing $SKILL_COUNT skills to $CLAUDE_SKILLS_DIR ..."
mkdir -p "$CLAUDE_SKILLS_DIR"

for skill_dir in "$AKIRA_DIR"/skills/*/; do
    skill_name=$(basename "$skill_dir")
    if [ -d "$CLAUDE_SKILLS_DIR/$skill_name" ]; then
        echo "  Updating: $skill_name"
    else
        echo "  Installing: $skill_name"
    fi
    cp -r "$skill_dir" "$CLAUDE_SKILLS_DIR/"
done

# Platform adapters
if [ -f "$AKIRA_DIR/platform-adapters/GEMINI.md" ]; then
    echo ""
    echo "  Gemini CLI: see platform-adapters/GEMINI.md"
fi
if [ -f "$AKIRA_DIR/platform-adapters/.cursor/rules/akira.mdc" ]; then
    echo "  Cursor: see platform-adapters/.cursor/rules/"
fi

echo ""
echo "  Done. $SKILL_COUNT skills installed."
echo ""
echo "  Start your first engagement:"
echo "    /plan-engagement <target>"
echo ""
echo "  Run bootstrap.sh to install tools (nuclei, dalfox, subfinder, etc.)"
echo ""
