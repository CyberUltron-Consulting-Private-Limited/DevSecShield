#!/usr/bin/env bash
set -euo pipefail

cat <<'JSON'
{
  "continue": true,
  "systemMessage": "STRICT WORKSPACE ENFORCEMENT (MANDATORY): Apply .github/instructions/Copilot.instructions.md and .github/copilot-instructions.md for every request in every chat. Follow the full production-grade lifecycle and constraints defined there exactly (brainstorming -> debug -> plan -> execute -> review -> verify), treat the current user ask as {query}, and do not bypass required skills or live verification when applicable."
}
JSON
