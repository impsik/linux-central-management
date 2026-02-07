#!/usr/bin/env bash
set -euo pipefail

# Sanitize repo for public GitHub upload.
# Default: dry-run (prints what would be removed).
# Use --apply to actually remove.

APPLY=0
if [[ "${1:-}" == "--apply" ]]; then
  APPLY=1
fi

say() { printf "%s\n" "$*"; }

do_rm() {
  local path="$1"
  if [[ ! -e "$path" ]]; then
    return
  fi
  if [[ "$APPLY" -eq 0 ]]; then
    say "DRY-RUN: would remove $path"
    return
  fi
  say "Removing $path"
  rm -rf -- "$path"
}

say "Sanitize (dry-run=$((1-APPLY)))"

# Secrets / local env
# NOTE: never commit these.
do_rm "deploy/docker/.env"
do_rm ".env"

# Logs + build artifacts
# (These should also be ignored by .gitignore)
do_rm "ansible_logs"
do_rm "agent/fleet-agent"

# Local virtualenvs (never commit)
do_rm "server/.venv"
do_rm "server/.venv312"
do_rm "server/.venv313"
do_rm ".venv"

# Common Python junk
find server -type d -name "__pycache__" -print0 | while IFS= read -r -d '' d; do
  do_rm "$d"
done
find server -type f -name "*.pyc" -print0 | while IFS= read -r -d '' f; do
  do_rm "$f"
done

# Misc dev caches
find . -type d \( -name ".pytest_cache" -o -name ".mypy_cache" -o -name ".ruff_cache" -o -name "htmlcov" \) -print0 | while IFS= read -r -d '' d; do
  do_rm "$d"
done
find . -type f \( -name ".coverage" -o -name "coverage.xml" \) -print0 | while IFS= read -r -d '' f; do
  do_rm "$f"
done

say "Done."

if [[ "$APPLY" -eq 0 ]]; then
  say "Tip: run with --apply to actually delete the files." 
fi
