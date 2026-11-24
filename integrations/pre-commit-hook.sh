#!/usr/bin/env bash
# SkillGuard pre-commit hook — scan staged/changed skill directories.
# Install: see examples/pre-commit-config.yaml or copy into .git/hooks/pre-commit
set -euo pipefail

ROOT="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
cd "$ROOT"

if ! command -v skillguard >/dev/null 2>&1; then
  echo "skillguard not found on PATH; install with: pip install skillguard" >&2
  exit 1
fi

# Prefer scanning paths that look like skills (contain SKILL.md)
mapfile -t CHANGED < <(git diff --cached --name-only --diff-filter=ACMR | grep -E 'SKILL\.md$|skills/' || true)

TARGETS=()
for f in "${CHANGED[@]:-}"; do
  if [[ "$f" == */SKILL.md ]]; then
    TARGETS+=("$(dirname "$f")")
  elif [[ -d "$f" ]]; then
    TARGETS+=("$f")
  fi
done

# Deduplicate
if [[ ${#TARGETS[@]} -eq 0 ]]; then
  # Fallback: if repo has a skills/ directory, scan it lightly
  if [[ -d skills ]]; then
    TARGETS+=(skills)
  else
    exit 0
  fi
fi

UNIQUE=()
declare -A SEEN=()
for t in "${TARGETS[@]}"; do
  if [[ -z "${SEEN[$t]:-}" ]]; then
    SEEN[$t]=1
    UNIQUE+=("$t")
  fi
done

FAIL_ON="${SKILLGUARD_FAIL_ON:-high}"
for t in "${UNIQUE[@]}"; do
  echo "SkillGuard scanning: $t"
  skillguard scan "$t" --quiet --fail-on "$FAIL_ON" --format terminal
done
