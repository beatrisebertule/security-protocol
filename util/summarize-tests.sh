#!/bin/bash
# Usage: summarize-tests.sh "SuiteName:file" ...
# Prints a per-suite results table and a totals line.
# Exits 1 if any suite failed or crashed.

total_passed=0
total_failed=0
total_crashed=0

printf "\n%-28s %7s %7s  %s\n" "Suite" "Passed" "Failed" "Status"
printf -- "%-28s %7s %7s  %s\n" "----------------------------" "-------" "-------" "--------"

for arg in "$@"; do
  name="${arg%%:*}"
  file="${arg#*:}"

  results=$(grep "^=== Results:" "$file" 2>/dev/null)
  if [ -z "$results" ]; then
    printf "%-28s %7s %7s  %s\n" "$name" "-" "-" "CRASHED"
    total_crashed=$((total_crashed + 1))
    continue
  fi

  passed=$(echo "$results" | grep -oE '[0-9]+ passed' | grep -oE '[0-9]+')
  failed=$(echo "$results" | grep -oE '[0-9]+ failed' | grep -oE '[0-9]+')
  passed=${passed:-0}
  failed=${failed:-0}

  total_passed=$((total_passed + passed))
  total_failed=$((total_failed + failed))

  if [ "$failed" -gt 0 ]; then
    status="FAILED"
  else
    status="OK"
  fi

  printf "%-28s %7d %7d  %s\n" "$name" "$passed" "$failed" "$status"
done

printf -- "%-28s %7s %7s\n" "----------------------------" "-------" "-------"

if [ "$total_crashed" -gt 0 ]; then
  printf "%-28s %7d %7d  (%d suite(s) CRASHED — fix to see full count)\n" \
    "TOTAL" "$total_passed" "$total_failed" "$total_crashed"
  exit 1
else
  printf "%-28s %7d %7d\n" "TOTAL" "$total_passed" "$total_failed"
  if [ "$total_failed" -gt 0 ]; then
    exit 1
  fi
fi
