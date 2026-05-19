#!/usr/bin/env bash
# Merge audit + verbose logs into one stream.
# Audit lines red, verbose lines default. Line-buffered end-to-end.
set -u

AUDIT=/tmp/rentalsim-audit.log
VERBOSE=/tmp/rentalsim-verbose.log

RED=$(printf '\033[1;31m')
RST=$(printf '\033[0m')

stdbuf -oL -eL tail -n +1 -F "$AUDIT" 2>/dev/null \
  | stdbuf -oL sed -u "s/.*/${RED}&${RST}/" &
PID1=$!

stdbuf -oL -eL tail -n +1 -F "$VERBOSE" 2>/dev/null &
PID2=$!

trap 'kill $PID1 $PID2 2>/dev/null' EXIT INT TERM
wait
