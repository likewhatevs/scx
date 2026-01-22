#!/usr/bin/env bash
set -euo pipefail

CPUS=${CPUS:-"0-1"}
WORKERS=${WORKERS:-8}
TIMEOUT=${TIMEOUT:-30}
METHOD=${METHOD:-matrixprod}

out=$(
  taskset -c "$CPUS" stress-ng \
    --cpu "$WORKERS" \
    --cpu-method "$METHOD" \
    --timeout "${TIMEOUT}s" \
    --metrics-brief 2>&1
)

line=$(printf "%s\n" "$out" | awk '/cpu/ && /bogo ops\/s/ {print; exit}')
if [ -z "$line" ]; then
  printf "error: failed to parse stress-ng output\n" >&2
  printf "%s\n" "$out" >&2
  exit 1
fi

printf "%s\n" "$line" | awk '{
  for (i = 1; i <= NF; i++) {
    if ($i == "bogo" && $(i+1) == "ops/s") {
      print $(i-1);
      exit;
    }
  }
  exit 1;
}'
