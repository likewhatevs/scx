#!/usr/bin/env bash
set -euo pipefail

usage() {
    echo "Usage: $0 <scheduler-binary> <label> <commit-sha> [scheduler-flags]"
    echo "  label: HEAD or BASE"
    exit 1
}

if [ $# -lt 3 ]; then
    usage
fi

SCHED_BIN="$1"
LABEL="$2"
COMMIT="$3"
SCHED_FLAGS="${4:-}"
RUNTIME="${BENCH_RUNTIME:-45}"
SCHED_PID=""

cleanup() {
    if [ -n "$SCHED_PID" ] && kill -0 "$SCHED_PID" 2>/dev/null; then
        kill -INT "$SCHED_PID" 2>/dev/null || true
        wait "$SCHED_PID" 2>/dev/null || true
    fi
}
trap cleanup EXIT

sched_name=$(basename "$SCHED_BIN")
SCHED_RESTARTS=0

start_scheduler() {
    # Kill existing scheduler if any
    if [ -n "$SCHED_PID" ] && kill -0 "$SCHED_PID" 2>/dev/null; then
        kill -INT "$SCHED_PID" 2>/dev/null || true
        wait "$SCHED_PID" 2>/dev/null || true
    fi

    if [ -n "$SCHED_FLAGS" ]; then
        # shellcheck disable=SC2086
        "$SCHED_BIN" $SCHED_FLAGS &
    else
        "$SCHED_BIN" &
    fi
    SCHED_PID=$!

    echo "Waiting for sched_ext to enable (PID $SCHED_PID)..."
    for i in $(seq 1 100); do
        if [ -f /sys/kernel/sched_ext/state ]; then
            state=$(cat /sys/kernel/sched_ext/state)
            if [ "$state" = "enabled" ]; then
                echo "sched_ext enabled after $((i / 10)).${i##*[0-9]}s"
                return 0
            fi
        fi
        if ! kill -0 "$SCHED_PID" 2>/dev/null; then
            echo "ERROR: scheduler exited before enabling"
            SCHED_PID=""
            return 1
        fi
        sleep 0.1
    done

    echo "ERROR: sched_ext not enabled after 10s"
    kill -INT "$SCHED_PID" 2>/dev/null || true
    wait "$SCHED_PID" 2>/dev/null || true
    SCHED_PID=""
    return 1
}

ensure_scheduler() {
    if [ -n "$SCHED_PID" ] && kill -0 "$SCHED_PID" 2>/dev/null; then
        return 0
    fi
    echo "WARNING: scheduler not running, restarting..."
    SCHED_RESTARTS=$((SCHED_RESTARTS + 1))
    if [ "$SCHED_RESTARTS" -gt 3 ]; then
        echo "ERROR: scheduler restarted too many times, aborting"
        exit 1
    fi
    start_scheduler
}

echo "========================================"
echo "BENCHMARK RUN [$LABEL]"
echo "  scheduler: $sched_name"
echo "  commit:    $COMMIT"
echo "  label:     $LABEL"
echo "  runtime:   ${RUNTIME}s per benchmark"
echo "========================================"

start_scheduler || exit 1

run_bench() {
    local name="$1"
    shift
    local rsched_out bench_out bench_exit rsched_pid

    rsched_out=$(mktemp /tmp/bench-rsched.XXXXXX)
    bench_out=$(mktemp /tmp/bench-out.XXXXXX)

    local desc="$1"
    shift

    # Ensure scheduler is running, restart if needed
    ensure_scheduler

    echo ""
    echo ">>> [$LABEL] $name | scheduler=$sched_name | commit=$COMMIT"
    echo "    $desc"
    echo "    cmd: $*"

    # Start benchmark, let it ramp up, then capture steady-state with rsched
    bench_exit=0
    "$@" > "$bench_out" 2>&1 &
    bench_pid=$!

    sleep 5
    rsched -r "$((RUNTIME - 15))" -i "$((RUNTIME - 20))" -g all > "$rsched_out" 2>&1 || true

    wait "$bench_pid" 2>/dev/null || bench_exit=$?

    echo "===BENCH_RESULT_START==="
    echo "label=$LABEL"
    echo "commit=$COMMIT"
    echo "scheduler=$sched_name"
    echo "benchmark=$name"
    echo "description=$desc"
    echo "command=$*"
    echo "exit_code=$bench_exit"
    echo "---RSCHED_START---"
    cat "$rsched_out"
    echo "---RSCHED_END---"
    echo "---BENCH_OUTPUT_START---"
    cat "$bench_out"
    echo "---BENCH_OUTPUT_END---"
    echo "===BENCH_RESULT_END==="

    rm -f "$rsched_out" "$bench_out"
}

run_bench schbench \
    "Wakeup latency + preemption cost, request/worker model" \
    schbench -r "$RUNTIME" -i "$((RUNTIME - 1))"

run_bench schbench-split \
    "Shared+private working set, cross-core placement / cacheline bouncing" \
    schbench -r "$RUNTIME" -i "$((RUNTIME - 1))" --split 30

run_bench schbench-pipe \
    "Futex + shared memory pipe-like transfers, scheduler bottleneck" \
    schbench -r "$RUNTIME" -i "$((RUNTIME - 1))" -p 65536 -t 4

run_bench epoll-single \
    "Concurrent epoll_wait, single shared queue, no forced affinity" \
    perf bench epoll wait --runtime "$RUNTIME" --noaffinity --oneshot

run_bench epoll-multiq \
    "Concurrent epoll_wait, one queue per worker, no forced affinity" \
    perf bench epoll wait --runtime "$RUNTIME" --noaffinity --oneshot --multiq

run_bench futex-lock-pi \
    "PI futex lock/unlock contention" \
    perf bench futex lock-pi --runtime "$RUNTIME" --silent

run_bench sysbench-threads \
    "Mutex/cond scheduling overhead, high yield/lock rates" \
    sysbench --threads="$(nproc)" --time="$RUNTIME" threads --thread-yields=1000 --thread-locks=8 run

run_bench sysbench-cpu \
    "CPU-bound throughput, load balance / migration effects" \
    sysbench --threads="$(nproc)" --time="$RUNTIME" cpu run

run_bench stress-ng-switch \
    "Rapid context switch activity, runqueue churn" \
    stress-ng --switch 0 -t "${RUNTIME}s" --metrics-brief

run_bench stress-ng-cache \
    "Aggressive cache thrash on large L3" \
    stress-ng --cache 0 -t "${RUNTIME}s" --metrics-brief

run_bench stress-ng-affinity \
    "CPU-pinned workers, constrained cpumask scheduling paths" \
    stress-ng --cpu "$(nproc)" -t "${RUNTIME}s" --taskset 0-$(($(nproc) / 2 - 1)) --metrics-brief

# Stop scheduler gracefully
echo ""
echo "Stopping scheduler (SIGINT)..."
kill -INT "$SCHED_PID" 2>/dev/null || true
wait "$SCHED_PID" 2>/dev/null || true
SCHED_PID=""

echo "Done [$LABEL]. 11 benchmarks × ${RUNTIME}s = $((11 * RUNTIME))s benchmark time for $sched_name @ $COMMIT"
