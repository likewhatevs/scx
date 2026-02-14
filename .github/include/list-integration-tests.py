#!/usr/bin/env python3

import json
import sys

SCHEDULERS = [
    "scx_beerland",
    "scx_bpfland",
    "scx_chaos",
    "scx_cosmos",
    "scx_flash",
    "scx_lavd",
    "scx_layered",
    "scx_p2dq",
    "scx_rlfifo",
    "scx_rustland",
    "scx_rusty",
    "scx_tickless",
]

SCHEDULER_FLAGS = {
    "scx_layered": "--run-example",
}

# https://github.com/sched-ext/scx/issues/3046
# https://github.com/sched-ext/scx/issues/3047
KERNEL_BLOCKLIST = {
    "scx_lavd": ["stable/6_12"],
    "scx_p2dq": ["stable/6_12"],
}


def main():
    if len(sys.argv) != 2:
        print("Usage: list-integration-tests.py <default-kernel>", file=sys.stderr)
        sys.exit(1)

    kernel = sys.argv[1]

    matrix = []
    for scheduler in SCHEDULERS:
        if kernel in KERNEL_BLOCKLIST.get(scheduler, []):
            continue
        matrix.append(
            {
                "name": scheduler,
                "flags": SCHEDULER_FLAGS.get(scheduler, ""),
                "kernel": "",
            }
        )

    print(f"matrix={json.dumps(matrix)}")


if __name__ == "__main__":
    main()
