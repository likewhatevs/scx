#![cfg(feature = "ktstr-tests")]

use ktstr::prelude::*;

declare_scheduler!(MITOSIS, {
    name = "mitosis",
    binary = "scx_mitosis",
    topology = (1, 4, 4, 1),
    sched_args = [
        "--exit-dump-len", "1048576",
        "--cpu-controller-disabled",
        "--cell-parent-cgroup", "/ktstr",
        "--dynamic-affinity-cpu-selection",
        "--enable-slice-shrinking",
        "--enable-llc-awareness",
    ],
});

/// `post_vm` proof of the mechanism: read scx_mitosis's own scx_stats over
/// ktstr's stats bridge at the capture boundaries and assert the orphan
/// rescue never ran. `Metrics.drain_cnt` counts orphaned-LLC-DSQ drain
/// events and `steal_pct` counts cross-LLC steals; both are bumped only
/// inside `try_stealing_work`, which `mitosis_dispatch` reaches only when a
/// CPU's own (cell, cctx->llc) DSQ is empty. So `drain_cnt == 0` at the
/// stall demonstrates that this is an *un-drained orphaned DSQ* stall (the
/// WIP gap PR #3648 flags) rather than generic overload: cell 0's saturated
/// LLC keeps the dispatch path off the rescue branch, so full-affinity tasks
/// stranded in cell 0's other-LLC DSQs are never reaped -> kind 1026.
fn assert_orphan_rescue_never_ran(result: &VmResult) -> anyhow::Result<()> {
    let drained = result.snapshot_bridge.drain_ordered_with_stats();
    let series = SampleSeries::from_drained_typed(drained, result.monitor.clone());
    let drain = series.stats("drain_cnt", |sv| sv.get("drain_cnt").as_u64());
    // Snapshot delivery under a stall is nondeterministic (the periodic
    // capture can be starved by the very stall), so don't require a sample;
    // the stall itself is the primary signal. Whenever a sample IS delivered,
    // assert the orphan rescue had not fired (drain_cnt stays 0).
    for (_tag, ms, slot) in drain.iter_full() {
        if let Ok(v) = slot {
            anyhow::ensure!(
                *v == 0,
                "drain_cnt={v} at {ms}ms: the orphan rescue fired; expected 0 \
                 (rescue starved while the orphaned DSQ stalls)"
            );
        }
    }
    Ok(())
}

/// LLC-aware orphaned-DSQ runnable-task stall (SCX exit kind 1026).
/// Partially addressed by https://github.com/sched-ext/scx/pull/3648
/// (its orphan-DSQ drain is WIP), so it still fires on top of the PR.
///
/// With --enable-llc-awareness mitosis keeps a DSQ per (cell, LLC); a CPU
/// only consumes its own (cell, cctx->llc) DSQ. The orphan rescue
/// (`try_stealing_work`, llc_aware.bpf.h) is the ONLY reaper of an orphaned
/// (cell, LLC) DSQ and is reached from `mitosis_dispatch` (mitosis.bpf.c)
/// only when a CPU's own (cell, cctx->llc) DSQ and per-CPU DSQ are both
/// empty.
///
/// Setup: child cells are cpuset-pinned to LLCs 1..N, so the root cell
/// (cell 0) is the remainder, left with CPUs in a single LLC (LLC 0) with
/// cctx->llc correct. The root cell's full-affinity host tasks
/// (all_cell_cpus_allowed=1) get tagged to LLCs the root cell owns no CPU in
/// (they ran there during the attach/bypass window), landing in
/// (cell 0, LLC N>0) DSQs that no CPU consumes. Because those same host
/// tasks heavily oversubscribe cell 0's one LLC, (cell 0, LLC 0) never goes
/// empty, so `mitosis_dispatch` always finds local work and never reaches
/// the rescue -> the orphaned tasks are never drained, never re-tagged (a
/// queued task is only re-tagged at its own next enqueue, which never
/// happens because it never runs) -> watchdog -> exit kind 1026.
///
/// Matches the captured for-realsies failure: cell 0 confined to one LLC, a
/// runnable full-affinity root-cell task stranded in an orphaned LLC DSQ —
/// `cell=0 llc=N dsq=2000000N all_cell_cpus_allowed=1`, full-affinity CPUS,
/// runnable past the watchdog.
#[ktstr_test(
    scheduler = MITOSIS,
    workload_root_cgroup = "/ktstr",
    duration_s = 30,
    watchdog_timeout_s = 8,
    llcs = 4,
    cores = 4,
    threads = 1,
    memory_mib = 96,
    // Capture periodic scx_stats snapshots so the post_vm hook can read
    // scx_mitosis's own drain_cnt and assert the rescue never fired.
    num_snapshots = 8,
    post_vm_unconditional = assert_orphan_rescue_never_ran,
)]
fn mitosis_llc_orphan_dsq_stall(ctx: &Ctx) -> Result<AssertResult> {
    // Cpuset-pin one child cell to each non-root LLC; cell 0 (root) is the
    // remainder, left with CPUs in a single LLC.
    let workloads: Vec<CgroupDef> = (1..ctx.topo.num_llcs())
        .map(|llc| {
            CgroupDef::named(format!("workload_llc{llc}"))
                .cpuset(CpusetSpec::llc(llc))
                .workers_pct(4.0)
                .work_type(WorkType::SpinWait)
        })
        .collect();

    // Full-affinity host workers run in the root cell and oversubscribe its
    // one LLC, keeping (cell 0, LLC 0) busy so the orphan rescue never runs;
    // the bursty herd churns wakeups across every LLC so some strand in
    // cell 0's other-LLC DSQs.
    let steps = vec![Step::with_defs(workloads, ctx.settled_hold(1.0)).set_ops(vec![
        Op::spawn_host(
            WorkSpec::default()
                .workers(1)
                .work_type(WorkType::SpinWait)
                .nice(19),
        ),
        Op::spawn_host(
            WorkSpec::default()
                .workers(200)
                .work_type(WorkType::Bursty {
                    burst_duration: std::time::Duration::from_millis(2),
                    sleep_duration: std::time::Duration::from_millis(20),
                }),
        ),
    ])];
    execute_steps(ctx, steps)
}
