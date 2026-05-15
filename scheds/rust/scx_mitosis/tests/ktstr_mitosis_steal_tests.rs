#![cfg(feature = "ktstr-tests")]

use ktstr::ktstr_test;
use ktstr::prelude::*;
use std::time::Duration;

declare_scheduler!(MITOSIS_EMPTY, {
    name = "mitosis",
    binary = "scx_mitosis",
    topology = (1, 4, 2, 2),
    cgroup_parent = "/ktstr",
    sched_args = [
        "--cpu-controller-disabled",
        "--cell-exclude", "systemd-workaround.service",
        "--exit-dump-len", "4194304",
        "--monitor-interval-s", "0",
    ],
});

/// Reproduce scx_bpf_error("Empty cpumask after intersection") at
/// llc_aware.bpf.h. apply_cell_config publishes cell->llcs[*].cpu_cnt
/// (recalc_cell_llc_counts) before publishing cell_cpumask
/// (publish_prepared_cpumask); a concurrent mitosis_running →
/// update_task_cpumask sees the stale cpumask but the fresh cpu_cnt,
/// pick_llc_for_task names an LLC absent from the stale cpumask, and
/// bpf_cpumask_and yields empty.
///
/// Six cgroups oscillate cpusets between a 1-LLC base and a 2-LLC
/// superset (pure GROW: OLD ⊆ NEW p->cpus_ptr, so update_task_cpumask's
/// all_cell_cpus_allowed subset check passes and the LLC path runs).
/// Each Step batches set_cpuset for all six cgroups, firing up to six
/// apply_cell_config invocations per polling tick. LLC3 stays unowned
/// so cell 0 always has CPUs. --monitor-interval-s=0 disables the 1Hz
/// polling cap on cpuset change detection.
#[ktstr_test(
    scheduler = MITOSIS_EMPTY,
    duration_s = 15,
    watchdog_timeout_s = 12,
    no_perf_mode = true,
    llcs = 4,
    cores = 2,
    threads = 2,
    numa_nodes = 1,
    memory_mb = 3072,
    auto_repro = true,
    extra_sched_args = [
        "--enable-borrowing",
        "--enable-rebalancing",
        "--dynamic-affinity-cpu-selection",
        "--enable-slice-shrinking",
        "--enable-llc-awareness",
        "--enable-work-stealing",
        "--enable-adaptive-stealing",
        "--steal-queued-max", "0",
    ],
)]
fn ktstr_mitosis_empty_cpumask(ctx: &Ctx) -> Result<AssertResult> {
    let work = WorkType::bursty(
        Duration::from_micros(500),
        Duration::from_micros(250),
    );

    let llc0: Vec<usize> = (0..4).collect();
    let llc1: Vec<usize> = (4..8).collect();
    let llc2: Vec<usize> = (8..12).collect();
    // LLC3 (12..16) is always reserved for cell 0; no cgroup may
    // claim it, otherwise cell 0 starves and the scheduler bails.

    // Pure GROW oscillations: each cgroup oscillates between a
    // single-LLC base and a two-LLC superset. Both phases include
    // the base LLC (subset relation OLD ⊆ NEW always holds, so
    // all_cell_cpus_allowed=TRUE during the race window — required
    // to hit the LLC-aware path that fires the bug).
    let cg_specs: Vec<(&'static str, Vec<usize>, Vec<usize>)> = vec![
        ("cg_0", llc0.clone(), llc0.iter().chain(llc1.iter()).copied().collect()),
        ("cg_1", llc0.clone(), llc0.iter().chain(llc2.iter()).copied().collect()),
        ("cg_2", llc1.clone(), llc1.iter().chain(llc0.iter()).copied().collect()),
        ("cg_3", llc1.clone(), llc1.iter().chain(llc2.iter()).copied().collect()),
        ("cg_4", llc2.clone(), llc2.iter().chain(llc0.iter()).copied().collect()),
        ("cg_5", llc2.clone(), llc2.iter().chain(llc1.iter()).copied().collect()),
    ];

    let mut backdrop = Backdrop::new();
    for (name, shrunk, _) in &cg_specs {
        backdrop = backdrop.with_cgroup(
            CgroupDef::named(*name)
                .with_cpuset(CpusetSpec::exact(shrunk.clone()))
                .workers(3)
                .work_type(work.clone()),
        );
    }

    let mut steps = vec![Step::new(vec![], HoldSpec::Fixed(Duration::from_secs(1)))];
    let hold = HoldSpec::Fixed(Duration::from_millis(10));

    // 800 steps × 10ms = 8s of churn. Bug fires within 5s.
    // Each step batches set_cpuset for all cgroups, alternating
    // SHRUNK/GROWN per cgroup independently so different cgroups
    // GROW in different steps.
    for i in 0..800 {
        let mut ops = Vec::with_capacity(cg_specs.len());
        for (idx, (name, shrunk, grown)) in cg_specs.iter().enumerate() {
            // Each cgroup has its own phase offset so they don't
            // all GROW at once; some are mid-shrink while others
            // are mid-grow each step.
            let phase = (i + idx) % 2;
            let cpus = if phase == 0 { grown.clone() } else { shrunk.clone() };
            ops.push(Op::set_cpuset(*name, CpusetSpec::exact(cpus)));
        }
        steps.push(Step::new(ops, hold.clone()));
    }

    execute_scenario(ctx, backdrop, steps)
}
