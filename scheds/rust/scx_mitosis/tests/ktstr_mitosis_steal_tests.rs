#![cfg(feature = "ktstr-tests")]

use ktstr::ktstr_test;
use ktstr::prelude::*;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

declare_scheduler!(MITOSIS_STEAL, {
    name = "mitosis",
    binary = "scx_mitosis",
    topology = (1, 4, 2, 1),
    cgroup_parent = "/ktstr",
    sched_args = [
        "--exit-dump-len", "1048576",
        "--cpu-controller-disabled",
    ],
});

/// Force a sparse cell_id range to trigger the
/// recalc_cell_llc_counts drain abort:
/// `cell N has no CPUs in any LLC; cannot drain
/// (cell, llc=M)` from llc_aware.bpf.h. Fires whenever
/// --enable-llc-awareness is set; work-stealing /
/// adaptive-stealing are not required.
///
/// `cgroup_parent = "/ktstr"` makes ktstr inject
/// `--cell-parent-cgroup /ktstr` (src/test_support/runtime.rs:226
/// in ktstr 0.5.x), so every cgroup mkdir under /ktstr is
/// observed by mitosis's cell_manager inotify watcher and gets
/// a cell_id allocated in event order.
///
/// The churner thread is spawned BEFORE execute_scenario, so the
/// first round of ephemeral mkdirs precedes cg_a creation. By
/// inotify event order the scheduler typically allocates cell_ids
/// 1, 2, 3 to the first three ephemerals and 4 to cg_a (exact
/// numbers depend on event ordering; any sparse range with a
/// freed middle slot triggers the bug).
///
/// The churner then rmdirs the MIDDLE ephemeral. cell_manager
/// produces an assignment list with a gap (e.g. {0, 1, 2, 4}):
/// max_cell_id+1 = num_cells; the slot for the freed middle cell
/// has an empty cpumask (main.rs zeros the whole cell_config
/// struct before writing only the assigned slots).
///
/// BPF apply_cell_config iterates cell_id 0..num_cells. The empty
/// slot's recalc sees llc_cpu_cnt_old[*] > 0 (the cell was
/// populated last reconfig) and llc_cpu_cnt_tmp[*] = 0 (empty
/// cpumask). recalc_cell_llc_counts' drain dest_llc search
/// returns LLC_INVALID and pre-fix fires scx_bpf_error,
/// aborting the scheduler within ~200ms of the workload starting.
///
/// Post-fix: the empty-cell drain returns 0 gracefully and the
/// scheduler keeps running.
#[ktstr_test(
    scheduler = MITOSIS_STEAL,
    duration_s = 4,
    watchdog_timeout_s = 3,
    no_perf_mode = true,
    llcs = 4,
    cores = 2,
    threads = 1,
    numa_nodes = 1,
    memory_mb = 1024,
    auto_repro = true,
    extra_sched_args = ["--enable-llc-awareness"],
)]
fn ktstr_mitosis_steal_cell_id_gap(ctx: &Ctx) -> Result<AssertResult> {
    // Single Backdrop cgroup whose cell_id (4) exceeds the
    // destroyed middle ephemeral's (3). This is what makes the
    // post-rmdir cell_id range sparse instead of dense.
    let backdrop = Backdrop::new().with_cgroup(CgroupDef::named("cg_a").workers(2));

    // execute_scenario requires at least one Step. This is a
    // whole-duration hold with no Ops; all cell churn is driven
    // by the host-thread churner below.
    let steps = vec![Step::new(vec![], HoldSpec::Frac(1.0))];

    let stop = Arc::new(AtomicBool::new(false));
    let stop_c = stop.clone();
    let churner = std::thread::spawn(move || {
        let base = "/sys/fs/cgroup/ktstr/ephemeral";
        let mut i: u64 = 0;
        while !stop_c.load(Ordering::Relaxed) {
            // Create three cgroups in tight succession. The
            // scheduler's inotify watcher allocates cell_ids 1/2/3
            // in event order (the order doesn't have to match _0
            // / _1 / _2 — only that one of them ends up between
            // the other two in cell_id space, which is guaranteed
            // by event ordering).
            for j in 0..3 {
                let _ = std::fs::create_dir(format!("{base}_{i}_{j}"));
            }
            // Wait long enough for the scheduler to process all
            // three cgroup_init events AND for the Backdrop's
            // cg_a to have its cell allocated (cell 4). Without
            // cg_a having a higher cell_id, removing a middle
            // ephemeral wouldn't produce a sparse range.
            std::thread::sleep(Duration::from_millis(150));
            // Remove the MIDDLE-by-creation-order cgroup. The
            // scheduler's next apply_cell_config sees a sparse
            // cell_id range and pre-fix triggers scx_bpf_error.
            let _ = std::fs::remove_dir(format!("{base}_{i}_1"));
            std::thread::sleep(Duration::from_millis(150));
            // Cleanup outer two before next cycle: bounds cell
            // count under MAX_CELLS and keeps cg_a as the unique
            // high-cell each iteration.
            let _ = std::fs::remove_dir(format!("{base}_{i}_0"));
            let _ = std::fs::remove_dir(format!("{base}_{i}_2"));
            i = i.wrapping_add(1);
        }
    });

    let result = execute_scenario(ctx, backdrop, steps);

    stop.store(true, Ordering::Relaxed);
    let _ = churner.join();
    result
}
