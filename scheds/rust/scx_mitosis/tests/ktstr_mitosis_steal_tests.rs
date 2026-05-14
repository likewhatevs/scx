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

/// A host churner mkdirs three ephemeral cgroups under
/// /sys/fs/cgroup/ktstr then rmdirs the middle one. The
/// freed middle cell_id makes apply_cell_config's next
/// cell_id range sparse; recalc_cell_llc_counts hits the
/// empty slot with non-zero old cpu_cnt and aborts the
/// scheduler at llc_aware.bpf.h.
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
    let backdrop = Backdrop::new().with_cgroup(CgroupDef::named("cg_a").workers(2));
    let steps = vec![Step::new(vec![], HoldSpec::Frac(1.0))];

    let stop = Arc::new(AtomicBool::new(false));
    let stop_c = stop.clone();
    let churner = std::thread::spawn(move || {
        let base = "/sys/fs/cgroup/ktstr/ephemeral";
        let mut i: u64 = 0;
        while !stop_c.load(Ordering::Relaxed) {
            for j in 0..3 {
                let _ = std::fs::create_dir(format!("{base}_{i}_{j}"));
            }
            std::thread::sleep(Duration::from_millis(150));
            let _ = std::fs::remove_dir(format!("{base}_{i}_1"));
            std::thread::sleep(Duration::from_millis(150));
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
