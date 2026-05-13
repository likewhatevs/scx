#![cfg(feature = "ktstr-tests")]

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use ktstr::prelude::*;

const CONFIG: &str = r#"[
  {"name":"batch","matches":[[{"CgroupPrefix":"s"}]],"kind":{"Confined":{"util_range":[0.8,0.9],"cpus_range":[1,32],"min_exec_us":20}}},
  {"name":"normal","matches":[[]],"kind":{"Open":{"min_exec_us":10}}}
]"#;

const LAYERED: Scheduler = Scheduler::new("scx_layered")
    .binary(SchedulerSpec::Discover("scx_layered"))
    .config_file_def("f:{file}", "/include-files/layered.json")
    .topology(1, 1, 4, 1);
const LAYERED_PAYLOAD: Payload = Payload::from_scheduler(&LAYERED);

/// Race cgroup.procs writes against task exit to trigger
/// bpf_task_acquire failure in tp_cgroup_attach_task.
#[ktstr_test(scheduler = LAYERED_PAYLOAD, config = CONFIG, duration_s = 8,
    llcs = 1, cores = 4, threads = 1)]
fn layered_acquire_leader(ctx: &Ctx) -> Result<AssertResult> {
    let race_cg = "/sys/fs/cgroup/race_target";
    std::fs::create_dir_all(race_cg)?;
    let cg_procs = format!("{race_cg}/cgroup.procs");

    let stop = Arc::new(AtomicBool::new(false));
    let stop_c = stop.clone();

    let churner = std::thread::spawn(move || {
        // Let the workload reach steady state before churning.
        std::thread::sleep(std::time::Duration::from_secs(3));
        unsafe {
            libc::signal(libc::SIGCHLD, libc::SIG_IGN);
        }
        while !stop_c.load(Ordering::Relaxed) {
            let child = unsafe { libc::fork() };
            if child == 0 {
                unsafe { libc::_exit(0) };
            }
            if child > 0 {
                let _ = std::fs::write(&cg_procs, child.to_string());
            }
        }
    });

    let result = execute_defs(
        ctx,
        vec![CgroupDef::named("s0").workers(ctx.workers_per_cgroup)],
    );

    stop.store(true, Ordering::Relaxed);
    let _ = churner.join();

    result
}
