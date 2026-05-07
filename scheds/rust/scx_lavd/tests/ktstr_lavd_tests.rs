#![cfg(feature = "ktstr-tests")]

use anyhow::Result;
use ktstr::prelude::*;

#[derive(ktstr::Scheduler)]
#[scheduler(name = "lavd", binary = "scx_lavd", topology(1, 2, 4, 2))]
#[allow(dead_code)]
enum LavdFlags {
    #[flag(args = ["--enable-cpu-bw"])]
    CpuBw,
    #[flag(args = [
        "--performance",
        "--slice-min-us", "3000",
        "--slice-max-us", "10000",
        "--pinned-slice-us", "3000",
    ])]
    Performance,
}

#[ktstr_test(
    scheduler = LAVD_PAYLOAD,
    duration_s = 15,
    watchdog_timeout_s = 5,
    required_flags = ["cpu-bw", "performance"],
)]
fn lavd_cpus_max_error(ctx: &Ctx) -> Result<AssertResult> {
    execute_defs(
        ctx,
        vec![CgroupDef::named("bw_limited")
            .cpu_quota_pct(50)
            .workers(8)
            .work_type(WorkType::AluHot {
                width: AluWidth::Widest,
            })],
    )
}
