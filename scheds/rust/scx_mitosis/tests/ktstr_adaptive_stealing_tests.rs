#![cfg(feature = "ktstr-tests")]

//! A/B test for the adaptive stealing controller added in
//! sched-ext/scx#3572. Single VM, two scheduler arms swapped via
//! `Op::ReplaceScheduler` at a phase boundary; the workload is
//! declared in the [`Backdrop`] so the same workers run
//! continuously through the swap.
//!
//! ## Metric
//!
//! The PR's stated goal is "throttling cross-LLC churn under low
//! pressure". The direct, self-normalizing measure of that goal is
//! the cross-LLC dispatch FRACTION:
//!
//!   cross_frac = nr_mig_cross_dispatch /
//!                (nr_mig_same_dispatch + nr_mig_cross_dispatch)
//!
//! Per-phase BPF BSS counters (cumulative since each scheduler's
//! spawn) give us a clean numerator + denominator within each
//! phase. Using the ratio instead of raw counts neutralizes
//! per-phase workload-intensity drift (worker spinup, snapshot
//! cadence variance, controller convergence lag).
//!
//! ## Assertion
//!
//! Adaptive's cross-LLC dispatch FRACTION is at least 15% below
//! the fixed arm's. That's a direct measurement of the controller
//! shifting decisions away from cross-LLC steals toward same-LLC
//! ones.
//!
//! ## Setup notes
//!
//! - `workload_root_cgroup = "/ktstr"`: framework-owned parent
//!   for every workload cgroup. The guest mkdirs it before the
//!   scheduler starts and enables `+cpuset +cpu` on every
//!   ancestor. The same path is what `--cell-parent-cgroup`
//!   should point at so mitosis treats each workload cgroup
//!   as its own cell.
//! - `Scheduler::cgroup_parent` only governs scheduler placement
//!   now; it does NOT auto-inject `--cell-parent-cgroup` anymore.

use anyhow::Result;
use ktstr::prelude::*;

declare_scheduler!(MITOSIS_FIXED, {
    name = "mitosis_fixed",
    binary = "scx_mitosis",
    topology = (1, 2, 4, 2),
    sched_args = [
        "--exit-dump-len", "1048576",
        "--enable-llc-awareness",
        "--enable-work-stealing",
        // Don't split CPUs into per-cgroup cells. With a single cell
        // spanning both LLCs, cross-LLC stealing is meaningful (CPUs
        // on LLC0 can steal tasks queued on LLC1's side of the cell).
        // Per-cgroup cell allocation otherwise gives each cell a
        // single LLC, making cross-LLC stealing impossible.
        "--cpu-controller-disabled",
        "--cell-parent-cgroup", "/ktstr",
    ],
});

declare_scheduler!(MITOSIS_ADAPTIVE, {
    name = "mitosis_adaptive",
    binary = "scx_mitosis",
    topology = (1, 2, 4, 2),
    sched_args = [
        "--exit-dump-len", "1048576",
        "--enable-llc-awareness",
        "--enable-work-stealing",
        "--enable-adaptive-stealing",
        // Target 0.1% steal-success rate (well below the workload's
        // natural rate observed without adaptive). With the default
        // 2.0% target the controller's measured steal_pct is already
        // below target, so the threshold stays clamped at
        // steal_queued_min=0 and the adaptive arm is indistinguishable
        // from the fixed arm. Lowering the target gives the controller
        // a reason to raise the threshold and throttle cross-LLC
        // dispatches.
        "--steal-target-pct", "0.001",
        // See MITOSIS_FIXED for why this is required.
        "--cpu-controller-disabled",
        "--cell-parent-cgroup", "/ktstr",
    ],
});

/// Heavy workload designed to produce a large, stable
/// cross-LLC-dispatch denominator: hundreds of bursty workers
/// concentrated in a single cgroup spanning both LLCs. The bursty
/// pattern (short burst, short sleep) creates frequent
/// wake/dispatch events — the population the controller has to
/// route, and the population whose cross-LLC fraction we measure.
fn workload_cgroups() -> Vec<CgroupDef> {
    let bursty = WorkType::Bursty {
        burst_duration: std::time::Duration::from_millis(1),
        sleep_duration: std::time::Duration::from_millis(2),
    };
    vec![
        CgroupDef::named("workload")
            .workers(384)
            .work_type(bursty),
    ]
}

/// Maximum `per_cell_steal_min_queued[]` value across all cells and
/// all non-placeholder samples in the phase. After `Op::ReplaceScheduler`
/// the snapshot carries both schedulers' bss copies — taking max
/// across them and across samples picks whichever the controller
/// actually wrote into. Returns 0 if no signal found.
///
/// This is informational only — the assertion is on the
/// cross-LLC dispatch fraction (which moves whether or not the
/// per-cell threshold counter is observably non-zero at sample
/// time, since the controller's writes happen at the userspace
/// monitor cadence and the threshold can be read back as 0 between
/// raise-then-lower oscillations).
fn phase_max_steal_threshold(samples: &[Sample<'_>]) -> u64 {
    let mut best: u64 = 0;
    for s in samples {
        if s.snapshot.is_placeholder() {
            continue;
        }
        for m in &s.snapshot.report().maps {
            if m.name != "bpf_bpf.bss" {
                continue;
            }
            let Some(value) = m.value.as_ref() else {
                continue;
            };
            if let Some(arr) = lookup_u32_array(value, "per_cell_steal_min_queued") {
                let phase_max = arr.iter().copied().max().unwrap_or(0) as u64;
                best = best.max(phase_max);
            }
        }
    }
    best
}

/// Per-phase (same, cross) dispatch counters pulled from BPF BSS.
/// After `Op::ReplaceScheduler` a snapshot carries both schedulers'
/// `bpf_bpf.bss` maps; pick the active one by taking the larger
/// `same+cross` total per sample (only the live BPF prog advances
/// either counter). Then pick the latest sample by the same
/// active-sum-max heuristic.
fn phase_dispatch_counters(samples: &[Sample<'_>]) -> Result<(u64, u64)> {
    let mut best: Option<(u64, u64)> = None;
    for s in samples {
        if s.snapshot.is_placeholder() {
            continue;
        }
        let report = s.snapshot.report();
        // Find the bss copy with the most dispatch activity.
        let active = report
            .maps
            .iter()
            .filter(|m| m.name == "bpf_bpf.bss")
            .filter_map(|m| m.value.as_ref())
            .filter_map(|v| {
                let same = lookup_u64(v, "nr_mig_same_dispatch")?;
                let cross = lookup_u64(v, "nr_mig_cross_dispatch")?;
                Some((same, cross))
            })
            .max_by_key(|(s, c)| s.saturating_add(*c));
        if let Some(pair) = active {
            let total = pair.0.saturating_add(pair.1);
            let best_total = best
                .as_ref()
                .map(|(s, c)| s.saturating_add(*c))
                .unwrap_or(0);
            if total >= best_total {
                best = Some(pair);
            }
        }
    }
    best.ok_or_else(|| {
        anyhow::anyhow!(
            "no dispatch-migration counters in any snapshot for this phase \
             (samples={})",
            samples.len()
        )
    })
}

/// Walk a BTF-rendered struct looking for a `uint` member by name.
fn lookup_u64(value: &RenderedValue, name: &str) -> Option<u64> {
    match value {
        RenderedValue::Struct { members, .. } => members.iter().find_map(|m| {
            if m.name != name {
                return None;
            }
            match &m.value {
                RenderedValue::Uint { value, .. } => Some(*value),
                _ => None,
            }
        }),
        _ => None,
    }
}

/// Extract a u32 array member by name from a BTF-rendered struct.
fn lookup_u32_array(value: &RenderedValue, name: &str) -> Option<Vec<u32>> {
    let RenderedValue::Struct { members, .. } = value else {
        return None;
    };
    let member = members.iter().find(|m| m.name == name)?;
    let RenderedValue::Array { elements, .. } = &member.value else {
        return None;
    };
    let mut out = Vec::with_capacity(elements.len());
    for e in elements {
        if let RenderedValue::Uint { value, .. } = e {
            out.push(*value as u32);
        } else {
            return None;
        }
    }
    Some(out)
}

fn assert_adaptive_cross_frac_below_fixed(result: &VmResult) -> Result<()> {
    let drained = result.snapshot_bridge.drain_ordered_with_stats();
    anyhow::ensure!(
        !drained.is_empty(),
        "snapshot bridge captured nothing (periodic_fired={}, periodic_target={})",
        result.periodic_fired,
        result.periodic_target,
    );
    let series = SampleSeries::from_drained_typed(drained, result.monitor.clone()).periodic_only();
    let buckets = series.by_phase();

    let fixed_phase = buckets.get(&1).ok_or_else(|| {
        anyhow::anyhow!(
            "no snapshots tagged with step_index=1 (fixed phase); widen duration_s \
             or raise num_snapshots"
        )
    })?;
    let adaptive_phase = buckets.get(&2).ok_or_else(|| {
        anyhow::anyhow!(
            "no snapshots tagged with step_index=2 (adaptive phase); widen duration_s \
             or raise num_snapshots"
        )
    })?;

    let (fix_same, fix_cross) = phase_dispatch_counters(fixed_phase)?;
    let (adp_same, adp_cross) = phase_dispatch_counters(adaptive_phase)?;

    let fix_total = fix_same.saturating_add(fix_cross);
    let adp_total = adp_same.saturating_add(adp_cross);
    anyhow::ensure!(
        fix_total > 0 && adp_total > 0,
        "one or both phases recorded zero dispatch migrations \
         (fix_total={fix_total}, adp_total={adp_total}); workload didn't \
         exercise the dispatch path",
    );

    let fix_frac = fix_cross as f64 / fix_total as f64;
    let adp_frac = adp_cross as f64 / adp_total as f64;

    let csw = result
        .monitor
        .as_ref()
        .and_then(|m| m.summary.schedstat_deltas.as_ref())
        .map(|d| d.total_sched_count)
        .unwrap_or(0);

    let fix_thr = phase_max_steal_threshold(fixed_phase);
    let adp_thr = phase_max_steal_threshold(adaptive_phase);

    println!(
        "[fixed]    same={fix_same} cross={fix_cross} total={fix_total} \
         cross_frac={fix_frac:.4} steal_thresh_max={fix_thr} ({} samples)",
        fixed_phase.len()
    );
    println!(
        "[adaptive] same={adp_same} cross={adp_cross} total={adp_total} \
         cross_frac={adp_frac:.4} steal_thresh_max={adp_thr} ({} samples)",
        adaptive_phase.len()
    );
    println!("[monitor]  total_sched_count={csw} (window covers both phases)");

    let max_allowed = fix_frac * 0.85;
    anyhow::ensure!(
        adp_frac <= max_allowed,
        "adaptive cross_frac={adp_frac:.4} must be at most 85% of fixed \
         cross_frac={fix_frac:.4} (= {max_allowed:.4}); adaptive controller \
         did not shift dispatch decisions away from cross-LLC steals by at \
         least 15%",
    );
    let pct = (1.0 - adp_frac / fix_frac) * 100.0;
    println!(
        "[result]   adaptive reduces cross-LLC dispatch fraction by {pct:.1}% \
         ({fix_frac:.4} → {adp_frac:.4})"
    );
    Ok(())
}

/// Workload in the Backdrop so the same workers run continuously
/// across the scheduler swap. Each Step's `HoldSpec::frac(0.5)`
/// gives the phase half of the test's `duration_s`.
fn build_backdrop() -> ktstr::scenario::backdrop::Backdrop {
    let mut b = ktstr::scenario::backdrop::Backdrop::new();
    for def in workload_cgroups() {
        b = b.push_cgroup(def);
    }
    b
}

fn two_phase_swap_steps(_ctx: &Ctx) -> Vec<Step> {
    vec![
        // Phase 1: short fixed baseline (the BPF counters need only
        // a few samples to characterize the steady-state fraction).
        Step::new(vec![], HoldSpec::frac(0.3)),
        // Phase 2: swap to MITOSIS_ADAPTIVE, give it 70% of duration
        // so the adaptive controller has many monitor ticks
        // (default 1 s cadence) to walk the per-cell threshold up
        // toward its steady-state value before the phase ends.
        Step::new(
            vec![Op::replace_scheduler(&MITOSIS_ADAPTIVE)],
            HoldSpec::frac(0.7),
        ),
    ]
}

#[ktstr_test(
    scheduler = MITOSIS_FIXED,
    staged_schedulers = [MITOSIS_ADAPTIVE],
    workload_root_cgroup = "/ktstr",
    duration_s = 120,
    watchdog_timeout_s = 10,
    num_snapshots = 16,
    memory_mib = 256,
    post_vm = assert_adaptive_cross_frac_below_fixed,
)]
fn mitosis_adaptive_reduces_xllc_dispatch_fraction(ctx: &Ctx) -> Result<AssertResult> {
    execute_scenario(ctx, build_backdrop(), two_phase_swap_steps(ctx))
}

fn assert_smoke_periodic_fired(result: &VmResult) -> Result<()> {
    anyhow::ensure!(
        result.periodic_fired >= 1,
        "periodic_fired={}, target={} — scheduler attached but no \
         periodic snapshot landed within the workload window",
        result.periodic_fired,
        result.periodic_target,
    );
    let drained = result.snapshot_bridge.drain_ordered_with_stats();
    let series = SampleSeries::from_drained_typed(drained, result.monitor.clone()).periodic_only();
    let samples: Vec<_> = series.iter_samples().collect();
    let (same, cross) = phase_dispatch_counters(&samples).unwrap_or((0, 0));
    let thr = phase_max_steal_threshold(&samples);
    println!(
        "[smoke] same={same} cross={cross} steal_thresh_max={thr} ({} samples)",
        samples.len()
    );
    Ok(())
}

/// Smoke test: MITOSIS_ADAPTIVE alone (no scheduler swap) must run
/// the same workload long enough to fire at least one periodic
/// snapshot. Isolates "is mitosis_adaptive viable as a standalone
/// scheduler?" from "is `Op::ReplaceScheduler` swapping in
/// mitosis_adaptive cleanly?"
#[ktstr_test(
    scheduler = MITOSIS_ADAPTIVE,
    workload_root_cgroup = "/ktstr",
    duration_s = 30,
    watchdog_timeout_s = 10,
    num_snapshots = 2,
    memory_mib = 256,
    post_vm = assert_smoke_periodic_fired,
)]
fn mitosis_adaptive_standalone_smoke(ctx: &Ctx) -> Result<AssertResult> {
    execute_scenario(
        ctx,
        build_backdrop(),
        vec![Step::new(vec![], HoldSpec::FULL)],
    )
}
