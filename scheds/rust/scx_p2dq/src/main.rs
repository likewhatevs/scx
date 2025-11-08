// Copyright (c) Meta Platforms, Inc. and affiliates.

// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.
pub mod stats;
use stats::Metrics;

use std::mem::MaybeUninit;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use anyhow::bail;
use anyhow::Context;
use anyhow::Result;
use clap::Parser;
use crossbeam::channel::RecvTimeoutError;
use libbpf_rs::skel::Skel;
use libbpf_rs::MapCore as _;
use libbpf_rs::OpenObject;
use libbpf_rs::ProgramInput;
use scx_arena::ArenaLib;
use scx_stats::prelude::*;
use scx_utils::build_id;
use scx_utils::compat;
use scx_utils::init_libbpf_logging;
use scx_utils::libbpf_clap_opts::LibbpfOpts;
use scx_utils::pm::{cpu_idle_resume_latency_supported, update_cpu_idle_resume_latency};
use scx_utils::scx_ops_attach;
use scx_utils::scx_ops_load;
use scx_utils::scx_ops_open;
use scx_utils::uei_exited;
use scx_utils::uei_report;
use scx_utils::Topology;
use scx_utils::UserExitInfo;
use scx_utils::NR_CPU_IDS;
use tracing::{debug, info, trace, warn};
use tracing_subscriber::filter::EnvFilter;

use bpf_intf::stat_idx_P2DQ_NR_STATS;
use bpf_intf::stat_idx_P2DQ_STAT_ATQ_ENQ;
use bpf_intf::stat_idx_P2DQ_STAT_ATQ_REENQ;
use bpf_intf::stat_idx_P2DQ_STAT_DIRECT;
use bpf_intf::stat_idx_P2DQ_STAT_DISPATCH_PICK2;
use bpf_intf::stat_idx_P2DQ_STAT_DSQ_CHANGE;
use bpf_intf::stat_idx_P2DQ_STAT_DSQ_SAME;
use bpf_intf::stat_idx_P2DQ_STAT_ENQ_CPU;
use bpf_intf::stat_idx_P2DQ_STAT_ENQ_INTR;
use bpf_intf::stat_idx_P2DQ_STAT_ENQ_LLC;
use bpf_intf::stat_idx_P2DQ_STAT_ENQ_MIG;
use bpf_intf::stat_idx_P2DQ_STAT_IDLE;
use bpf_intf::stat_idx_P2DQ_STAT_KEEP;
use bpf_intf::stat_idx_P2DQ_STAT_LLC_MIGRATION;
use bpf_intf::stat_idx_P2DQ_STAT_NODE_MIGRATION;
use bpf_intf::stat_idx_P2DQ_STAT_SELECT_PICK2;
use bpf_intf::stat_idx_P2DQ_STAT_WAKE_LLC;
use bpf_intf::stat_idx_P2DQ_STAT_WAKE_MIG;
use bpf_intf::stat_idx_P2DQ_STAT_WAKE_PREV;
use scx_p2dq::bpf_intf;
use scx_p2dq::bpf_skel::*;
use scx_p2dq::SchedulerOpts;
use scx_p2dq::TOPO;

const SCHEDULER_NAME: &str = "scx_p2dq";
/// scx_p2dq: A pick 2 dumb queuing load balancing scheduler.
///
/// The BPF part does simple vtime or round robin scheduling in each domain
/// while tracking average load of each domain and duty cycle of each task.
///
#[derive(Debug, Parser)]
struct CliOpts {
    /// Specify the logging level. Accepts rust's envfilter syntax for modular
    /// logging: https://docs.rs/tracing-subscriber/latest/tracing_subscriber/filter/struct.EnvFilter.html#example-syntax. Examples: ["info", "warn,tokio=info"]
    #[clap(long, default_value = "info")]
    pub log_level: String,

    /// Enable stats monitoring with the specified interval.
    #[clap(long)]
    pub stats: Option<f64>,

    /// Run in stats monitoring mode with the specified interval. Scheduler
    /// is not launched.
    #[clap(long)]
    pub monitor: Option<f64>,

    /// Print version and exit.
    #[clap(long)]
    pub version: bool,

    /// Optional run ID for tracking scheduler instances.
    #[clap(long)]
    pub run_id: Option<u64>,

    #[clap(flatten)]
    pub sched: SchedulerOpts,

    #[clap(flatten, next_help_heading = "Libbpf Options")]
    pub libbpf: LibbpfOpts,
}

struct Scheduler<'a> {
    skel: BpfSkel<'a>,
    struct_ops: Option<libbpf_rs::Link>,
    debug_level: u8,

    stats_server: StatsServer<(), Metrics>,
    last_debug_pos: u32,
}

impl<'a> Scheduler<'a> {
    fn init(
        opts: &SchedulerOpts,
        libbpf_ops: &LibbpfOpts,
        open_object: &'a mut MaybeUninit<OpenObject>,
        log_level: &str,
    ) -> Result<Self> {
        // Open the BPF prog first for verification.
        let debug_level = if log_level.contains("trace") {
            2
        } else if log_level.contains("debug") {
            1
        } else {
            0
        };
        let mut skel_builder = BpfSkelBuilder::default();
        skel_builder.obj_builder.debug(debug_level > 1);
        init_libbpf_logging(None);
        info!(
            "Running scx_p2dq (build ID: {})",
            build_id::full_version(env!("CARGO_PKG_VERSION"))
        );
        let topo = if opts.virt_llc_enabled {
            Topology::with_args(&opts.topo)?
        } else {
            Topology::new()?
        };
        let open_opts = libbpf_ops.clone().into_bpf_open_opts();
        let mut open_skel = scx_ops_open!(skel_builder, open_object, p2dq, open_opts).context(
            "Failed to open BPF object. This can be caused by a mismatch between the kernel \
            version and the BPF object, permission or other libbpf issues. Try running `dmesg \
            | grep bpf` to see if there are any error messages related to the BPF object. See \
            the LibbpfOptions section in the help for more information on configuration related \
            to this issue or file an issue on the scx repo if the problem persists. \
            https://github.com/sched-ext/scx/issues/new?labels=scx_p2dq&title=scx_p2dq:%20New%20Issue&assignees=hodgesds&body=Kernel%20version:%20(fill%20me%20out)%0ADistribution:%20(fill%20me%20out)%0AHardware:%20(fill%20me%20out)%0A%0AIssue:%20(fill%20me%20out)"
        )?;

        // Apply hardware-specific optimizations before macro
        let hw_profile = scx_p2dq::HardwareProfile::detect();
        let mut opts_optimized = opts.clone();
        if opts.hw_auto_optimize {
            hw_profile.optimize_scheduler_opts(&mut opts_optimized);
        }

        // Create compatibility struct for macro requirements
        struct CompatCliOpts {
            log_level: String,
        }
        let cli_opts_compat = CompatCliOpts {
            log_level: log_level.to_string(),
        };

        scx_p2dq::init_open_skel!(
            &mut open_skel,
            topo,
            &opts_optimized,
            &cli_opts_compat,
            &hw_profile
        )?;

        if opts.queued_wakeup {
            open_skel.struct_ops.p2dq_mut().flags |= *compat::SCX_OPS_ALLOW_QUEUED_WAKEUP;
        }
        open_skel.struct_ops.p2dq_mut().flags |= *compat::SCX_OPS_KEEP_BUILTIN_IDLE;

        let mut skel = scx_ops_load!(open_skel, p2dq, uei)?;
        scx_p2dq::init_skel!(&mut skel, topo);

        let stats_server = StatsServer::new(stats::server_data()).launch()?;

        Ok(Self {
            skel,
            struct_ops: None,
            debug_level,
            stats_server,
            last_debug_pos: 0,
        })
    }

    fn get_metrics(&self) -> Metrics {
        let mut stats = vec![0u64; stat_idx_P2DQ_NR_STATS as usize];
        let stats_map = &self.skel.maps.stats;
        for stat in 0..stat_idx_P2DQ_NR_STATS {
            let cpu_stat_vec: Vec<Vec<u8>> = stats_map
                .lookup_percpu(&stat.to_ne_bytes(), libbpf_rs::MapFlags::ANY)
                .unwrap()
                .unwrap();
            let sum: u64 = cpu_stat_vec
                .iter()
                .map(|val| u64::from_ne_bytes(val.as_slice().try_into().unwrap()))
                .sum();
            stats[stat as usize] = sum;
        }
        Metrics {
            atq_enq: stats[stat_idx_P2DQ_STAT_ATQ_ENQ as usize],
            atq_reenq: stats[stat_idx_P2DQ_STAT_ATQ_REENQ as usize],
            direct: stats[stat_idx_P2DQ_STAT_DIRECT as usize],
            idle: stats[stat_idx_P2DQ_STAT_IDLE as usize],
            dsq_change: stats[stat_idx_P2DQ_STAT_DSQ_CHANGE as usize],
            same_dsq: stats[stat_idx_P2DQ_STAT_DSQ_SAME as usize],
            keep: stats[stat_idx_P2DQ_STAT_KEEP as usize],
            enq_cpu: stats[stat_idx_P2DQ_STAT_ENQ_CPU as usize],
            enq_intr: stats[stat_idx_P2DQ_STAT_ENQ_INTR as usize],
            enq_llc: stats[stat_idx_P2DQ_STAT_ENQ_LLC as usize],
            enq_mig: stats[stat_idx_P2DQ_STAT_ENQ_MIG as usize],
            select_pick2: stats[stat_idx_P2DQ_STAT_SELECT_PICK2 as usize],
            dispatch_pick2: stats[stat_idx_P2DQ_STAT_DISPATCH_PICK2 as usize],
            llc_migrations: stats[stat_idx_P2DQ_STAT_LLC_MIGRATION as usize],
            node_migrations: stats[stat_idx_P2DQ_STAT_NODE_MIGRATION as usize],
            wake_prev: stats[stat_idx_P2DQ_STAT_WAKE_PREV as usize],
            wake_llc: stats[stat_idx_P2DQ_STAT_WAKE_LLC as usize],
            wake_mig: stats[stat_idx_P2DQ_STAT_WAKE_MIG as usize],
        }
    }

    fn process_debug_events(&mut self) {
        // Fix issue #4: Use consistent debug level check with BPF boolean flags
        if self.debug_level == 0 {
            return;
        }

        // Fix issues #1 & #2: Read current debug_event_pos from BPF to determine valid events
        // This avoids race conditions and unreliable timestamp == 0 checks
        let current_debug_pos = unsafe {
            let ptr = &self.skel.maps.bss_data.as_ref().unwrap().debug_event_pos as *const u32;
            (ptr as *const std::sync::atomic::AtomicU32)
                .as_ref()
                .unwrap()
                .load(std::sync::atomic::Ordering::Acquire)
        };

        let debug_events_map = &self.skel.maps.debug_events;
        let buf_size = bpf_intf::consts_DEBUG_EVENTS_BUF_SIZE as u32;
        let mut events_found = 0;

        // Calculate how many new events to process (handles wraparound automatically)
        let events_to_process = current_debug_pos.wrapping_sub(self.last_debug_pos);

        // Process up to buffer size events to avoid infinite loops
        let events_to_process = std::cmp::min(events_to_process, buf_size);

        for _ in 0..events_to_process {
            let key = (self.last_debug_pos % buf_size) as usize;

            match debug_events_map.lookup(&(key as u32).to_ne_bytes(), libbpf_rs::MapFlags::ANY) {
                Ok(Some(data)) => {
                    if data.len() >= std::mem::size_of::<bpf_intf::debug_event>() {
                        let event = unsafe {
                            std::ptr::read(data.as_ptr() as *const bpf_intf::debug_event)
                        };

                        // Process event using position-based approach (no timestamp check needed)
                        events_found += 1;
                        self.format_debug_event(&event);

                        self.last_debug_pos = self.last_debug_pos.wrapping_add(1);
                    }
                }
                _ => {
                    self.last_debug_pos = self.last_debug_pos.wrapping_add(1);
                }
            }
        }

        if events_found > 0 {
            debug!("Processed {} debug events from BPF", events_found);
        }
    }

    fn format_debug_event(&self, event: &bpf_intf::debug_event) {
        let timestamp = event.timestamp; // Copy to avoid packed field reference
        let timestamp_ms = timestamp / 1_000_000; // Convert ns to ms
        let event_type = event.event_type; // Copy to avoid packed field reference
        let args = event.args; // Copy array to avoid packed field reference

        match event_type {
            bpf_intf::debug_event_type_TRACE_EVENT_ENQUEUE_TASK_WEIGHT_SLICE_VTIME_LLC_VTIME => {
                trace!(
                    "[{}ms] ENQUEUE: pid={} weight={} slice_ns={} vtime={}",
                    timestamp_ms,
                    args[0],
                    args[1],
                    args[2],
                    args[3]
                );
            }
            bpf_intf::debug_event_type_TRACE_EVENT_DISPATCH_CPU_MIN_VTIME_DSQ_ATQ => {
                trace!(
                    "[{}ms] DISPATCH: cpu={} min_vtime={} dsq_id={} atq={:#x}",
                    timestamp_ms,
                    args[0],
                    args[1],
                    args[2],
                    args[3]
                );
            }
            bpf_intf::debug_event_type_TRACE_EVENT_RUNNING_PID_CPU_MIGRATION_LLC_MIGRATION => {
                trace!(
                    "[{}ms] RUNNING: pid={} cpu={} task_cpu={} llc_id={}",
                    timestamp_ms,
                    args[0],
                    args[1],
                    args[2],
                    args[3]
                );
            }
            bpf_intf::debug_event_type_TRACE_EVENT_STOPPING_TASK_WEIGHT_SLICE_USED_SCALED => {
                trace!(
                    "[{}ms] STOPPING: pid={} weight={} slice_ns={} used_ns={}",
                    timestamp_ms,
                    args[0],
                    args[1],
                    args[2],
                    args[3]
                );
            }
            bpf_intf::debug_event_type_TRACE_EVENT_SELECT_CPU_PID_COMM_PREV_TO_NEW_IDLE => {
                trace!(
                    "[{}ms] SELECT_CPU: pid={} prev_cpu={} new_cpu={} idle={}",
                    timestamp_ms,
                    args[0],
                    args[1],
                    args[2],
                    args[3]
                );
            }
            bpf_intf::debug_event_type_DEBUG_EVENT_ATQ_CREATED_FOR_LLC => {
                debug!(
                    "[{}ms] ATQ_CREATED: atq={:#x} llc_id={}",
                    timestamp_ms, args[0], args[1]
                );
            }
            bpf_intf::debug_event_type_DEBUG_EVENT_ATQ_FAILED_TO_GET_PID => {
                debug!("[{}ms] ATQ_FAILED: pid={}", timestamp_ms, args[0]);
            }
            bpf_intf::debug_event_type_TRACE_EVENT_ATQ_INSERT_TASK_TO_QUEUE => {
                trace!(
                    "[{}ms] ATQ_INSERT: atq={:#x} pid={}",
                    timestamp_ms,
                    args[0],
                    args[1]
                );
            }
            bpf_intf::debug_event_type_TRACE_EVENT_PICK2_CPU_FIRST_SECOND_LOAD => {
                trace!(
                    "[{}ms] PICK2: cpu={} first_llc={} first_load={} second_llc={}",
                    timestamp_ms,
                    args[0],
                    args[1],
                    args[2],
                    args[3]
                );
            }
            bpf_intf::debug_event_type_TRACE_EVENT_DSQ_INDEX_INCREMENT_FOR_TASK => {
                trace!(
                    "[{}ms] DSQ_INC: pid={} from_idx={} to_idx={}",
                    timestamp_ms,
                    args[0],
                    args[1],
                    args[2]
                );
            }
            bpf_intf::debug_event_type_TRACE_EVENT_DSQ_INDEX_DECREMENT_FOR_TASK => {
                trace!(
                    "[{}ms] DSQ_DEC: pid={} from_idx={} to_idx={}",
                    timestamp_ms,
                    args[0],
                    args[1],
                    args[2]
                );
            }
            bpf_intf::debug_event_type_TRACE_EVENT_PREFERRED_CPU_IDLE_FOR_TASK => {
                trace!("[{}ms] PREFERRED_CPU: cpu={}", timestamp_ms, args[0]);
            }
            bpf_intf::debug_event_type_DEBUG_EVENT_CONFIG_NODE_CONFIGURED => {
                debug!("[{}ms] NODE_CONFIG: node_id={}", timestamp_ms, args[0]);
            }
            bpf_intf::debug_event_type_DEBUG_EVENT_CONFIG_CPU_NODE_LLC_INITIALIZED => {
                debug!(
                    "[{}ms] CPU_INIT: cpu={} node_id={} llc_id={}",
                    timestamp_ms, args[0], args[1], args[2]
                );
            }
            bpf_intf::debug_event_type_DEBUG_EVENT_CPU_IS_BIG_CORE => {
                debug!("[{}ms] BIG_CORE: cpu={}", timestamp_ms, args[0]);
            }
            bpf_intf::debug_event_type_DEBUG_EVENT_LOAD_BALANCE_LLC_CONTEXT => {
                debug!(
                    "[{}ms] LB_LLC: llc_id={} load={} lb_llc_id={} lb_load={}",
                    timestamp_ms, args[0], args[1], args[2], args[3]
                );
            }
            bpf_intf::debug_event_type_DEBUG_EVENT_LOAD_BALANCE_TOTAL_LOAD_INTERACTIVE => {
                debug!(
                    "[{}ms] LB_TOTAL: load_sum={} interactive_sum={}",
                    timestamp_ms, args[0], args[1]
                );
            }
            bpf_intf::debug_event_type_DEBUG_EVENT_LOAD_BALANCE_AUTOSLICE_IDEAL_SUM => {
                debug!(
                    "[{}ms] AUTOSLICE_IDEAL: ideal_sum={} interactive_sum={}",
                    timestamp_ms, args[0], args[1]
                );
            }
            bpf_intf::debug_event_type_DEBUG_EVENT_LOAD_BALANCE_AUTOSLICE_INTERACTIVE_SLICE => {
                debug!(
                    "[{}ms] AUTOSLICE_SLICE: dsq_idx={} slice_ns={}",
                    timestamp_ms, args[0], args[1]
                );
            }
            bpf_intf::debug_event_type_DEBUG_EVENT_TIMER_STOPPED_FOR_KEY => {
                debug!("[{}ms] TIMER_STOPPED: key={}", timestamp_ms, args[0]);
            }
            bpf_intf::debug_event_type_DEBUG_EVENT_CONFIG_CREATING_AFFINITY_CPU_DSQ => {
                debug!(
                    "[{}ms] CREATE_AFFN_DSQ: cpu={} dsq_id={}",
                    timestamp_ms, args[0], args[1]
                );
            }
            _ => {
                debug!(
                    "[{}ms] UNKNOWN_EVENT: type={} args=[{}, {}, {}, {}]",
                    timestamp_ms, event_type, args[0], args[1], args[2], args[3]
                );
            }
        }
    }

    fn run(&mut self, shutdown: Arc<AtomicBool>) -> Result<UserExitInfo> {
        let (res_ch, req_ch) = self.stats_server.channels();

        while !shutdown.load(Ordering::Relaxed) && !uei_exited!(&self.skel, uei) {
            match req_ch.recv_timeout(Duration::from_secs(1)) {
                Ok(()) => {
                    res_ch.send(self.get_metrics())?;
                }
                Err(RecvTimeoutError::Timeout) => {}
                Err(e) => Err(e)?,
            }
            if self.debug_level >= 1 {
                self.process_debug_events();
            }
        }

        let _ = self.struct_ops.take();
        uei_report!(&self.skel, uei)
    }

    fn print_topology(&mut self) -> Result<()> {
        let input = ProgramInput {
            ..Default::default()
        };

        let output = self.skel.progs.arena_topology_print.test_run(input)?;
        if output.return_value != 0 {
            bail!(
                "Could not initialize arenas, topo_print returned {}",
                output.return_value as i32
            );
        }

        Ok(())
    }

    fn start(&mut self) -> Result<()> {
        self.struct_ops = Some(scx_ops_attach!(self.skel, p2dq)?);

        if self.debug_level > 0 {
            self.print_topology()?;
        }

        info!("P2DQ scheduler started! Run `scx_p2dq --monitor` for metrics.");

        Ok(())
    }
}

impl Drop for Scheduler<'_> {
    fn drop(&mut self) {
        info!("Unregister {SCHEDULER_NAME} scheduler");

        if let Some(struct_ops) = self.struct_ops.take() {
            drop(struct_ops);
        }
    }
}

#[clap_main::clap_main]
fn main(opts: CliOpts) -> Result<()> {
    if opts.version {
        println!(
            "scx_p2dq: {}",
            build_id::full_version(env!("CARGO_PKG_VERSION"))
        );
        return Ok(());
    }

    let env_filter = EnvFilter::try_from_default_env()
        .or_else(|_| match EnvFilter::try_new(&opts.log_level) {
            Ok(filter) => Ok(filter),
            Err(e) => {
                eprintln!(
                    "invalid log envvar: {}, using info, err is: {}",
                    opts.log_level, e
                );
                EnvFilter::try_new("info")
            }
        })
        .unwrap_or_else(|_| EnvFilter::new("info"));

    match tracing_subscriber::fmt()
        .with_env_filter(env_filter)
        .with_target(true)
        .with_thread_ids(true)
        .with_file(true)
        .with_line_number(true)
        .try_init()
    {
        Ok(()) => {}
        Err(e) => eprintln!("failed to init logger: {}", e),
    }

    if let Some(run_id) = opts.run_id {
        info!("scx_p2dq run_id: {}", run_id);
    }

    let shutdown = Arc::new(AtomicBool::new(false));
    let shutdown_clone = shutdown.clone();
    ctrlc::set_handler(move || {
        shutdown_clone.store(true, Ordering::Relaxed);
    })
    .context("Error setting Ctrl-C handler")?;

    if let Some(intv) = opts.monitor.or(opts.stats) {
        let shutdown_copy = shutdown.clone();
        let jh = std::thread::spawn(move || {
            match stats::monitor(Duration::from_secs_f64(intv), shutdown_copy) {
                Ok(_) => {
                    debug!("stats monitor thread finished successfully")
                }
                Err(error_object) => {
                    warn!("stats monitor thread finished because of an error {error_object}")
                }
            }
        });
        if opts.monitor.is_some() {
            let _ = jh.join();
            return Ok(());
        }
    }

    if let Some(idle_resume_us) = opts.sched.idle_resume_us {
        if !cpu_idle_resume_latency_supported() {
            warn!("idle resume latency not supported");
        } else if idle_resume_us > 0 {
            info!("Setting idle QoS to {idle_resume_us}us");
            for cpu in TOPO.all_cpus.values() {
                update_cpu_idle_resume_latency(cpu.id, idle_resume_us.try_into().unwrap())?;
            }
        }
    }

    let mut open_object = MaybeUninit::uninit();
    loop {
        let mut sched =
            Scheduler::init(&opts.sched, &opts.libbpf, &mut open_object, &opts.log_level)?;
        let task_size = std::mem::size_of::<types::task_p2dq>();
        let arenalib = ArenaLib::init(sched.skel.object_mut(), task_size, *NR_CPU_IDS)?;
        arenalib.setup()?;

        sched.start()?;

        if !sched.run(shutdown.clone())?.should_restart() {
            break;
        }
    }
    Ok(())
}
