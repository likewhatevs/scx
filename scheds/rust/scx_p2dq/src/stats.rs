use std::io::Write;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use scx_stats::prelude::*;
use scx_stats_derive::stat_doc;
use scx_stats_derive::Stats;
use serde::Deserialize;
use serde::Serialize;

#[stat_doc]
#[derive(Clone, Debug, Default, Serialize, Deserialize, Stats)]
#[stat(top)]
pub struct Metrics {
    #[stat(desc = "Scheduler mode")]
    pub sched_mode: u32,
    #[stat(desc = "Number of times tasks have switched DSQs")]
    pub dsq_change: u64,
    #[stat(desc = "Number of times tasks have stayed on the same DSQ")]
    pub same_dsq: u64,
    #[stat(desc = "Number of times a task kept running")]
    pub keep: u64,
    #[stat(desc = "Number of times a pick 2 load balancing occured")]
    pub pick2: u64,
    #[stat(desc = "Number of times a task migrated LLCs")]
    pub llc_migrations: u64,
}

impl Metrics {
    fn format<W: Write>(&self, w: &mut W) -> Result<()> {
        writeln!(
            w,
            "same_dsq: {} dsq_change: {} keep: {} pick2: {}\n\tllc_migrations: {}",
            self.same_dsq, self.dsq_change, self.keep, self.pick2, self.llc_migrations
        )?;
        Ok(())
    }

    fn delta(&self, rhs: &Self) -> Self {
        Self {
            dsq_change: self.dsq_change - rhs.dsq_change,
            same_dsq: self.same_dsq - rhs.same_dsq,
            keep: self.keep - rhs.keep,
            pick2: self.pick2 - rhs.pick2,
            llc_migrations: self.llc_migrations - rhs.llc_migrations,
            ..self.clone()
        }
    }
}
pub fn server_data() -> StatsServerData<(), Metrics> {
    let open: Box<dyn StatsOpener<(), Metrics>> = Box::new(move |(req_ch, res_ch)| {
        req_ch.send(())?;
        let mut prev = res_ch.recv()?;

        let read: Box<dyn StatsReader<(), Metrics>> = Box::new(move |_args, (req_ch, res_ch)| {
            req_ch.send(())?;
            let cur = res_ch.recv()?;
            let delta = cur.delta(&prev);
            prev = cur;
            delta.to_json()
        });

        Ok(read)
    });

    StatsServerData::new()
        .add_meta(Metrics::meta())
        .add_ops("top", StatsOps { open, close: None })
}

pub fn monitor(intv: Duration, shutdown: Arc<AtomicBool>) -> Result<()> {
    scx_utils::monitor_stats::<Metrics>(
        &[],
        intv,
        || shutdown.load(Ordering::Relaxed),
        |metrics| metrics.format(&mut std::io::stdout()),
    )
}
