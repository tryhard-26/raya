// src/cli/watch.rs
//
// CLI command handler for `raya watch <dir>`
// Runs real-time drop folder monitoring and quarantine.

use crate::watch::{run_watchdog, WatchConfig};
use std::path::PathBuf;

pub struct WatchArgs {
    pub watch_dir: PathBuf,
    pub rules: PathBuf,
    pub quarantine: Option<PathBuf>,
    pub interval_ms: u64,
    pub once: bool,
    pub password: Option<String>,
}

pub fn run_watch(args: WatchArgs) -> i32 {
    run_watchdog(WatchConfig {
        watch_dir: args.watch_dir,
        rules_path: args.rules,
        quarantine_dir: args.quarantine,
        poll_interval_ms: args.interval_ms,
        run_once: args.once,
        password: args.password,
    })
}
