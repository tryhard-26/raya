// src/cli/sync.rs
//
// CLI command handler for `raya rules sync`
// Synchronizes detection rules from threat intelligence feeds.

use crate::sync::{run_sync, SyncConfig};
use std::path::PathBuf;

pub struct SyncArgs {
    pub feed: String,
    pub output: PathBuf,
    pub compile: bool,
}

pub fn run_sync_cli(args: SyncArgs) -> i32 {
    run_sync(SyncConfig {
        feed_name_or_url: args.feed,
        output_dir: args.output,
        compile_cache: args.compile,
    })
}
