pub mod bench;
pub mod carve;
pub mod check;
pub mod compile;
pub mod config;
pub mod convert;
pub mod diff;
pub mod inspect;
pub mod process;
pub mod scan;
pub mod sync;
pub mod test;
pub mod tui;
pub mod watch;

use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
#[command(
    name = "raya",
    author = "Raya Security Engineering",
    version,
    about = "Rust-native malware detection and binary pattern-matching engine",
    long_about = "Raya is a modern, high-performance binary analysis and static detection engine.\nIt provides multi-pattern string/hex/regex matching, deep PE/ELF/Mach-O inspection, Shannon entropy analysis, and explainable verdicts."
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Scan a file, directory, live process memory, or stdin against Raya detection rules
    Scan {
        /// Target file, directory, or '-' for standard input
        #[arg(value_name = "TARGET")]
        target: Option<PathBuf>,

        /// Path to rule file, directory, or precompiled .rc rule cache (default: ./rules)
        #[arg(short = 'R', long)]
        rules: Option<PathBuf>,

        /// Recursively traverse subdirectories
        #[arg(short = 'r', long, default_value_t = true)]
        recursive: bool,

        /// Output results in JSON format
        #[arg(long)]
        json: bool,

        /// Output format: text, json, sarif, stix, or html
        #[arg(long, value_name = "FORMAT")]
        format: Option<String>,

        /// Output file path (defaults to stdout)
        #[arg(short = 'o', long, value_name = "FILE")]
        output: Option<PathBuf>,

        /// Scan live process virtual memory by PID
        #[arg(long, value_name = "PID")]
        pid: Option<u32>,

        /// Quiet mode: emit minimal output suitable for shell pipelines
        #[arg(short, long)]
        quiet: bool,

        /// Filter rules by tag
        #[arg(short, long)]
        tag: Option<String>,

        /// Number of worker threads for parallel scanning
        #[arg(long)]
        threads: Option<usize>,

        /// Optional decryption password for password-protected archives (defaults: infected, malware, etc.)
        #[arg(long, value_name = "PASSWORD")]
        password: Option<String>,
    },

    /// Deep forensic triage and structural binary inspection dashboard
    Inspect {
        /// Target binary file to inspect
        #[arg(value_name = "TARGET")]
        target: PathBuf,

        /// Output results in JSON format
        #[arg(long)]
        json: bool,

        /// Optional decryption password for password-protected archives (defaults: infected, malware, etc.)
        #[arg(long, value_name = "PASSWORD")]
        password: Option<String>,
    },

    /// Transpile legacy YARA rules (.yar / .yara) into native Raya detection rules
    Convert {
        /// Input YARA rule file
        #[arg(value_name = "INPUT")]
        input: PathBuf,

        /// Output Raya rule file path
        #[arg(short, long, value_name = "OUTPUT")]
        output: PathBuf,
    },

    /// Pre-compile rules into a high-performance binary cache (.rc)
    Compile {
        /// Path to rule file or directory containing rules
        rules: PathBuf,

        /// Output compiled rule cache path
        #[arg(short, long, default_value = "rules.rayac")]
        output: PathBuf,
    },

    /// Validate syntax and integrity of rule files
    Check {
        /// Rule file or directory to validate
        path: PathBuf,

        /// Display verbose output for passed rules
        #[arg(short, long)]
        verbose: bool,
    },

    /// Execute rule test suite against positive and negative samples
    Test {
        /// Path to test suite specification JSON file
        spec: PathBuf,

        /// Output results in JSON format
        #[arg(long)]
        json: bool,
    },

    /// Run performance benchmarks across rules and datasets
    Bench {
        /// Target file or directory to benchmark against
        target: PathBuf,

        /// Path to rule file or directory containing rules
        #[arg(short, long)]
        rules: Option<PathBuf>,

        /// Number of benchmark iterations
        #[arg(short, long, default_value_t = 3)]
        iterations: usize,
    },

    /// Compare and diff two binaries using CFG graph isomorphism and similarity scoring
    Diff {
        /// Primary binary file (Target A)
        #[arg(value_name = "FILE_A")]
        file_a: PathBuf,

        /// Comparison binary file (Target B)
        #[arg(value_name = "FILE_B")]
        file_b: PathBuf,

        /// Output results in JSON format
        #[arg(long)]
        json: bool,
    },

    /// Extract in-memory C2 configurations (Cobalt Strike, WannaCry, Mirai, RedLine)
    Config {
        /// Target binary file or archive to extract configuration from
        #[arg(value_name = "TARGET")]
        target: PathBuf,

        /// Output results in JSON format
        #[arg(long)]
        json: bool,

        /// Optional decryption password for password-protected archives
        #[arg(long, value_name = "PASSWORD")]
        password: Option<String>,
    },

    /// Carve embedded executables, ELF binaries, archives, and overlay payloads
    Carve {
        /// Target binary file to carve artifacts from
        #[arg(value_name = "TARGET")]
        target: PathBuf,

        /// Output directory to extract carved artifacts to
        #[arg(short, long, value_name = "OUTPUT_DIR")]
        output: Option<PathBuf>,

        /// Output results in JSON format
        #[arg(long)]
        json: bool,
    },

    /// Real-time directory watchdog and automatic malware quarantine daemon
    Watch {
        /// Target directory to monitor for newly dropped files
        #[arg(value_name = "DIR")]
        target: PathBuf,

        /// Path to rule file, directory, or precompiled .rc rule cache (default: ./rules)
        #[arg(short = 'R', long, default_value = "./rules")]
        rules: PathBuf,

        /// Quarantine directory to isolate detected threats
        #[arg(short, long, value_name = "QUARANTINE_DIR")]
        quarantine: Option<PathBuf>,

        /// Polling interval in milliseconds
        #[arg(long, default_value_t = 500)]
        interval: u64,

        /// Execute a single pass scan and exit immediately
        #[arg(long)]
        once: bool,

        /// Optional decryption password for password-protected archives
        #[arg(long, value_name = "PASSWORD")]
        password: Option<String>,
    },

    /// Threat intelligence feed management and rule synchronization
    Rules {
        #[command(subcommand)]
        command: RulesCommands,
    },

    /// Launch the interactive terminal forensic triage dashboard
    Tui {
        /// Target binary file to inspect interactively
        #[arg(value_name = "TARGET")]
        target: PathBuf,

        /// Optional decryption password for password-protected archives
        #[arg(long, value_name = "PASSWORD")]
        password: Option<String>,
    },

    /// Display version and build information
    Version,
}

#[derive(Subcommand)]
pub enum RulesCommands {
    /// Synchronize and transpile rules from threat intelligence feeds
    Sync {
        /// Feed name preset (signature-base, yara-rules) or custom URL/path
        #[arg(long, default_value = "signature-base")]
        feed: String,

        /// Output directory for synchronized rules
        #[arg(short, long, default_value = "./rules/community")]
        output: PathBuf,

        /// Precompile synchronized rules into rules.rcache binary cache
        #[arg(long, default_value_t = true)]
        compile: bool,
    },
}

pub fn run_cli() -> i32 {
    let cli = Cli::parse();

    match cli.command {
        Commands::Scan {
            target,
            rules,
            recursive,
            json,
            format,
            output,
            pid,
            quiet,
            tag,
            threads,
            password,
        } => scan::run_scan(scan::ScanArgs {
            target,
            rules,
            recursive,
            json,
            format,
            output,
            pid,
            quiet,
            tag,
            threads,
            password,
        }),
        Commands::Compile { rules, output } => {
            compile::run_compile(compile::CompileArgs { rules, output })
        }
        Commands::Inspect {
            target,
            json,
            password,
        } => inspect::run_inspect(inspect::InspectArgs {
            target,
            json,
            password,
        }),
        Commands::Convert { input, output } => {
            convert::run_convert(convert::ConvertArgs { input, output })
        }
        Commands::Check { path, verbose } => check::run_check(check::CheckArgs { path, verbose }),
        Commands::Test { spec, json } => test::run_test(test::TestArgs { spec, json }),
        Commands::Bench {
            target,
            rules,
            iterations,
        } => bench::run_bench(bench::BenchArgs {
            target,
            rules,
            iterations,
        }),
        Commands::Diff {
            file_a,
            file_b,
            json,
        } => diff::run_diff(diff::DiffArgs {
            file_a,
            file_b,
            json,
        }),
        Commands::Config {
            target,
            json,
            password,
        } => config::run_config(config::ConfigArgs {
            target,
            json,
            password,
        }),
        Commands::Carve {
            target,
            output,
            json,
        } => carve::run_carve(carve::CarveArgs {
            target,
            output_dir: output,
            json,
        }),
        Commands::Watch {
            target,
            rules,
            quarantine,
            interval,
            once,
            password,
        } => watch::run_watch(watch::WatchArgs {
            watch_dir: target,
            rules,
            quarantine,
            interval_ms: interval,
            once,
            password,
        }),
        Commands::Rules { command } => match command {
            RulesCommands::Sync {
                feed,
                output,
                compile,
            } => sync::run_sync_cli(sync::SyncArgs {
                feed,
                output,
                compile,
            }),
        },
        Commands::Tui { target, password } => tui::run_tui_cli(tui::TuiArgs { target, password }),
        Commands::Version => {
            println!("raya {}", env!("CARGO_PKG_VERSION"));
            println!("Architecture: {}", std::env::consts::ARCH);
            println!("OS:           {}", std::env::consts::OS);
            println!("Engine:       Raya Core v{}", env!("CARGO_PKG_VERSION"));
            0
        }
    }
}
