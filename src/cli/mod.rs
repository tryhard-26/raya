pub mod bench;
pub mod check;
pub mod compile;
pub mod process;
pub mod scan;
pub mod test;

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

        /// Output format: text, json, sarif, or stix
        #[arg(long, value_name = "FORMAT")]
        format: Option<String>,

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
    },

    /// Pre-compile rules into a high-performance binary cache (.rc)
    Compile {
        /// Path to rule file or directory containing rules
        rules: PathBuf,

        /// Output compiled rule cache path
        #[arg(short, long, default_value = "rules.rc")]
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

    /// Display version and build information
    Version,
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
            pid,
            quiet,
            tag,
            threads,
        } => scan::run_scan(scan::ScanArgs {
            target,
            rules,
            recursive,
            json,
            format,
            pid,
            quiet,
            tag,
            threads,
        }),
        Commands::Compile { rules, output } => {
            compile::run_compile(compile::CompileArgs { rules, output })
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
        Commands::Version => {
            println!("raya {}", env!("CARGO_PKG_VERSION"));
            println!("Architecture: {}", std::env::consts::ARCH);
            println!("OS:           {}", std::env::consts::OS);
            println!("Engine:       Raya Core v{}", env!("CARGO_PKG_VERSION"));
            0
        }
    }
}
