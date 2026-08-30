use crate::test_runner::run_test_suite;
use colored::Colorize;
use std::path::PathBuf;

pub struct TestArgs {
    pub spec: PathBuf,
    pub json: bool,
}

pub fn run_test(args: TestArgs) -> i32 {
    match run_test_suite(&args.spec) {
        Ok(summary) => {
            if args.json {
                match serde_json::to_string_pretty(&summary) {
                    Ok(j) => println!("{}", j),
                    Err(e) => {
                        eprintln!("{} Failed to serialize JSON: {}", "ERROR:".red().bold(), e);
                        return 2;
                    }
                }
            } else {
                print!("{}", summary.render_terminal());
            }

            if summary.failed > 0 {
                1
            } else {
                0
            }
        }
        Err(err) => {
            eprintln!("{} {}", "ERROR:".red().bold(), err);
            2
        }
    }
}
