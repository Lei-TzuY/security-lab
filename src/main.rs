mod cli_json;

use security_lab::{run, run_report, SandboxPolicy};
use std::env;
use std::ffi::OsStr;
use std::fs;
use std::process;

fn main() {
    let mut args = env::args_os();
    let program = args.next().unwrap_or_default();
    let command = args.next();
    let policy_path = args.next();
    let has_extra_args = args.next().is_some();
    let json_requested = command.as_deref() == Some(OsStr::new("run-json"));
    let human_requested = command.as_deref() == Some(OsStr::new("run"));

    if (!json_requested && !human_requested) || policy_path.is_none() || has_extra_args {
        let usage = format!(
            "usage: {} <run|run-json> <policy-file>",
            program.to_string_lossy()
        );
        if json_requested {
            println!("{}", cli_json::error_json("usage", &usage));
        } else {
            eprintln!("{usage}");
        }
        process::exit(2);
    }

    let policy_path = policy_path.expect("policy path was checked above");
    let text = match fs::read_to_string(&policy_path) {
        Ok(text) => text,
        Err(err) => {
            if json_requested {
                println!("{}", cli_json::error_json("policy_read", &err.to_string()));
            } else {
                eprintln!("policy read failed: {err}");
            }
            process::exit(2);
        }
    };
    let policy: SandboxPolicy = match text.parse() {
        Ok(policy) => policy,
        Err(err) => {
            if json_requested {
                println!(
                    "{}",
                    cli_json::error_json("policy_rejected", &err.to_string())
                );
            } else {
                eprintln!("policy rejected: {err}");
            }
            process::exit(2);
        }
    };

    if json_requested {
        run_json(&policy)
    } else {
        run_human(&policy)
    }
}

fn run_human(policy: &SandboxPolicy) -> ! {
    match run(policy) {
        Ok(outcome) => {
            println!("sandbox-result: {outcome}");
            process::exit(cli_json::outcome_exit_code(outcome));
        }
        Err(err) => {
            eprintln!("sandbox-error: {err}");
            process::exit(125);
        }
    }
}

fn run_json(policy: &SandboxPolicy) -> ! {
    match run_report(policy) {
        Ok(report) => {
            println!("{}", cli_json::report_json(&report));
            process::exit(cli_json::outcome_exit_code(report.outcome));
        }
        Err(err) => {
            println!(
                "{}",
                cli_json::error_json(cli_json::sandbox_error_kind(&err), &err.to_string())
            );
            process::exit(125);
        }
    }
}
