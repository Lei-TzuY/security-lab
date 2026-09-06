mod cli_json;
mod host_capabilities;

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
    let run_json_requested = command.as_deref() == Some(OsStr::new("run-json"));
    let run_requested = command.as_deref() == Some(OsStr::new("run"));
    let check_json_requested = command.as_deref() == Some(OsStr::new("check-json"));
    let check_requested = command.as_deref() == Some(OsStr::new("check"));
    let host_json_requested = command.as_deref() == Some(OsStr::new("host-json"));
    let host_requested = command.as_deref() == Some(OsStr::new("host"));
    let host_command = host_json_requested || host_requested;
    let machine_requested = run_json_requested || check_json_requested || host_json_requested;
    let recognized_command = run_json_requested
        || run_requested
        || check_json_requested
        || check_requested
        || host_json_requested
        || host_requested;
    let invalid_shape = if host_command {
        policy_path.is_some() || has_extra_args
    } else {
        policy_path.is_none() || has_extra_args
    };

    if !recognized_command || invalid_shape {
        let display_program = program.to_string_lossy();
        let usage = format!(
            "usage: {display_program} <run|run-json|check|check-json> <policy-file> | {display_program} <host|host-json>"
        );
        if machine_requested {
            println!("{}", cli_json::error_json("usage", &usage));
        } else {
            eprintln!("{usage}");
        }
        process::exit(2);
    }

    if host_json_requested {
        println!("{}", host_capabilities::probe().to_json());
        return;
    }
    if host_requested {
        print!("{}", host_capabilities::probe().to_human());
        return;
    }

    let policy_path = policy_path.expect("policy path was checked above");
    let text = match fs::read_to_string(&policy_path) {
        Ok(text) => text,
        Err(err) => {
            if machine_requested {
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
            if machine_requested {
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

    if check_json_requested {
        println!("{}", cli_json::validation_json());
        process::exit(0);
    }
    if check_requested {
        println!("policy-valid");
        process::exit(0);
    }
    if run_json_requested {
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
