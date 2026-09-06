use security_lab::{run, ChildOutcome, SandboxPolicy};
use std::env;
use std::fs;
use std::process;

fn main() {
    let mut args = env::args_os();
    let program = args.next().unwrap_or_default();
    let command = args.next();
    let policy_path = args.next();

    if command.as_deref() != Some(std::ffi::OsStr::new("run"))
        || policy_path.is_none()
        || args.next().is_some()
    {
        eprintln!("usage: {} run <policy-file>", program.to_string_lossy());
        process::exit(2);
    }

    let policy_path = policy_path.unwrap();
    let text = match fs::read_to_string(&policy_path) {
        Ok(text) => text,
        Err(err) => {
            eprintln!("policy read failed: {err}");
            process::exit(2);
        }
    };
    let policy: SandboxPolicy = match text.parse() {
        Ok(policy) => policy,
        Err(err) => {
            eprintln!("policy rejected: {err}");
            process::exit(2);
        }
    };

    match run(&policy) {
        Ok(outcome) => {
            println!("sandbox-result: {outcome}");
            match outcome {
                ChildOutcome::Exited(code) => process::exit(code),
                ChildOutcome::Signaled(signal) => process::exit(128 + signal),
                ChildOutcome::TimedOut => process::exit(124),
                ChildOutcome::Cancelled => process::exit(130),
            }
        }
        Err(err) => {
            eprintln!("sandbox-error: {err}");
            process::exit(125);
        }
    }
}
