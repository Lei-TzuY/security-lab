mod authority_delta;

use security_lab::SandboxPolicy;
use std::env;
use std::ffi::OsStr;
use std::fs;
use std::path::Path;
use std::process;

fn main() {
    let mut args = env::args_os();
    let program = args.next().unwrap_or_default();
    let command = args.next();
    let baseline_path = args.next();
    let candidate_path = args.next();
    let has_extra_args = args.next().is_some();

    let json_requested = command.as_deref() == Some(OsStr::new("compare-json"));
    let human_requested = command.as_deref() == Some(OsStr::new("compare"));
    if (!json_requested && !human_requested)
        || baseline_path.is_none()
        || candidate_path.is_none()
        || has_extra_args
    {
        let usage = format!(
            "usage: {} <compare|compare-json> <baseline-policy> <candidate-policy>",
            program.to_string_lossy()
        );
        if json_requested {
            println!("{}", error_json("usage", &usage));
        } else {
            eprintln!("{usage}");
        }
        process::exit(2);
    }

    let baseline = load_policy(
        Path::new(&baseline_path.expect("baseline path checked above")),
        "baseline",
        json_requested,
    );
    let candidate = load_policy(
        Path::new(&candidate_path.expect("candidate path checked above")),
        "candidate",
        json_requested,
    );
    let delta = authority_delta::compare(&baseline, &candidate);
    if json_requested {
        println!("{}", delta.to_json());
    } else {
        print!("{}", delta.to_human());
    }
    process::exit(delta.exit_code());
}

fn load_policy(path: &Path, label: &str, machine: bool) -> SandboxPolicy {
    let text = match fs::read_to_string(path) {
        Ok(text) => text,
        Err(error) => fail(
            machine,
            &format!("{label}_policy_read"),
            &format!("{label} policy read failed: {error}"),
        ),
    };
    match text.parse() {
        Ok(policy) => policy,
        Err(error) => fail(
            machine,
            &format!("{label}_policy_rejected"),
            &format!("{label} policy rejected: {error}"),
        ),
    }
}

fn fail(machine: bool, kind: &str, message: &str) -> ! {
    if machine {
        println!("{}", error_json(kind, message));
    } else {
        eprintln!("{message}");
    }
    process::exit(2);
}

fn error_json(kind: &str, message: &str) -> String {
    let mut output = String::from("{\"ok\":false,\"error\":{\"kind\":");
    push_json_string(&mut output, kind);
    output.push_str(",\"message\":");
    push_json_string(&mut output, message);
    output.push_str("}}");
    output
}

fn push_json_string(output: &mut String, value: &str) {
    use std::fmt::Write as _;

    output.push('"');
    for character in value.chars() {
        match character {
            '"' => output.push_str("\\\""),
            '\\' => output.push_str("\\\\"),
            '\n' => output.push_str("\\n"),
            '\r' => output.push_str("\\r"),
            '\t' => output.push_str("\\t"),
            character if character <= '\u{1f}' => {
                write!(output, "\\u{:04x}", character as u32).expect("write to String cannot fail");
            }
            character => output.push(character),
        }
    }
    output.push('"');
}
