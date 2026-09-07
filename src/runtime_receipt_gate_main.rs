use security_lab::{run_report, EnforcementReceipt, SandboxPolicy};
use std::env;
use std::ffi::OsStr;
use std::fmt::Write as _;
use std::fs;
use std::path::Path;
use std::process;

const EXIT_USAGE_OR_POLICY: i32 = 2;
const EXIT_RUNTIME_ERROR: i32 = 3;
const EXIT_RECEIPT_INCOMPLETE: i32 = 7;
const EXIT_RECEIPT_UNEXPECTED: i32 = 8;

#[derive(Debug, PartialEq, Eq)]
struct ReceiptAssessment {
    required: Vec<&'static str>,
    missing: Vec<&'static str>,
    unexpected: Vec<&'static str>,
}

impl ReceiptAssessment {
    fn complete(&self) -> bool {
        self.missing.is_empty() && self.unexpected.is_empty()
    }

    fn exit_code(&self) -> i32 {
        if !self.unexpected.is_empty() {
            EXIT_RECEIPT_UNEXPECTED
        } else if !self.missing.is_empty() {
            EXIT_RECEIPT_INCOMPLETE
        } else {
            0
        }
    }
}

fn main() {
    let mut args = env::args_os();
    let program = args.next().unwrap_or_default();
    let command = args.next();
    let policy_path = args.next();
    let has_extra_args = args.next().is_some();

    let json_requested = command.as_deref() == Some(OsStr::new("check-json"));
    let human_requested = command.as_deref() == Some(OsStr::new("check"));
    if (!json_requested && !human_requested) || policy_path.is_none() || has_extra_args {
        let usage = format!(
            "usage: {} <check|check-json> <policy>",
            program.to_string_lossy()
        );
        fail(
            json_requested,
            EXIT_USAGE_OR_POLICY,
            "usage",
            &usage,
        );
    }

    let policy = load_policy(
        Path::new(&policy_path.expect("policy path checked above")),
        json_requested,
    );
    let report = match run_report(&policy) {
        Ok(report) => report,
        Err(error) => fail(
            json_requested,
            EXIT_RUNTIME_ERROR,
            "runtime_error",
            &format!("sandbox execution failed: {error}"),
        ),
    };
    let assessment = assess(&policy, &report.enforcement);

    if json_requested {
        println!(
            "{}",
            assessment_json(&assessment, &report.outcome.to_string())
        );
    } else {
        print!(
            "{}",
            assessment_human(&assessment, &report.outcome.to_string())
        );
    }
    process::exit(assessment.exit_code());
}

fn load_policy(path: &Path, machine: bool) -> SandboxPolicy {
    let text = match fs::read_to_string(path) {
        Ok(text) => text,
        Err(error) => fail(
            machine,
            EXIT_USAGE_OR_POLICY,
            "policy_read",
            &format!("policy read failed: {error}"),
        ),
    };
    match text.parse() {
        Ok(policy) => policy,
        Err(error) => fail(
            machine,
            EXIT_USAGE_OR_POLICY,
            "policy_rejected",
            &format!("policy rejected: {error}"),
        ),
    }
}

fn assess(policy: &SandboxPolicy, receipt: &EnforcementReceipt) -> ReceiptAssessment {
    let mut required = Vec::new();
    let mut missing = Vec::new();
    let mut unexpected = Vec::new();

    require(&mut required, &mut missing, "base_namespaces", receipt.base_namespaces);
    if policy.time_monotonic_offset_seconds.is_some() {
        require(
            &mut required,
            &mut missing,
            "time_namespace_offsets",
            receipt.time_namespace_offsets,
        );
    } else if receipt.time_namespace_offsets {
        unexpected.push("time_namespace_offsets");
    }
    require(&mut required, &mut missing, "hostname", receipt.hostname);
    require(
        &mut required,
        &mut missing,
        "private_mount_propagation",
        receipt.private_mount_propagation,
    );
    require(&mut required, &mut missing, "readonly_root", receipt.readonly_root);
    require(&mut required, &mut missing, "chroot", receipt.chroot);
    require(
        &mut required,
        &mut missing,
        "fd_sanitization",
        receipt.fd_sanitization,
    );
    if policy.procfs_enabled {
        require(
            &mut required,
            &mut missing,
            "private_procfs",
            receipt.private_procfs,
        );
    } else if receipt.private_procfs {
        unexpected.push("private_procfs");
    }
    require(&mut required, &mut missing, "rlimits", receipt.rlimits);
    require(
        &mut required,
        &mut missing,
        "capabilities_reduced",
        receipt.capabilities_reduced,
    );
    require(
        &mut required,
        &mut missing,
        "no_new_privs",
        receipt.no_new_privs,
    );
    if landlock_requested(policy) {
        require(&mut required, &mut missing, "landlock", receipt.landlock);
    } else if receipt.landlock {
        unexpected.push("landlock");
    }
    require(&mut required, &mut missing, "seccomp", receipt.seccomp);

    ReceiptAssessment {
        required,
        missing,
        unexpected,
    }
}

fn landlock_requested(policy: &SandboxPolicy) -> bool {
    !policy.landlock_read_execute.is_empty()
        || !policy.landlock_file_mutate.is_empty()
        || !policy.landlock_path_topology_mutate.is_empty()
        || !policy.landlock_device_ioctl.is_empty()
        || !policy.landlock_tcp_bind_ports.is_empty()
        || !policy.landlock_tcp_connect_ports.is_empty()
        || policy.landlock_scope_abstract_unix_socket
        || policy.landlock_scope_signal
}

fn require(
    required: &mut Vec<&'static str>,
    missing: &mut Vec<&'static str>,
    name: &'static str,
    observed: bool,
) {
    required.push(name);
    if !observed {
        missing.push(name);
    }
}

fn assessment_human(assessment: &ReceiptAssessment, outcome: &str) -> String {
    let mut output = String::new();
    writeln!(&mut output, "runtime-receipt-gate:").expect("write to String cannot fail");
    writeln!(&mut output, "receipt-complete: {}", assessment.complete())
        .expect("write to String cannot fail");
    writeln!(&mut output, "full-policy-attestation: false")
        .expect("write to String cannot fail");
    writeln!(&mut output, "exec-success-proof: false").expect("write to String cannot fail");
    writeln!(&mut output, "target-outcome: {outcome}").expect("write to String cannot fail");
    writeln!(&mut output, "required: {}", join_names(&assessment.required))
        .expect("write to String cannot fail");
    writeln!(&mut output, "missing: {}", join_names(&assessment.missing))
        .expect("write to String cannot fail");
    writeln!(
        &mut output,
        "unexpected: {}",
        join_names(&assessment.unexpected)
    )
    .expect("write to String cannot fail");
    output
}

fn assessment_json(assessment: &ReceiptAssessment, outcome: &str) -> String {
    let mut output = String::from("{\"ok\":");
    output.push_str(if assessment.complete() { "true" } else { "false" });
    output.push_str(",\"kind\":\"runtime_receipt_gate\",\"receipt_complete\":");
    output.push_str(if assessment.complete() { "true" } else { "false" });
    output.push_str(",\"full_policy_attestation\":false,\"exec_success_proof\":false,\"target_outcome\":");
    push_json_string(&mut output, outcome);
    output.push_str(",\"required\":");
    push_json_array(&mut output, &assessment.required);
    output.push_str(",\"missing\":");
    push_json_array(&mut output, &assessment.missing);
    output.push_str(",\"unexpected\":");
    push_json_array(&mut output, &assessment.unexpected);
    output.push('}');
    output
}

fn join_names(values: &[&str]) -> String {
    if values.is_empty() {
        "-".to_owned()
    } else {
        values.join(",")
    }
}

fn push_json_array(output: &mut String, values: &[&str]) {
    output.push('[');
    for (index, value) in values.iter().enumerate() {
        if index != 0 {
            output.push(',');
        }
        push_json_string(output, value);
    }
    output.push(']');
}

fn fail(machine: bool, code: i32, kind: &str, message: &str) -> ! {
    if machine {
        let mut output = String::from("{\"ok\":false,\"error\":{\"kind\":");
        push_json_string(&mut output, kind);
        output.push_str(",\"message\":");
        push_json_string(&mut output, message);
        output.push_str("},\"full_policy_attestation\":false,\"exec_success_proof\":false}");
        println!("{output}");
    } else {
        eprintln!("{message}");
    }
    process::exit(code);
}

fn push_json_string(output: &mut String, value: &str) {
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

#[cfg(test)]
mod tests {
    use super::*;

    const POLICY: &str = r#"
        filesystem.root = /tmp/security-lab-receipt-unit-root
        identity.hostname = receipt-gate
        executable = /probe
        arg = X
        working_dir = /work
        stdio.stdin = closed
        stdio.stdout = closed
        stdio.stderr = closed
        limit.cpu_seconds = 1
        limit.address_space_bytes = 134217728
        limit.file_size_bytes = 1048576
        limit.open_files = 32
        seccomp.allow = execveat,exit
    "#;

    fn policy(extra: &str) -> SandboxPolicy {
        format!("{POLICY}\n{extra}").parse().unwrap()
    }

    fn complete_base_receipt() -> EnforcementReceipt {
        EnforcementReceipt {
            base_namespaces: true,
            time_namespace_offsets: false,
            hostname: true,
            private_mount_propagation: true,
            readonly_root: true,
            chroot: true,
            fd_sanitization: true,
            private_procfs: false,
            rlimits: true,
            capabilities_reduced: true,
            no_new_privs: true,
            landlock: false,
            seccomp: true,
        }
    }

    #[test]
    fn complete_receipt_accepts_nonzero_target_outcome_independently() {
        let assessment = assess(&policy(""), &complete_base_receipt());
        assert!(assessment.complete());
        assert_eq!(assessment.exit_code(), 0);
    }

    #[test]
    fn missing_mandatory_stage_fails_closed() {
        let mut receipt = complete_base_receipt();
        receipt.seccomp = false;
        let assessment = assess(&policy(""), &receipt);
        assert_eq!(assessment.missing, vec!["seccomp"]);
        assert_eq!(assessment.exit_code(), EXIT_RECEIPT_INCOMPLETE);
    }

    #[test]
    fn requested_optional_stage_becomes_required() {
        let receipt = complete_base_receipt();
        let assessment = assess(&policy("filesystem.proc = enabled"), &receipt);
        assert_eq!(assessment.missing, vec!["private_procfs"]);
        assert_eq!(assessment.exit_code(), EXIT_RECEIPT_INCOMPLETE);
    }

    #[test]
    fn unrequested_optional_stage_is_rejected_as_unexpected() {
        let mut receipt = complete_base_receipt();
        receipt.landlock = true;
        let assessment = assess(&policy(""), &receipt);
        assert_eq!(assessment.unexpected, vec!["landlock"]);
        assert_eq!(assessment.exit_code(), EXIT_RECEIPT_UNEXPECTED);
    }
}
