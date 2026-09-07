use security_lab::{ChildOutcome, RunReport, SandboxError};
use std::fmt::Write as _;

pub(crate) fn report_json(report: &RunReport) -> String {
    let mut output = String::from("{\"ok\":true,\"outcome\":");
    push_outcome(&mut output, report.outcome);
    output.push_str(",\"stdout\":");
    match &report.stdout {
        Some(captured) => {
            output.push_str("{\"encoding\":\"hex\",\"data\":\"");
            push_hex(&mut output, &captured.bytes);
            output.push_str("\",\"truncated\":");
            output.push_str(if captured.truncated { "true" } else { "false" });
            output.push('}');
        }
        None => output.push_str("null"),
    }
    output.push_str(",\"reaped_descendants\":");
    write!(&mut output, "{}", report.reaped_descendants).expect("write to String cannot fail");
    output.push_str(",\"process_tree_usage\":{\"user_cpu_micros\":");
    write!(&mut output, "{}", report.process_tree_usage.user_cpu_micros)
        .expect("write to String cannot fail");
    output.push_str(",\"system_cpu_micros\":");
    write!(
        &mut output,
        "{}",
        report.process_tree_usage.system_cpu_micros
    )
    .expect("write to String cannot fail");
    output.push_str(",\"max_child_rss_kib\":");
    write!(
        &mut output,
        "{}",
        report.process_tree_usage.max_child_rss_kib
    )
    .expect("write to String cannot fail");
    output.push_str("}}");
    output
}

pub(crate) fn validation_json() -> &'static str {
    "{\"ok\":true,\"validation\":{\"kind\":\"static_policy\",\"runtime_preflight\":false}}"
}

pub(crate) fn error_json(kind: &str, message: &str) -> String {
    let mut output = String::from("{\"ok\":false,\"error\":{\"kind\":");
    push_json_string(&mut output, kind);
    output.push_str(",\"message\":");
    push_json_string(&mut output, message);
    output.push_str("}}");
    output
}

pub(crate) fn sandbox_error_kind(error: &SandboxError) -> &'static str {
    match error {
        SandboxError::InvalidPolicy(_) => "invalid_policy",
        SandboxError::UnsupportedPlatform(_) => "unsupported_platform",
        SandboxError::SetupFailed(_) => "setup_failed",
    }
}

pub(crate) fn outcome_exit_code(outcome: ChildOutcome) -> i32 {
    match outcome {
        ChildOutcome::Exited(code) => code,
        ChildOutcome::Signaled(signal) => 128 + signal,
        ChildOutcome::TimedOut => 124,
        ChildOutcome::Cancelled => 130,
        ChildOutcome::OutputLimitExceeded => 122,
    }
}

fn push_outcome(output: &mut String, outcome: ChildOutcome) {
    match outcome {
        ChildOutcome::Exited(code) => {
            output.push_str("{\"kind\":\"exited\",\"code\":");
            write!(output, "{code}").expect("write to String cannot fail");
            output.push('}');
        }
        ChildOutcome::Signaled(signal) => {
            output.push_str("{\"kind\":\"signaled\",\"signal\":");
            write!(output, "{signal}").expect("write to String cannot fail");
            output.push('}');
        }
        ChildOutcome::TimedOut => output.push_str("{\"kind\":\"timed_out\"}"),
        ChildOutcome::Cancelled => output.push_str("{\"kind\":\"cancelled\"}"),
        ChildOutcome::OutputLimitExceeded => {
            output.push_str("{\"kind\":\"output_limit_exceeded\"}")
        }
    }
}

fn push_hex(output: &mut String, bytes: &[u8]) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    output.reserve(bytes.len().saturating_mul(2));
    for &byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
}

fn push_json_string(output: &mut String, value: &str) {
    output.push('"');
    for character in value.chars() {
        match character {
            '"' => output.push_str("\\\""),
            '\\' => output.push_str("\\\\"),
            '\u{08}' => output.push_str("\\b"),
            '\u{0c}' => output.push_str("\\f"),
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
    use security_lab::{CapturedOutput, EnforcementReceipt, ProcessTreeUsage, RunReport};

    #[test]
    fn serializes_binary_capture_without_loss() {
        let report = RunReport {
            outcome: ChildOutcome::Exited(7),
            stdout: Some(CapturedOutput {
                bytes: vec![0x00, 0x22, 0xff],
                truncated: true,
            }),
            reaped_descendants: 3,
            process_tree_usage: ProcessTreeUsage {
                user_cpu_micros: 11,
                system_cpu_micros: 22,
                max_child_rss_kib: 33,
            },
            enforcement: EnforcementReceipt::default(),
        };

        assert_eq!(
            report_json(&report),
            "{\"ok\":true,\"outcome\":{\"kind\":\"exited\",\"code\":7},\"stdout\":{\"encoding\":\"hex\",\"data\":\"0022ff\",\"truncated\":true},\"reaped_descendants\":3,\"process_tree_usage\":{\"user_cpu_micros\":11,\"system_cpu_micros\":22,\"max_child_rss_kib\":33}}"
        );
    }

    #[test]
    fn serializes_static_validation_scope_explicitly() {
        assert_eq!(
            validation_json(),
            "{\"ok\":true,\"validation\":{\"kind\":\"static_policy\",\"runtime_preflight\":false}}"
        );
    }

    #[test]
    fn serializes_stdout_output_limit_outcome() {
        let report = RunReport {
            outcome: ChildOutcome::OutputLimitExceeded,
            stdout: Some(CapturedOutput {
                bytes: b"prefix".to_vec(),
                truncated: true,
            }),
            reaped_descendants: 1,
            process_tree_usage: ProcessTreeUsage::default(),
            enforcement: EnforcementReceipt::default(),
        };
        assert!(report_json(&report).contains("\"kind\":\"output_limit_exceeded\""));
    }

    #[test]
    fn escapes_json_error_strings() {
        assert_eq!(
            error_json("bad\"kind", "line\\path\n\u{0001}µ"),
            "{\"ok\":false,\"error\":{\"kind\":\"bad\\\"kind\",\"message\":\"line\\\\path\\n\\u0001µ\"}}"
        );
    }

    #[test]
    fn preserves_existing_exit_status_mapping() {
        assert_eq!(outcome_exit_code(ChildOutcome::Exited(42)), 42);
        assert_eq!(outcome_exit_code(ChildOutcome::Signaled(9)), 137);
        assert_eq!(outcome_exit_code(ChildOutcome::TimedOut), 124);
        assert_eq!(outcome_exit_code(ChildOutcome::Cancelled), 130);
        assert_eq!(outcome_exit_code(ChildOutcome::OutputLimitExceeded), 122);
    }
}
