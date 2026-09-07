from pathlib import Path

path = Path("src/platform/linux.rs")
text = path.read_text()

old = '''        let control_flags = lifecycle_record.timed_out
            + lifecycle_record.cancelled
            + lifecycle_record.output_limit_exceeded;
        if control_flags > 1 {
            return Err(SandboxError::SetupFailed(format!(
                "PID namespace lifecycle published conflicting termination flags timed_out={} cancelled={} output_limit_exceeded={}",
                lifecycle_record.timed_out,
                lifecycle_record.cancelled,
                lifecycle_record.output_limit_exceeded
            )));
        }
        let outcome = if output_limit_observed || lifecycle_record.output_limit_exceeded == 1 {
            ChildOutcome::OutputLimitExceeded
        } else {
            match (lifecycle_record.timed_out, lifecycle_record.cancelled) {
                (0, 0) => decode_wait_status(lifecycle_record.status)?,
                (1, 0) => ChildOutcome::TimedOut,
                (0, 1) => ChildOutcome::Cancelled,
                (timed_out, cancelled) => {
                    return Err(SandboxError::SetupFailed(format!(
                        "PID namespace lifecycle published invalid termination flags timed_out={timed_out} cancelled={cancelled}"
                    )));
                }
            }
        };
'''
new = '''        let outcome = resolve_lifecycle_outcome(&lifecycle_record, output_limit_observed)?;
'''
if text.count(old) != 1:
    raise SystemExit(f"outcome arbitration block: expected 1 match, got {text.count(old)}")
text = text.replace(old, new, 1)

marker = '''    fn decode_wait_status(status: libc::c_int) -> Result<ChildOutcome, SandboxError> {
'''
helper = '''    fn resolve_lifecycle_outcome(
        lifecycle_record: &TargetLifecycleRecord,
        output_limit_observed: bool,
    ) -> Result<ChildOutcome, SandboxError> {
        let control_flags = lifecycle_record.timed_out
            + lifecycle_record.cancelled
            + lifecycle_record.output_limit_exceeded;
        if control_flags > 1 {
            return Err(SandboxError::SetupFailed(format!(
                "PID namespace lifecycle published conflicting termination flags timed_out={} cancelled={} output_limit_exceeded={}",
                lifecycle_record.timed_out,
                lifecycle_record.cancelled,
                lifecycle_record.output_limit_exceeded
            )));
        }

        match (
            lifecycle_record.timed_out,
            lifecycle_record.cancelled,
            lifecycle_record.output_limit_exceeded,
        ) {
            (0, 0, 1) => Ok(ChildOutcome::OutputLimitExceeded),
            (1, 0, 0) => Ok(ChildOutcome::TimedOut),
            (0, 1, 0) => Ok(ChildOutcome::Cancelled),
            (0, 0, 0) if output_limit_observed => Ok(ChildOutcome::OutputLimitExceeded),
            (0, 0, 0) => decode_wait_status(lifecycle_record.status),
            (timed_out, cancelled, output_limit_exceeded) => {
                Err(SandboxError::SetupFailed(format!(
                    "PID namespace lifecycle published invalid termination flags timed_out={timed_out} cancelled={cancelled} output_limit_exceeded={output_limit_exceeded}"
                )))
            }
        }
    }

'''
if text.count(marker) != 1:
    raise SystemExit(f"decode marker: expected 1 match, got {text.count(marker)}")
text = text.replace(marker, helper + marker, 1)

test_module = '''
    #[cfg(test)]
    mod output_outcome_tests {
        use super::*;

        fn lifecycle(
            status: libc::c_int,
            timed_out: u32,
            cancelled: u32,
            output_limit_exceeded: u32,
        ) -> TargetLifecycleRecord {
            TargetLifecycleRecord {
                status,
                reaped_descendants: 0,
                timed_out,
                cancelled,
                output_limit_exceeded,
                user_cpu_micros: 0,
                system_cpu_micros: 0,
                max_child_rss_kib: 0,
                ready: 1,
            }
        }

        #[test]
        fn late_output_observation_does_not_replace_existing_control_owner() {
            let timed_out = lifecycle(9, 1, 0, 0);
            assert_eq!(
                resolve_lifecycle_outcome(&timed_out, true).unwrap(),
                ChildOutcome::TimedOut
            );

            let cancelled = lifecycle(9, 0, 1, 0);
            assert_eq!(
                resolve_lifecycle_outcome(&cancelled, true).unwrap(),
                ChildOutcome::Cancelled
            );
        }

        #[test]
        fn output_budget_still_owns_observed_natural_completion_or_pid1_flag() {
            let natural = lifecycle(42 << 8, 0, 0, 0);
            assert_eq!(
                resolve_lifecycle_outcome(&natural, true).unwrap(),
                ChildOutcome::OutputLimitExceeded
            );

            let pid1_owned = lifecycle(9, 0, 0, 1);
            assert_eq!(
                resolve_lifecycle_outcome(&pid1_owned, false).unwrap(),
                ChildOutcome::OutputLimitExceeded
            );
        }
    }
'''
if not text.endswith("}\n"):
    raise SystemExit("linux x86_64 module does not end with the expected closing brace")
text = text[:-2] + test_module + "}\n"
path.write_text(text)
