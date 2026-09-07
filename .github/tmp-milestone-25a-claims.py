from pathlib import Path


def replace_one(path: str, old: str, new: str, label: str) -> None:
    p = Path(path)
    text = p.read_text()
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{label}: expected exactly one match, got {count}")
    p.write_text(text.replace(old, new, 1))


# README: distinguish static manifest, partial preflight, and post-attempt receipt.
replace_one(
    "README.md",
    "Milestone 24A added deterministic human and JSON **static policy-authority manifests** that validate policy without launching or probing runtime support. The current Milestone 24B verified candidate adds a **conservative policy-specific host preflight**: it reports safely observed optional runtime capabilities, but keeps the overall verdict `indeterminate` while mandatory launch prerequisites remain unprobed rather than falsely claiming launch compatibility.",
    "Milestone 24A added deterministic human and JSON **static policy-authority manifests** that validate policy without launching or probing runtime support. Milestone 24B added a **conservative policy-specific host preflight**: it reports safely observed optional runtime capabilities, but keeps the overall verdict `indeterminate` while mandatory launch prerequisites remain unprobed rather than falsely claiming launch compatibility. The current Milestone 25A verified candidate adds a **runtime enforcement receipt** to successful `RunReport`/`run-json` results, positively recording launcher-owned kernel setup stages that actually completed during that invocation.",
    "README milestone summary",
)
replace_one(
    "README.md",
    "The CLI intentionally separates four evidence levels rather than treating them as interchangeable:",
    "The CLI intentionally separates five evidence levels rather than treating them as interchangeable:",
    "README evidence count",
)
replace_one(
    "README.md",
    "- `run` / `run-json` remain the executable runtime evidence: only an actual successful launch demonstrates that all mandatory setup and enforcement mechanisms worked for that invocation.\n",
    "- `run` / `run-json` remain the executable runtime evidence. Milestone 25A adds an enforcement receipt to `RunReport` and `run-json`: each `true` bit is published only after that launcher-owned kernel setup stage succeeds. A `false` bit means only that the stage was not positively observed before termination; it is not proof that the mechanism is unsupported or absent. The receipt deliberately stops at seccomp and does not claim successful `execveat` or continued target lifetime.\n",
    "README runtime evidence layer",
)
replace_one(
    "README.md",
    "12. **Reporting** `run_report()` / `run_report_with_cancel()` return `Exited(code)`, `Signaled(signal)`, `TimedOut`, `Cancelled`, or `OutputLimitExceeded`, plus captured stdout, `reaped_descendants`, and `ProcessTreeUsage { user_cpu_micros, system_cpu_micros, max_child_rss_kib }`. The compatibility status-only APIs return the same `ChildOutcome`. `run-json` emits `output_limit_exceeded` for the new outcome; the CLI maps it to status 122 while preserving `TimedOut` 124 and `Cancelled` 130.",
    "12. **Reporting** `run_report()` / `run_report_with_cancel()` return `Exited(code)`, `Signaled(signal)`, `TimedOut`, `Cancelled`, or `OutputLimitExceeded`, plus captured stdout, `reaped_descendants`, `ProcessTreeUsage { user_cpu_micros, system_cpu_micros, max_child_rss_kib }`, and `EnforcementReceipt`. The receipt positively records completed base namespace, optional time-offset, hostname, private-mount, read-only-root, chroot, FD-sanitization, rlimit, capability-reduction, `no_new_privs`, optional Landlock, and seccomp stages. Impossible receipt progressions fail closed. `run-json` serializes the same deterministic receipt while the compatibility status-only APIs continue returning only `ChildOutcome`; output-limit status remains 122, `TimedOut` 124, and `Cancelled` 130.",
    "README runtime reporting",
)

# Threat model: make 24B integrated and add only post-attempt facts actually observed by 25A.
replace_one(
    "THREAT_MODEL.md",
    "# Milestones 1–23A + Milestone 24B candidate threat model",
    "# Milestones 1–24B + Milestone 25A candidate threat model",
    "threat title",
)
replace_one(
    "THREAT_MODEL.md",
    "Milestone 24A adds a static declared-authority manifest, and the current Milestone 24B verified candidate adds conservative policy-specific host preflight that remains explicitly incomplete until mandatory launch prerequisites are positively established.",
    "Milestone 24A added a static declared-authority manifest, and Milestone 24B added conservative policy-specific host preflight that remains explicitly incomplete until mandatory launch prerequisites are positively established. The current Milestone 25A verified candidate adds a post-attempt runtime enforcement receipt whose positive fields are published only after the corresponding launcher-owned kernel setup operation succeeds.",
    "threat purpose 25A",
)
replace_one(
    "THREAT_MODEL.md",
    "- **Conservative policy-specific host preflight:** `preflight` / `preflight-json` validate policy and compare only independently safe host observations such as target build support, Landlock ABI, pidfd, timerfd, and eventfd against requested features. They do not launch or materialize sandbox state. The report explicitly marks the mandatory namespace/filesystem/descriptor launch core `unprobed`; therefore current production preflight can report known incompatibility or indeterminate evidence but cannot claim full satisfaction. Static `manifest` output, partial preflight, and actual runtime enforcement are separate evidence classes.\n",
    "- **Conservative policy-specific host preflight:** `preflight` / `preflight-json` validate policy and compare only independently safe host observations such as target build support, Landlock ABI, pidfd, timerfd, and eventfd against requested features. They do not launch or materialize sandbox state. The report explicitly marks the mandatory namespace/filesystem/descriptor launch core `unprobed`; therefore current production preflight can report known incompatibility or indeterminate evidence but cannot claim full satisfaction. Static `manifest` output, partial preflight, and actual runtime enforcement are separate evidence classes.\n- **Runtime enforcement receipt:** an actual run publishes a launcher-owned bit only after the corresponding setup stage succeeds. The decoder rejects unknown bits and impossible predecessor orderings and cross-checks requested optional time-namespace/Landlock state. A false field is only absence of positive observation before termination, not negative capability evidence. The receipt deliberately makes no successful-`execveat` claim because launcher control may terminate after final setup but before the non-returning exec transition. `RunReport` exposes the structured receipt and `run-json` serializes the same fields.\n",
    "threat runtime receipt property",
)

# Roadmap: seal 24B and add one materially different post-attempt observability slice.
replace_one(
    "ROADMAP.md",
    "**Current verified candidate.** Adds non-destructive policy/host capability matching without claiming that partial probing proves the full sandbox launch path.",
    "**Status: complete on `main`.** Adds non-destructive policy/host capability matching without claiming that partial probing proves the full sandbox launch path.",
    "roadmap 24B status",
)
replace_one(
    "ROADMAP.md",
    "### Milestone 24 promotion rule\n\nAfter 24B integrates, seal the current policy-observability layer. Do not farm output aliases or relabel partial probes as conformance. A later preflight slice must add genuinely safe positive evidence for previously unprobed mandatory mechanisms; otherwise promote to a materially different executable authority/enforcement frontier.\n\n## Later frontiers\n",
    "### Milestone 24 promotion rule\n\n24A–24B are sealed on `main`. Do not farm output aliases or relabel partial probes as conformance. A later preflight slice must add genuinely safe positive evidence for previously unprobed mandatory mechanisms. Milestone 25A is deliberately different: it reports kernel stages positively observed during an actual run rather than predicting launch compatibility.\n\n## Milestone 25 — runtime enforcement evidence\n\n### Slice 25A — post-attempt enforcement receipt\n\n**Current verified candidate.** Adds structured positive evidence for launcher-owned setup stages that actually completed during a sandbox invocation.\n\nAcceptance evidence is executable:\n\n- `RunReport` gains an `EnforcementReceipt` covering base namespaces, optional time-namespace offsets, hostname, private mount propagation, read-only root, chroot, FD sanitization, all configured rlimits, capability reduction, `no_new_privs`, optional Landlock restriction, and seccomp installation;\n- each bit is published only after the corresponding kernel/setup stage returns success through the existing shared launch-state channel; unknown bits, impossible predecessor progressions, unrequested optional bits, and missing requested optional predecessors fail closed during receipt decoding;\n- early launcher-owned termination may therefore yield a valid partial receipt. A false field means only `not positively observed before termination`, not `unsupported`, `disabled`, or `failed`;\n- the receipt intentionally does not record successful `execveat`: a deadline/cancellation/output-limit control path can win after seccomp is installed but before the non-returning exec syscall, so claiming exec success from setup progress would be unsound;\n- time-namespace and Landlock integration tests require their respective positive receipt bits after successful real runs, while receipt-decoder unit tests reject corrupted/impossible progressions;\n- `run-json` serializes the complete receipt in deterministic field order, and the real example-policy CLI regression requires the expected true/false stage set rather than merely checking JSON shape;\n- Milestone 24B preflight remains distinct and non-destructive, while 25A is post-attempt evidence from the actual run path; stable rustfmt/Clippy/full tests and the full Rust 1.74 suite are green on the exact candidate.\n\nBoundary: 25A is positive setup-stage telemetry, not a cryptographic attestation, kernel-state snapshot, complete conformance proof, successful-exec receipt, or guarantee that a stage remains effective after its observation point. It does not turn false bits into negative capability claims.\n\n### Milestone 25 promotion rule\n\nAfter 25A integrates, seal this receipt schema at the current stage granularity. Do not farm aliases, duplicate per-syscall bits, or relabel the receipt as attestation/conformance. Promote to a materially different executable authority/enforcement frontier unless a new receipt field corresponds to a genuinely new kernel boundary.\n\n## Later frontiers\n",
    "roadmap 25A section",
)
