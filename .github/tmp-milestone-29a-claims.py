from pathlib import Path


def replace_one(path: str, old: str, new: str, label: str) -> None:
    p = Path(path)
    text = p.read_text()
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{label}: expected exactly one match, got {count}")
    p.write_text(text.replace(old, new, 1))


def insert_before(path: str, marker: str, block: str, label: str) -> None:
    replace_one(path, marker, block + marker, label)


# README: seal integrated 24E and describe only executable 29A behavior.
replace_one(
    "README.md",
    "The current Milestone 24E verified candidate adds a **policy-specific isolated time-namespace probe**: when offsets are requested, a throwaway helper mirrors production user/time-namespace setup, installs the exact declared MONOTONIC/BOOTTIME offsets, and verifies a descendant observes those offsets without touching the configured root or executing the target.",
    "Milestone 24E added a **policy-specific isolated time-namespace probe**: when offsets are requested, a throwaway helper mirrors production user/time-namespace setup, installs the exact declared MONOTONIC/BOOTTIME offsets, and verifies a descendant observes those offsets without touching the configured root or executing the target.",
    "README 24E status",
)
replace_one(
    "README.md",
    "Milestone 27C added a **conservative static policy-authority delta checker**, and Milestone 27D added a **runtime receipt-completeness gate** that checks only receipt-modeled enforcement evidence from a real run without claiming full-policy attestation or successful exec. The project is **not** a penetration-testing toolkit, malware framework, container runtime, or production multi-tenant isolation boundary.",
    "Milestone 27C added a **conservative static policy-authority delta checker**, and Milestone 27D added a **runtime receipt-completeness gate** that checks only receipt-modeled enforcement evidence from a real run without claiming full-policy attestation or successful exec. The current Milestone 29A verified candidate adds **forbidden masked seccomp argument patterns**: a matching raw 64-bit bit pattern is denied with `EPERM`, while non-matching values continue through the existing conjunctive masked-equality/range checks. The project is **not** a penetration-testing toolkit, malware framework, container runtime, or production multi-tenant isolation boundary.",
    "README milestone summary",
)
replace_one(
    "README.md",
    "Optional `seccomp.arg.<syscall>.<0..5>` masked-equality rules and `seccomp.range.<syscall>.<0..5>` inclusive unsigned range rules further narrow already-allowed syscalls; when both families constrain the same argument, every declared predicate must pass before `ALLOW`.",
    "Optional `seccomp.arg.<syscall>.<0..5>` masked-equality rules, `seccomp.range.<syscall>.<0..5>` inclusive unsigned range rules, and `seccomp.deny_mask.<syscall>.<0..5>` forbidden masked patterns further narrow already-allowed syscalls. Positive equality/range constraints must pass, and any matching forbidden pattern returns seccomp `EPERM` before `ALLOW`.",
    "README target seccomp semantics",
)
readme_test_marker = "- masked seccomp argument-rule parser/validator regressions plus a raw `lseek` oracle"
readme_text = Path("README.md").read_text()
if readme_test_marker in readme_text:
    readme_text = readme_text.replace(
        readme_test_marker,
        "- forbidden-mask seccomp parser/validator regressions plus a raw `mmap` oracle where `PROT_READ|PROT_WRITE` and `PROT_READ|PROT_EXEC` succeed but `PROT_READ|PROT_WRITE|PROT_EXEC` receives exact `EPERM`, proving the denied bit pattern narrows rather than replaces the syscall allowlist;\n" + readme_test_marker,
        1,
    )
    Path("README.md").write_text(readme_text)

# Threat model: keep numeric-only boundary explicit.
replace_one(
    "THREAT_MODEL.md",
    "The current Milestone 24E verified candidate independently probes requested descendant time-namespace offsets in a throwaway user/time namespace and keeps that positive evidence distinct from the still-unprobed complete mandatory launch core.",
    "Milestone 24E independently probes requested descendant time-namespace offsets in a throwaway user/time namespace and keeps that positive evidence distinct from the still-unprobed complete mandatory launch core.",
    "threat 24E status",
)
replace_one(
    "THREAT_MODEL.md",
    "Milestone 27C added conservative static policy-authority delta classification, while Milestone 27D added a real-run receipt-completeness gate bounded to the existing receipt model. Every claimed property must correspond to a kernel mechanism and executable evidence.",
    "Milestone 27C added conservative static policy-authority delta classification, while Milestone 27D added a real-run receipt-completeness gate bounded to the existing receipt model. The current Milestone 29A verified candidate adds forbidden masked numeric seccomp predicates that deny a selected bit pattern without widening the underlying syscall allowlist. Every claimed property must correspond to a kernel mechanism and executable evidence.",
    "threat milestone summary",
)
replace_one(
    "THREAT_MODEL.md",
    "target syscall numbers plus selected numeric syscall arguments narrowed by masked equality and/or inclusive unsigned ranges,",
    "target syscall numbers plus selected numeric syscall arguments narrowed by masked equality, inclusive unsigned ranges, and/or forbidden masked patterns,",
    "threat protected seccomp boundary",
)
replace_one(
    "THREAT_MODEL.md",
    "seccomp predicates beyond masked equality and one inclusive unsigned range on raw numeric syscall argument values, including pointer-target/string inspection, signed-range interpretation, cross-argument relational matching, arbitrary Boolean predicate composition, or pathname-content policy;",
    "seccomp predicates beyond masked equality, inclusive unsigned ranges, and forbidden masked patterns on raw numeric syscall argument values, including pointer-target/string inspection, signed-range interpretation, cross-argument relational matching, arbitrary Boolean predicate composition, or pathname-content policy;",
    "threat seccomp non-goal",
)
replace_one(
    "THREAT_MODEL.md",
    "- masked seccomp argument-rule parser/validator regressions plus a raw `lseek` oracle whose allowed offset matches the declared low/high 64-bit mask while separate low-bit and high-32-bit mismatches both return `EPERM`;\n",
    "- masked seccomp argument-rule parser/validator regressions plus a raw `lseek` oracle whose allowed offset matches the declared low/high 64-bit mask while separate low-bit and high-32-bit mismatches both return `EPERM`;\n- forbidden-mask seccomp parser/validator regressions plus a raw `mmap` oracle that permits RW and RX anonymous mappings but requires exact `EPERM` for W+X, demonstrating negative bit-pattern narrowing without replacing the syscall-number allowlist;\n",
    "threat forbidden-mask evidence",
)
replace_one(
    "THREAT_MODEL.md",
    "Milestones through 26A are complete on `main`; the bounded persistent-volume, namespace/network brokers, Landlock pathname/network/IPC/device envelopes, richer seccomp predicates, resource observability, observed-output enforcement, descendant time namespace, static/preflight observability, runtime enforcement receipt, and private-PID-procfs phases are sealed. Milestone 27C static authority-delta and 27D runtime receipt-gate tooling are also integrated and remain deliberately narrower than runtime attestation. The current 24C candidate adds positive isolated primitive evidence while keeping complete launch preflight indeterminate; after it integrates, do not farm probe-stage aliases. Milestone 4A cgroup-v2 aggregate process accounting remains blocked by missing unprivileged delegation; supplementary-group isolation also remains blocked on a viable mapping architecture. Future promotion must target a materially different executable authority/enforcement frontier or safely close a genuinely unprobed prerequisite without overstating evidence.",
    "Milestones through 27D are integrated on `main`, including the complete 24A–24E static/preflight evidence sequence; complete launch preflight intentionally remains indeterminate because the mandatory launch core is still unprobed as a whole. The current Milestone 29A candidate adds a materially different negative seccomp predicate rather than farming range endpoint aliases. Milestone 4A cgroup-v2 aggregate process accounting remains blocked by missing unprivileged delegation; supplementary-group isolation also remains blocked on a viable mapping architecture. Future promotion must target a materially different executable authority/enforcement frontier or safely close a genuinely unprobed prerequisite without overstating evidence.",
    "threat phase promotion sync",
)

# ROADMAP: close 24E and record 29A as the verified candidate.
replace_one(
    "ROADMAP.md",
    "**Current verified candidate.** Closes the separately requested time-namespace prerequisite without converting preflight into target execution or a privileged launch simulation.",
    "**Status: complete on `main`.** Closes the separately requested time-namespace prerequisite without converting preflight into target execution or a privileged launch simulation.",
    "roadmap 24E status",
)
replace_one(
    "ROADMAP.md",
    "24A–24D are sealed on `main`; 24E is the current integration candidate. After 24E integrates, do not farm clock IDs, offset values, path aliases, errno cases, or duplicate isolated probes.",
    "24A–24E are sealed on `main`. Do not farm clock IDs, offset values, path aliases, errno cases, or duplicate isolated probes.",
    "roadmap 24 promotion",
)
roadmap_marker = "## Later frontiers\n"
roadmap_block = '''## Milestone 29 — negative seccomp argument predicates

### Slice 29A — forbidden masked bit patterns

**Current verified candidate.** Adds a negative raw-argument predicate that cannot be expressed by the existing single conjunctive masked-equality/range rule families without enumerating allowed alternatives.

Acceptance evidence is executable:

- policy accepts `seccomp.deny_mask.<syscall>.<0..5> = <mask>:<value>` only for a syscall already present in `seccomp.allow`; zero masks, values with bits outside the mask, invalid argument indices, launcher-critical syscalls, duplicates, and aggregate predicate counts above the existing ceiling fail closed;
- Linux x86_64 cBPF evaluates the complete raw 64-bit selected argument and returns seccomp `EPERM` only when every masked bit matches the forbidden value; a non-match continues through the remaining conjunctive constraints and can reach `ALLOW`;
- a raw `mmap` oracle declares `mask=0x6,value=0x6` on protection argument 2, proves RW and RX anonymous mappings succeed, and requires exact `EPERM` for RWX;
- the static authority manifest emits forbidden masks deterministically, and the authority-delta checker classifies adding the restriction as `reduced` and removing it as `widened` rather than silently treating the new predicate as unchanged;
- all prior seccomp, sandbox, manifest, delta, preflight, receipt, and runtime regressions remain active; stable rustfmt/Clippy/full tests and the full Rust 1.74 suite are green on the exact implementation head.

Boundary: 29A is one additional numeric predicate family, not pointer/string inspection, signed comparison, cross-argument relations, a general Boolean expression language, or pathname/socket-address content filtering. Rules still only narrow syscalls already named by `seccomp.allow`.

### Milestone 29 promotion rule

After 29A integrates, do not farm inverse-equality aliases, extra masks, W^X-specific names, or Boolean spelling variants. A later seccomp slice must add materially different executable semantics with raw positive/negative evidence; otherwise promote to another independent authority/enforcement frontier.

'''
insert_before("ROADMAP.md", roadmap_marker, roadmap_block, "roadmap 29A section")
