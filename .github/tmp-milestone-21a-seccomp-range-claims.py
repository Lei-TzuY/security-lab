from pathlib import Path


def replace_one(path: str, old: str, new: str, label: str) -> None:
    p = Path(path)
    text = p.read_text()
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{label}: expected exactly one match, got {count}")
    p.write_text(text.replace(old, new, 1))


# README: synchronize the sealed 20A state and describe only verified 21A behavior.
replace_one(
    "README.md",
    "Milestone 19A additionally **binds that broker to one exact peer UID/GID pair** using Linux `SO_PEERCRED` before the socket is admitted to target authority. The project is **not** a penetration-testing toolkit, malware framework, container runtime, or production multi-tenant isolation boundary.",
    "Milestone 19A additionally **binds that broker to one exact peer UID/GID pair** using Linux `SO_PEERCRED` before the socket is admitted to target authority. Milestone 20A added **bounded Landlock pathname-topology mutation** only on directories that already hold regular-file mutation authority. The current Milestone 21A verified candidate adds **inclusive unsigned full-64-bit seccomp argument ranges** that only narrow already-allowed syscalls and compose conjunctively with existing masked-equality rules. The project is **not** a penetration-testing toolkit, malware framework, container runtime, or production multi-tenant isolation boundary.",
    "README milestone summary",
)
replace_one(
    "README.md",
    "Optional `seccomp.arg.<syscall>.<0..5>` rules further narrow already-allowed syscalls with full 64-bit masked-equality checks.",
    "Optional `seccomp.arg.<syscall>.<0..5>` masked-equality rules and `seccomp.range.<syscall>.<0..5>` inclusive unsigned range rules further narrow already-allowed syscalls; when both families constrain the same argument, every declared predicate must pass before `ALLOW`.",
    "README target seccomp pipeline",
)
replace_one(
    "README.md",
    "- A `seccomp.arg.<syscall>.<index>` rule can only narrow a syscall already present in `seccomp.allow`. On Linux x86_64, each rule applies `(argument & mask) == value` to the full 64-bit numeric argument; a mismatch returns `EPERM`.\n",
    "- A `seccomp.arg.<syscall>.<index>` rule can only narrow a syscall already present in `seccomp.allow`. On Linux x86_64, each rule applies `(argument & mask) == value` to the full 64-bit numeric argument; a mismatch returns `EPERM`.\n- A `seccomp.range.<syscall>.<index>` rule likewise only narrows an already-allowed syscall and requires the raw unsigned 64-bit argument to lie within one inclusive `[minimum, maximum]` interval. High and low 32-bit words are compared explicitly; range rules compose conjunctively with masked-equality rules, including when both target the same argument.\n",
    "README range invariant",
)
replace_one(
    "README.md",
    "Optional syscall-argument rules use `seccomp.arg.<syscall>.<0..5> = <mask>:<value>`. Mask/value integers may be decimal or `0x` hexadecimal. The syscall must also appear in `seccomp.allow`, the mask must be non-zero, `value` may not set bits outside the mask, and the launcher-critical `execveat`, `exit`, and `exit_group` syscalls may not receive argument rules. At most 64 argument rules are accepted.",
    "Optional masked-equality syscall-argument rules use `seccomp.arg.<syscall>.<0..5> = <mask>:<value>`. Optional inclusive unsigned range rules use `seccomp.range.<syscall>.<0..5> = <minimum>:<maximum>`. All integers may be decimal or `0x` hexadecimal. Either rule family can only narrow a syscall already present in `seccomp.allow`; launcher-critical `execveat`, `exit`, and `exit_group` may not be constrained. A mask must be non-zero and its value may not set bits outside the mask. A range requires `minimum <= maximum` and may not span the entire `0..=u64::MAX` domain because that would narrow nothing. Masked and range predicates compose conjunctively, and their combined count is limited to 64.",
    "README policy format",
)
replace_one(
    "README.md",
    "- a raw target exercises one `lseek` syscall under `seccomp.arg.lseek.1 = 0xffffffff0000000f:0x0000000100000008`: offset `0x0000000112345678` succeeds, while a low masked-bit mismatch (`...79`) and a high-32-bit mismatch (`0x00000002...78`) each receive seccomp `EPERM`, proving both halves of the 64-bit argument are enforced;\n",
    "- a raw target exercises one `lseek` syscall under `seccomp.arg.lseek.1 = 0xffffffff0000000f:0x0000000100000008`: offset `0x0000000112345678` succeeds, while a low masked-bit mismatch (`...79`) and a high-32-bit mismatch (`0x00000002...78`) each receive seccomp `EPERM`, proving both halves of the 64-bit argument are enforced;\n- a separate raw `lseek` oracle applies `seccomp.range.lseek.1 = 0x00000000fffffff0:0x0000000100000010` together with a same-argument even-value mask. The exact lower bound, a value across the 32-bit word boundary, and the exact upper bound succeed; an in-range odd value is denied by the mask, while even values below/above the interval and a high-32-bit outlier are denied by the range. This proves unsigned full-64-bit inclusive comparison and conjunctive composition rather than low-word-only checking;\n",
    "README range evidence",
)
replace_one(
    "README.md",
    "- seccomp argument rules currently support masked equality over the six numeric 64-bit syscall argument slots only. Classic seccomp does not dereference pointers, so this is not pathname/string-content filtering, a pointer-target integrity guarantee, range/relational matching, or a TOCTOU solution;",
    "- seccomp argument rules currently support masked equality plus one inclusive unsigned range over the six raw numeric 64-bit syscall argument slots. Classic seccomp does not dereference pointers, so this is not pathname/string-content filtering, signed-range semantics, cross-argument relational matching, a pointer-target integrity guarantee, or a TOCTOU solution;",
    "README seccomp limitation",
)

# Threat model: distinguish completed 20A from verified 21A and narrow claims precisely.
replace_one(
    "THREAT_MODEL.md",
    "# Milestones 1–20A threat model",
    "# Milestones 1–21A threat model",
    "threat title",
)
replace_one(
    "THREAT_MODEL.md",
    "Milestone 19A optionally narrows that authority by requiring the connected peer's Linux `SO_PEERCRED` UID/GID to match one declared pair before target launch. The current Milestone 20A verified candidate adds an explicit Landlock pathname-topology mutation augmentation for directories that already have the regular-file mutation envelope. Every claimed property must correspond to a kernel mechanism and executable evidence.",
    "Milestone 19A optionally narrows that authority by requiring the connected peer's Linux `SO_PEERCRED` UID/GID to match one declared pair before target launch. Milestone 20A added an explicit Landlock pathname-topology mutation augmentation for directories that already have the regular-file mutation envelope. The current Milestone 21A verified candidate adds inclusive unsigned full-64-bit seccomp argument ranges that compose with the existing masked-equality predicate family. Every claimed property must correspond to a kernel mechanism and executable evidence.",
    "threat purpose",
)
replace_one(
    "THREAT_MODEL.md",
    "target syscall numbers and selected numeric syscall arguments, selected resources",
    "target syscall numbers plus selected numeric syscall arguments narrowed by masked equality and/or inclusive unsigned ranges, selected resources",
    "threat protected boundary",
)
replace_one(
    "THREAT_MODEL.md",
    "- **Masked syscall-argument narrowing:** an argument rule applies only to a syscall already in `seccomp.allow`. Linux x86_64 cBPF evaluates the selected `seccomp_data.args[]` slot as two 32-bit words and requires the complete 64-bit `(argument & mask) == value` condition before returning `ALLOW`; a mismatch returns `EPERM`.",
    "- **Numeric syscall-argument narrowing:** masked-equality and inclusive unsigned range rules apply only to syscalls already in `seccomp.allow`. Linux x86_64 cBPF evaluates both 32-bit words of the selected 64-bit `seccomp_data.args[]` slot. Mask rules require `(argument & mask) == value`; range rules require `minimum <= argument <= maximum` as an unsigned 64-bit comparison. All predicates declared for the matched syscall must pass before `ALLOW`; any mismatch returns `EPERM`.",
    "threat argument property",
)
replace_one(
    "THREAT_MODEL.md",
    "Milestone 5A extends the existing syscall-number allowlist with optional `seccomp.arg.<syscall>.<0..5> = <mask>:<value>` rules. Rules only narrow already-allowed syscalls; they never introduce a syscall that is absent from `seccomp.allow`. Policy validation requires a non-zero mask, requires `value` to contain no bits outside that mask, rejects duplicate syscall/argument pairs, and forbids rules on launcher-critical `execveat`, `exit`, and `exit_group`.\n\nOn Linux x86_64 the classic-BPF compiler reads both 32-bit words of each selected 64-bit `seccomp_data.args[]` slot. A masked low-word mismatch or high-word mismatch returns `EPERM`; all declared argument rules for the matched syscall must pass before `ALLOW`. The executable oracle deliberately uses `lseek` argument 1 with mask `0xffffffff0000000f`, proving one matching offset succeeds while independent low-bit and high-32-bit mismatches are denied.\n\nThis mechanism compares numeric syscall arguments only. Classic seccomp cannot safely dereference a pathname, socket-address, or other pointer supplied by the target, so Milestone 5A does not claim pointed-to data inspection, pathname-content policy, range/relational predicates, or elimination of pointer-related TOCTOU hazards.",
    "Milestone 5A extends the existing syscall-number allowlist with optional `seccomp.arg.<syscall>.<0..5> = <mask>:<value>` masked-equality rules. Milestone 21A adds `seccomp.range.<syscall>.<0..5> = <minimum>:<maximum>` for one inclusive unsigned interval. Both families only narrow already-allowed syscalls; they never introduce a syscall absent from `seccomp.allow`. Policy validation retains the masked-rule constraints, requires range `minimum <= maximum`, rejects the unconstrained full `0..=u64::MAX` interval, rejects duplicate same-family syscall/argument entries, forbids both families on launcher-critical `execveat`, `exit`, and `exit_group`, and caps the combined predicate count at 64.\n\nOn Linux x86_64 the classic-BPF compiler reads both 32-bit words of each selected 64-bit `seccomp_data.args[]` slot. Existing masked rules require the complete `(argument & mask) == value` condition. Range rules first compare the unsigned high word and only compare the low word when the high word equals the corresponding bound, implementing inclusive `minimum <= argument <= maximum` without truncation. Masked and range checks are emitted sequentially before the syscall's `ALLOW`, so they compose conjunctively. The range oracle crosses the `0xffffffff`/`0x1_00000000` boundary and independently demonstrates exact endpoints, masked denial inside the interval, range denial outside it, and a high-32-bit outlier.\n\nThese mechanisms compare raw numeric syscall arguments only. Classic seccomp cannot safely dereference a pathname, socket address, or other pointer supplied by the target. Milestone 21A therefore does not claim pointed-to data inspection, pathname-content policy, signed-range interpretation, relations between different arguments, arbitrary Boolean predicate composition, or elimination of pointer-related TOCTOU hazards.",
    "threat seccomp semantics",
)
replace_one(
    "THREAT_MODEL.md",
    "- seccomp predicates beyond masked equality on numeric syscall argument values, including pointer-target/string inspection, range/relational matching, or pathname-content policy;",
    "- seccomp predicates beyond masked equality and one inclusive unsigned range on raw numeric syscall argument values, including pointer-target/string inspection, signed-range interpretation, cross-argument relational matching, arbitrary Boolean predicate composition, or pathname-content policy;",
    "threat seccomp non-goal",
)
replace_one(
    "THREAT_MODEL.md",
    "- masked seccomp argument-rule parser/validator regressions plus a raw `lseek` oracle whose allowed offset matches the declared low/high 64-bit mask while separate low-bit and high-32-bit mismatches both return `EPERM`;",
    "- masked seccomp argument-rule parser/validator regressions plus a raw `lseek` oracle whose allowed offset matches the declared low/high 64-bit mask while separate low-bit and high-32-bit mismatches both return `EPERM`;\n- seccomp range parser/validator regressions plus a raw `lseek` oracle spanning a 32-bit-word boundary: exact inclusive endpoints and an interior cross-boundary even value succeed, an interior odd value is denied by a same-argument mask, and below/above/high-word range mismatches return `EPERM`;",
    "threat range evidence",
)

# Roadmap: seal 20A and promote 21A as a materially new predicate model.
replace_one(
    "ROADMAP.md",
    "**Current verified candidate.** Extends the existing 10B regular-file mutation envelope with an explicit topology authority bitset rather than implicitly widening every writable directory.",
    "**Status: complete on `main`.** Extends the existing 10B regular-file mutation envelope with an explicit topology authority bitset rather than implicitly widening every writable directory.",
    "roadmap 20A status",
)
replace_one(
    "ROADMAP.md",
    "## Later frontiers\n\nSupplementary-group isolation with a viable mapping architecture, broader/generalized persistent-volume policy, routed/broader network authority beyond the bounded IPv4 brokers, generalized host-local IPC authority beyond the exact-path/peer-credential broker, and delegated aggregate cgroup accounting remain separate evidence-backed frontiers. Do not add configuration-only names without executable kernel behavior and integration evidence.",
    "## Milestone 21 — richer numeric syscall semantics\n\n### Slice 21A — inclusive unsigned 64-bit seccomp argument ranges\n\n**Current verified candidate.** Adds a materially different numeric predicate model beyond 5A masked equality without widening the syscall allowlist.\n\nAcceptance evidence is executable:\n\n- policy accepts `seccomp.range.<syscall>.<0..5> = <minimum>:<maximum>` using decimal or `0x` literals; a range only applies to an already-allowed syscall, launcher-critical `execveat`/`exit`/`exit_group` remain unconstrainable, argument indexes stay 0–5, `minimum` may not exceed `maximum`, and the full unconstrained `0..=u64::MAX` interval is rejected;\n- masked-equality and range rules retain separate per-syscall/per-argument maps but share the existing aggregate 64-predicate ceiling; when both families constrain the same argument, they compose conjunctively rather than one overriding the other;\n- Linux x86_64 cBPF compares each bound as unsigned high/low 32-bit words and performs the low-word comparison only when the high word equals that bound, implementing full-64-bit inclusive comparison before the syscall's final `ALLOW`;\n- the raw `lseek` oracle uses range `0x00000000fffffff0..=0x0000000100000010` plus an even-value mask on the same argument: exact lower/interior-cross-boundary/upper values succeed, an in-range odd value receives `EPERM` from the mask, and even below/above plus a high-32-bit outlier receive `EPERM` from the range;\n- the existing 5A masked-value oracle, Milestone 17A resource-usage mode, all Milestones 1–20A regressions, stable format/Clippy/full tests, and the full Rust 1.74 suite remain green.\n\nBoundary: 21A compares one raw syscall argument against an unsigned inclusive interval. It does not provide signed ranges, relations between arguments, pointed-to/string/path inspection, arbitrary Boolean expressions, or pointer-target TOCTOU protection.\n\n### Milestone 21 promotion rule\n\nAfter 21A integrates, seal this bounded numeric-range slice. Do not farm `<`, `<=`, `>`, `>=`, endpoint aliases, or more fixture values around the same cBPF comparison mechanism. A later seccomp slice must introduce materially different executable semantics; otherwise promote to another subsystem frontier such as routed/broader networking only when explicit topology/endpoint evidence is available.\n\n## Later frontiers\n\nSupplementary-group isolation with a viable mapping architecture, broader/generalized persistent-volume policy, routed/broader network authority beyond the bounded IPv4 brokers, generalized host-local IPC authority beyond the exact-path/peer-credential broker, and delegated aggregate cgroup accounting remain separate evidence-backed frontiers. Do not add configuration-only names without executable kernel behavior and integration evidence.",
    "roadmap 21A section",
)
