from pathlib import Path


def replace_one(path: str, old: str, new: str, label: str) -> None:
    p = Path(path)
    text = p.read_text()
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{label}: expected exactly one match, got {count}")
    p.write_text(text.replace(old, new, 1))


replace_one(
    "README.md",
    "The current Milestone 4D candidate adds an **owned UTS identity boundary**: policy supplies a validated sandbox hostname, the trusted launcher installs it in a new UTS namespace, and the host hostname remains unchanged.",
    "Milestone 4D added an **owned UTS identity boundary** with a validated launcher-installed sandbox hostname. The current Milestone 5A candidate adds **masked seccomp syscall-argument filtering**: policy may narrow an already-allowed syscall by numeric 64-bit argument values, and the x86_64 cBPF program enforces those constraints before allowing the call.",
    "README opening milestone",
)
replace_one(
    "README.md",
    "9. **Target enforcement** the direct target alone applies explicit stdio, rlimits, capability reduction, `no_new_privs`, default-deny seccomp, and pinned `execveat`. Launcher namespace/deadline operations are not silently added to the target syscall allowlist. A policy may explicitly grant target `socket`/`connect`, but those syscalls execute inside the isolated network namespace.",
    "9. **Target enforcement** the direct target alone applies explicit stdio, rlimits, capability reduction, `no_new_privs`, default-deny seccomp, and pinned `execveat`. Optional `seccomp.arg.<syscall>.<0..5>` rules further narrow already-allowed syscalls with full 64-bit masked-equality checks. Launcher namespace/deadline operations are not silently added to the target syscall allowlist. A policy may explicitly grant target `socket`/`connect`, but those syscalls execute inside the isolated network namespace.",
    "README target enforcement",
)
replace_one(
    "README.md",
    "- Target socket authority remains explicit at the syscall layer: `socket` and `connect` are available only when the policy names them. Network namespace creation is launcher management and does not itself widen target seccomp.\n",
    "- Target socket authority remains explicit at the syscall layer: `socket` and `connect` are available only when the policy names them. Network namespace creation is launcher management and does not itself widen target seccomp.\n- A `seccomp.arg.<syscall>.<index>` rule can only narrow a syscall already present in `seccomp.allow`. On Linux x86_64, each rule applies `(argument & mask) == value` to the full 64-bit numeric argument; a mismatch returns `EPERM`.\n",
    "README argument invariant",
)
replace_one(
    "README.md",
    "`identity.hostname` is required. It must contain 1–63 ASCII bytes using letters, digits, `-`, or `.`, with an alphanumeric first and last byte. The launcher installs this value as the sandbox UTS nodename before the untrusted target starts.\n\n`limit.wall_clock_milliseconds` is optional.",
    "`identity.hostname` is required. It must contain 1–63 ASCII bytes using letters, digits, `-`, or `.`, with an alphanumeric first and last byte. The launcher installs this value as the sandbox UTS nodename before the untrusted target starts.\n\nOptional syscall-argument rules use `seccomp.arg.<syscall>.<0..5> = <mask>:<value>`. Mask/value integers may be decimal or `0x` hexadecimal. The syscall must also appear in `seccomp.allow`, the mask must be non-zero, `value` may not set bits outside the mask, and the launcher-critical `execveat`, `exit`, and `exit_group` syscalls may not receive argument rules. At most 64 argument rules are accepted.\n\n`limit.wall_clock_milliseconds` is optional.",
    "README policy format",
)
replace_one(
    "README.md",
    "- required hostname parsing rejects missing, duplicate, empty, oversized, underscore-containing, and leading/trailing punctuation values; a raw target explicitly granted `uname` observes the exact policy hostname while the trusted parent proves `/proc/sys/kernel/hostname` is byte-for-byte unchanged before and after sandbox execution;\n",
    "- required hostname parsing rejects missing, duplicate, empty, oversized, underscore-containing, and leading/trailing punctuation values; a raw target explicitly granted `uname` observes the exact policy hostname while the trusted parent proves `/proc/sys/kernel/hostname` is byte-for-byte unchanged before and after sandbox execution;\n- a raw target exercises one `lseek` syscall under `seccomp.arg.lseek.1 = 0xffffffff0000000f:0x0000000100000008`: offset `0x0000000112345678` succeeds, while a low masked-bit mismatch (`...79`) and a high-32-bit mismatch (`0x00000002...78`) each receive seccomp `EPERM`, proving both halves of the 64-bit argument are enforced;\n",
    "README test evidence",
)
replace_one(
    "README.md",
    "- there is no device namespace, syscall argument filtering, persistent data-volume policy, or configured network endpoint policy;\n",
    "- seccomp argument rules currently support masked equality over the six numeric 64-bit syscall argument slots only. Classic seccomp does not dereference pointers, so this is not pathname/string-content filtering, a pointer-target integrity guarantee, range/relational matching, or a TOCTOU solution;\n- there is no device namespace, persistent data-volume policy, or configured network endpoint policy;\n",
    "README seccomp limitations",
)

replace_one(
    "THREAT_MODEL.md",
    "# Milestones 1–4D threat model",
    "# Milestones 1–5A threat model",
    "threat model title",
)
replace_one(
    "THREAT_MODEL.md",
    "The current Milestone 4D candidate adds launcher-owned UTS nodename identity.",
    "Milestone 4D added launcher-owned UTS nodename identity. The current Milestone 5A candidate adds masked numeric syscall-argument constraints to the default-deny seccomp boundary.",
    "threat purpose milestone",
)
replace_one(
    "THREAT_MODEL.md",
    "capabilities, target syscalls, selected resources, environment, cwd, inherited descriptors",
    "capabilities, target syscall numbers and selected numeric syscall arguments, selected resources, environment, cwd, inherited descriptors",
    "threat protected boundary",
)
replace_one(
    "THREAT_MODEL.md",
    "- **No target-policy widening:** namespace management, pidfd/timerfd/poll, mounts, capture/remapping, and teardown execute in trusted launcher processes outside target seccomp. `socket` and `connect` are target syscalls only when the policy explicitly names them.\n",
    "- **No target-policy widening:** namespace management, pidfd/timerfd/poll, mounts, capture/remapping, and teardown execute in trusted launcher processes outside target seccomp. `socket` and `connect` are target syscalls only when the policy explicitly names them.\n- **Masked syscall-argument narrowing:** an argument rule applies only to a syscall already in `seccomp.allow`. Linux x86_64 cBPF evaluates the selected `seccomp_data.args[]` slot as two 32-bit words and requires the complete 64-bit `(argument & mask) == value` condition before returning `ALLOW`; a mismatch returns `EPERM`.\n",
    "threat seccomp property",
)
replace_one(
    "THREAT_MODEL.md",
    "## Deadline and lifecycle orchestration\n",
    "## Seccomp argument semantics\n\nMilestone 5A extends the existing syscall-number allowlist with optional `seccomp.arg.<syscall>.<0..5> = <mask>:<value>` rules. Rules only narrow already-allowed syscalls; they never introduce a syscall that is absent from `seccomp.allow`. Policy validation requires a non-zero mask, requires `value` to contain no bits outside that mask, rejects duplicate syscall/argument pairs, and forbids rules on launcher-critical `execveat`, `exit`, and `exit_group`.\n\nOn Linux x86_64 the classic-BPF compiler reads both 32-bit words of each selected 64-bit `seccomp_data.args[]` slot. A masked low-word mismatch or high-word mismatch returns `EPERM`; all declared argument rules for the matched syscall must pass before `ALLOW`. The executable oracle deliberately uses `lseek` argument 1 with mask `0xffffffff0000000f`, proving one matching offset succeeds while independent low-bit and high-32-bit mismatches are denied.\n\nThis mechanism compares numeric syscall arguments only. Classic seccomp cannot safely dereference a pathname, socket-address, or other pointer supplied by the target, so Milestone 5A does not claim pointed-to data inspection, pathname-content policy, range/relational predicates, or elimination of pointer-related TOCTOU hazards.\n\n## Deadline and lifecycle orchestration\n",
    "threat seccomp semantics section",
)
replace_one(
    "THREAT_MODEL.md",
    "- a device namespace, syscall argument filtering, persistent data-volume policy, or immutable/cryptographic root-subtree snapshot;\n",
    "- seccomp predicates beyond masked equality on numeric syscall argument values, including pointer-target/string inspection, range/relational matching, or pathname-content policy;\n- a device namespace, persistent data-volume policy, or immutable/cryptographic root-subtree snapshot;\n",
    "threat limitation",
)
replace_one(
    "THREAT_MODEL.md",
    "- required `identity.hostname` parser regressions plus a raw target explicitly granted `uname` observing the exact configured nodename while the trusted parent verifies the host hostname is unchanged before/after execution;\n",
    "- required `identity.hostname` parser regressions plus a raw target explicitly granted `uname` observing the exact configured nodename while the trusted parent verifies the host hostname is unchanged before/after execution;\n- masked seccomp argument-rule parser/validator regressions plus a raw `lseek` oracle whose allowed offset matches the declared low/high 64-bit mask while separate low-bit and high-32-bit mismatches both return `EPERM`;\n",
    "threat evidence",
)
replace_one(
    "THREAT_MODEL.md",
    "Milestones 4B and 4C are complete on `main` with network- and IPC-namespace separation. The current 4D frontier owns the sandbox UTS nodename through required policy, trusted `sethostname`, raw `uname` evidence, and host-identity non-mutation evidence. After 4D integrates, do not farm hostname syntax aliases or domainname variants. The next promotion should target a materially different remaining boundary, with supplementary-group isolation and seccomp syscall-argument filtering both requiring architecture review before implementation.",
    "Milestones 4B–4D are complete on `main`, including network/IPC namespace separation and launcher-owned UTS nodename identity. The current Milestone 5A frontier increases seccomp precision from syscall-number allowlisting to evidence-backed masked equality on full 64-bit numeric arguments. After 5A integrates, do not farm copied predicates across more syscalls. Supplementary-group clearing remains a separate architecture problem under the current unprivileged `setgroups=deny`/`gid_map` flow; other promotions should introduce a materially different object-authority, controlled-connectivity, persistence, or lifecycle boundary.",
    "threat phase promotion",
)

replace_one(
    "ROADMAP.md",
    "**Current verified candidate.** Make sandbox nodename identity explicit and launcher-owned rather than inheriting the host hostname into an otherwise isolated environment.",
    "**Status: complete on `main`.** Makes sandbox nodename identity explicit and launcher-owned rather than inheriting the host hostname into an otherwise isolated environment.",
    "roadmap 4D status",
)
replace_one(
    "ROADMAP.md",
    "### Milestone 4 promotion rule\n\nAfter 4D integrates, do not farm hostname aliases, punctuation variants, or domainname copies. Return to 4A only when real unprivileged cgroup-v2 delegation becomes available. Otherwise select a materially different executable boundary after architecture audit; high-value candidates include enforcing/observing an empty supplementary-group set or introducing narrowly-scoped seccomp syscall-argument filtering with deterministic allow/deny evidence.\n\n## Later frontiers\n\nExternal asynchronous cancellation, selected-handle passing, syscall-argument filtering, supplementary-group isolation, broader persistent-volume policy, and controlled networking remain separate evidence-backed frontiers. Do not add configuration-only names without executable kernel behavior and integration evidence.",
    "### Milestone 4 promotion rule\n\nMilestone 4B–4D namespace/identity baselines are sealed on `main`; do not farm more loopback keys, SysV queue variants, or hostname syntax copies. Milestone 4A remains blocked until the runtime user receives a real delegated writable cgroup-v2 subtree.\n\n## Milestone 5 — syscall semantic precision\n\n### Slice 5A — masked seccomp syscall-argument filtering\n\n**Current verified candidate.** Extend default-deny seccomp from syscall-number allowlisting to optional masked equality over selected numeric syscall arguments without widening launcher management authority.\n\nAcceptance evidence is executable:\n\n- policy accepts `seccomp.arg.<syscall>.<0..5> = <mask>:<value>` using decimal or `0x` hexadecimal integers;\n- rules can only narrow syscalls already present in `seccomp.allow`, masks must be non-zero, values may not set bits outside the mask, duplicate syscall/argument rules are rejected, and no more than 64 rules are accepted;\n- `execveat`, `exit`, and `exit_group` cannot receive argument rules, preserving pinned target start and fail-closed post-filter termination;\n- the Linux x86_64 cBPF compiler checks both 32-bit words of the selected 64-bit `seccomp_data.args[]` slot and requires every declared rule for a matched syscall before returning `ALLOW`;\n- a raw `lseek` target under mask `0xffffffff0000000f` accepts offset `0x0000000112345678`, rejects a low masked-bit mismatch, and separately rejects a high-32-bit mismatch with seccomp `EPERM`;\n- all Milestones 1–4D regressions, stable format/Clippy/full tests, and the full Rust 1.74 suite remain green.\n\nBoundary: 5A is masked equality on numeric syscall argument values. Classic seccomp does not dereference target pointers, so this is not pathname/string-content inspection, range/relational policy, or a pointer TOCTOU solution.\n\n### Milestone 5 promotion rule\n\nAfter 5A integrates, do not farm identical argument masks across unrelated syscalls. Promote only when a new policy primitive or cross-layer integration is justified by a concrete authority boundary and executable evidence. Supplementary-group clearing requires a different user-namespace mapping architecture under the current nonprivileged `setgroups=deny` flow; 4A remains blocked on cgroup delegation.\n\n## Later frontiers\n\nExternal asynchronous cancellation, selected-handle passing, supplementary-group isolation with a viable mapping architecture, broader persistent-volume policy, and controlled networking remain separate evidence-backed frontiers. Do not add configuration-only names without executable kernel behavior and integration evidence.",
    "roadmap milestone 5",
)
