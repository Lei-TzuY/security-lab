from pathlib import Path


def replace_one(path: str, old: str, new: str, label: str) -> None:
    p = Path(path)
    text = p.read_text()
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{label}: expected exactly one match, got {count}")
    p.write_text(text.replace(old, new, 1))


def replace_between(path: str, start: str, end: str, replacement: str, label: str) -> None:
    p = Path(path)
    text = p.read_text()
    if text.count(start) != 1 or text.count(end) != 1:
        raise SystemExit(
            f"{label}: expected unique anchors, got start={text.count(start)} end={text.count(end)}"
        )
    begin = text.index(start)
    finish = text.index(end, begin)
    p.write_text(text[:begin] + replacement + text[finish:])


def insert_before(path: str, anchor: str, insertion: str, label: str) -> None:
    p = Path(path)
    text = p.read_text()
    count = text.count(anchor)
    if count != 1:
        raise SystemExit(f"{label}: expected exactly one anchor, got {count}")
    p.write_text(text.replace(anchor, insertion + anchor, 1))


# README: synchronize the current evidence stack and describe 24C without
# upgrading the conservative preflight verdict.
replace_between(
    "README.md",
    "Milestone 24A added deterministic human and JSON **static policy-authority manifests**",
    "The project is **not**",
    "Milestone 24A added deterministic human and JSON **static policy-authority manifests** that validate policy without launching or probing runtime support. Milestone 24B added a **conservative policy-specific host preflight** that refuses to infer full launch compatibility from partial evidence. The current Milestone 24C verified candidate adds an **isolated mandatory launch-primitive probe**: a throwaway helper exercises representative namespace, mount, descriptor, resource, capability, `no_new_privs`, and seccomp setup primitives without touching the configured policy root or executing the target, while the overall mandatory launch core deliberately remains `unprobed`. Milestone 25A added a **runtime enforcement receipt** to `RunReport`/`run-json`, positively recording launcher-owned kernel setup stages that actually completed during that invocation. Milestone 26A added an optional **private procfs for the sandbox PID namespace** while hardening launcher-owned PID 1 so the target cannot reopen PID1 control descriptors through `/proc/1/fd`. Milestone 27C added a **conservative static policy-authority delta checker**, and Milestone 27D added a **runtime receipt-completeness gate** that checks only receipt-modeled enforcement evidence from a real run without claiming full-policy attestation or successful exec. ",
    "README milestone summary",
)
replace_one(
    "README.md",
    "The CLI intentionally separates five evidence levels rather than treating them as interchangeable:",
    "The tooling intentionally separates static declaration, host/probe, runtime, and post-run evidence rather than treating them as interchangeable:",
    "README evidence heading",
)
replace_one(
    "README.md",
    "- `manifest` / `manifest-json` emit the deterministic declared-authority manifest from Milestone 24A. They remain static (`runtime_preflight=false`) and do not prove kernel support.\n",
    "- `manifest` / `manifest-json` emit the deterministic declared-authority manifest from Milestone 24A. They remain static (`runtime_preflight=false`) and do not prove kernel support.\n- `security-lab-authority-delta` compares two validated declarations conservatively and classifies modeled authority as unchanged, reduced, widened, or incomparable. It explicitly reports `kernel_effective_state=false` and `filesystem_alias_proof=false`; static non-widening is not runtime attestation.\n",
    "README authority delta evidence",
)
replace_one(
    "README.md",
    "- `preflight` / `preflight-json` match one validated policy against the safely probed host subset without launching or mutating sandbox runtime state. Known unavailable represented requirements produce `incompatible` and exit status 3. Unknown mandatory launch-core prerequisites, or another requested mechanism without a complete safe probe, produce `indeterminate` and exit status 4. The report states `launch_attempted=false` and `launch_preflight_complete=false`. The current implementation deliberately cannot emit `satisfied` from the real probe path because the mandatory namespace/filesystem/FD launch core is not independently proven.\n",
    "- `preflight` / `preflight-json` match one validated policy against safely obtained host evidence and may run a throwaway isolated helper that exercises representative mandatory namespace/mount/descriptor/resource/capability/`no_new_privs`/seccomp primitives. The helper creates only its own child namespaces and private mounts, never materializes or inspects the configured policy root, and never executes the target. Its staged result is reported separately from `mandatory_launch_core`, which intentionally remains `unprobed`; therefore the real preflight path still reports `indeterminate` / exit status 4 rather than treating primitive compatibility as complete launch compatibility. `launch_attempted=false` and `launch_preflight_complete=false` remain explicit. Known unavailable represented requirements still produce `incompatible` / exit status 3.\n",
    "README 24C preflight semantics",
)
replace_one(
    "README.md",
    "- `run` / `run-json` remain the executable runtime evidence. Milestone 25A adds an enforcement receipt to `RunReport` and `run-json`: each `true` bit is published only after that launcher-owned kernel setup stage succeeds. A `false` bit means only that the stage was not positively observed before termination; it is not proof that the mechanism is unsupported or absent. The receipt deliberately stops at seccomp and does not claim successful `execveat` or continued target lifetime.\n",
    "- `run` / `run-json` remain the executable runtime evidence. Milestone 25A adds an enforcement receipt to `RunReport` and `run-json`: each `true` bit is published only after that launcher-owned kernel setup stage succeeds. A `false` bit means only that the stage was not positively observed before termination; it is not proof that the mechanism is unsupported or absent. The receipt deliberately stops at seccomp and does not claim successful `execveat` or continued target lifetime.\n- `security-lab-runtime-receipt-gate` performs a real run and checks completeness/consistency only for enforcement stages modeled by that receipt. It explicitly reports `full_policy_attestation=false` and `exec_success_proof=false`; a green gate is not a cryptographic or full-kernel-state attestation.\n",
    "README runtime receipt gate evidence",
)

# ROADMAP: retain 24B as the non-destructive baseline, add the executable 24C
# primitive probe as the current candidate, and synchronize already-integrated
# 26A/27C/27D status that was intentionally deferred during parallel work.
replace_one(
    "ROADMAP.md",
    "- preflight never launches the target, creates sandbox namespaces, materializes the configured root, or mutates runtime filesystem state; machine and human reports explicitly carry `launch_attempted=false` and `launch_preflight_complete=false`;",
    "- Slice 24B itself never launched the target, created sandbox namespaces, materialized the configured root, or mutated runtime filesystem state; machine and human reports explicitly carried `launch_attempted=false` and `launch_preflight_complete=false`;",
    "ROADMAP 24B historical boundary",
)
replace_between(
    "ROADMAP.md",
    "### Milestone 24 promotion rule",
    "## Milestone 25 — runtime enforcement evidence",
    "### Slice 24C — isolated mandatory launch-primitive probe\n\n**Current verified candidate.** Adds positive compatibility evidence for a representative mandatory Linux setup core without relabeling that evidence as a complete launch preflight.\n\nAcceptance evidence is executable:\n\n- `preflight` / `preflight-json` fork a throwaway helper on Linux x86_64; the helper never receives the configured policy root, never executes the target, and confines its filesystem mutation to child-owned namespaces and a private tmpfs;\n- the staged helper exercises the production-relevant primitive classes for user/mount/PID/network/IPC/UTS namespace creation, `setgroups`/UID/GID mapping, UTS hostname setup, private mount propagation, `openat2`, `open_tree`, recursive read-only `mount_setattr`, `move_mount`, an `EROFS` write oracle, PID-namespace PID1 creation, `chroot`/`chdir`, `close_range(..., CLOEXEC)`, all four rlimit syscalls, capability bounding/ambient/current-set reduction, `no_new_privs`, and seccomp-filter installation;\n- the first failed stage plus errno is surfaced as an explicit unsupported probe result; a supported result requires a complete report and clean helper exit;\n- a deterministic CLI regression uses a deliberately nonexistent `filesystem.root`, requires the helper to report `supported` / `stage=complete`, requires `configured_root_touched=false` and `target_executed=false`, and proves the configured root remains absent;\n- the primary `mandatory_launch_core` state deliberately remains `unprobed`, `launch_attempted=false`, and `launch_preflight_complete=false`, so the real CLI remains `indeterminate` with exit status 4 rather than converting isolated primitive success into a false-positive `satisfied` verdict;\n- the exact implementation candidate passed stable rustfmt/Clippy/full tests and the full Rust 1.74 suite.\n\nBoundary: 24C is an isolated primitive-compatibility probe, not a launch dry-run or complete kernel compatibility oracle. It does not establish that the configured root exists or is pinnable, prove the exact configured executable/cwd/volume/Landlock/time/procfs path, reproduce the full launcher/PID1 orchestration, prove the production seccomp program for a policy, or prove successful `execveat`. Actual successful runtime execution remains authoritative for those properties.\n\n### Milestone 24 promotion rule\n\n24A–24B are sealed on `main`; 24C is the current integration candidate. After 24C integrates, do not farm additional syscall aliases or fixture variants around the same isolated-helper mechanism. A later preflight slice is justified only if it safely closes a currently unprobed prerequisite toward a sound complete verdict; otherwise promote to a materially different executable authority/enforcement frontier. Milestone 25A remains a separate evidence class because it records stages positively observed during an actual run.\n\n",
    "ROADMAP 24C candidate",
)
replace_one(
    "ROADMAP.md",
    "**Current verified candidate.** Adds an optional procfs view backed by the sandbox PID namespace while preserving launcher-owned PID 1 control authority.",
    "**Status: complete on `main`.** Adds an optional procfs view backed by the sandbox PID namespace while preserving launcher-owned PID 1 control authority.",
    "ROADMAP 26A status",
)
replace_one(
    "ROADMAP.md",
    "## Later frontiers\n",
    "## Milestone 27 — policy/runtime assurance tooling\n\n### Slice 27C — conservative static authority delta\n\n**Status: complete on `main`.** The standalone `security-lab-authority-delta` validates both policies fail-closed, classifies modeled declaration changes as unchanged/reduced/widened/incomparable, and uses distinct CI exit codes without launching the sandbox. Ambiguous endpoint/path substitutions and mixed widen/reduce changes remain incomparable rather than being guessed safe.\n\nBoundary: 27C is static declaration analysis. It explicitly does not claim effective kernel-state comparison, filesystem alias proof, theorem-proved implication, or a code-review waiver.\n\n### Slice 27D — runtime receipt completeness gate\n\n**Status: complete on `main`.** The standalone `security-lab-runtime-receipt-gate` performs a real `run_report`, derives the receipt-modeled enforcement stages required by the validated policy, rejects missing required stages and unexpected optional evidence, and preserves distinct runtime/setup failure reporting.\n\nBoundary: 27D checks only the current enforcement-receipt model. It explicitly does not claim full-policy attestation, successful exec, continued kernel-state effectiveness, or cryptographic/conformance certification.\n\n### Milestone 27 promotion rule\n\n27C–27D are sealed tooling slices. Do not farm comparator status aliases, receipt-field aliases, or extra output encodings. Future 27-series work must add a materially different executable authority/enforcement boundary or a genuinely stronger evidence model with implementation-backed semantics.\n\n## Later frontiers\n",
    "ROADMAP 27C/27D status",
)

# THREAT_MODEL: make the document status future-proof and distinguish isolated
# primitive probing from complete preflight/runtime evidence.
replace_one(
    "THREAT_MODEL.md",
    "# Milestones 1–25A + Milestone 26A candidate threat model",
    "# Current security-lab threat model",
    "threat title",
)
replace_between(
    "THREAT_MODEL.md",
    "Milestone 24A added a static declared-authority manifest",
    "Every claimed property must correspond to a kernel mechanism and executable evidence.",
    "Milestone 24A added a static declared-authority manifest, and Milestone 24B added conservative policy-specific host preflight that refuses to infer complete launch compatibility from partial host evidence. The current Milestone 24C verified candidate adds a throwaway isolated helper that positively probes representative mandatory namespace/mount/descriptor/resource/capability/`no_new_privs`/seccomp primitives without inspecting the configured root or executing the target; its result remains separate from the still-unprobed complete mandatory launch core. Milestone 25A added a post-attempt runtime enforcement receipt whose positive fields are published only after the corresponding launcher-owned kernel setup operation succeeds. Milestone 26A added optional private procfs for the sandbox PID namespace and closes the target's `/proc/1/fd` route to launcher-owned PID1 control descriptors. Milestone 27C added conservative static policy-authority delta classification, while Milestone 27D added a real-run receipt-completeness gate bounded to the existing receipt model. ",
    "threat purpose current evidence stack",
)
replace_between(
    "THREAT_MODEL.md",
    "- **Conservative policy-specific host preflight:**",
    "- **Runtime enforcement receipt:**",
    "- **Conservative policy-specific host preflight:** `preflight` / `preflight-json` validate policy and combine independently safe host observations with an optional throwaway Linux x86_64 helper that exercises representative mandatory namespace/mount/descriptor/resource/capability/`no_new_privs`/seccomp primitives. The helper mutates only its own child namespaces/private tmpfs, never materializes or inspects the configured policy root, and never executes the target. Its staged success/failure is reported separately; the complete `mandatory_launch_core` remains `unprobed`, so production preflight can still report known incompatibility or indeterminate evidence but cannot claim full satisfaction. `launch_attempted=false` and `launch_preflight_complete=false` remain explicit.\n- **Static policy-authority delta:** the standalone comparator operates only on two validated declarations and conservatively classifies modeled authority changes. It explicitly reports that it is not kernel-effective state or filesystem-alias proof, and incomparable relations are not treated as safe reductions.\n",
    "threat preflight and delta properties",
)
insert_before(
    "THREAT_MODEL.md",
    "- **Owned UTS nodename:**",
    "- **Runtime receipt completeness gate:** the standalone gate executes a real validated policy, then checks only mandatory/requested optional stages modeled by `EnforcementReceipt`; missing required or unexpected optional evidence fails the gate. It explicitly does not prove full policy attestation, successful exec, continuing enforcement, or cryptographic identity.\n",
    "threat receipt gate property",
)
replace_one(
    "THREAT_MODEL.md",
    "Milestones through 25A are complete on `main`; the bounded persistent-volume, namespace/network brokers, Landlock pathname/network/IPC/device envelopes, richer seccomp predicates, resource observability, observed-output enforcement, descendant time namespace, static/preflight observability, and runtime enforcement-receipt phases are sealed. The current Milestone 26A verified candidate adds private PID-namespace procfs observability while explicitly hardening launcher-owned PID1 descriptor-table access before target fork. After 26A integrates, seal this PID-visibility slice rather than farming proc mount aliases. Milestone 4A cgroup-v2 aggregate process accounting remains blocked by missing unprivileged delegation; supplementary-group isolation also remains blocked on a viable mapping architecture. Future promotion must target a materially different executable authority/enforcement frontier or add genuinely safe positive evidence for a previously unprobed mandatory runtime prerequisite.",
    "Milestones through 26A are complete on `main`; the bounded persistent-volume, namespace/network brokers, Landlock pathname/network/IPC/device envelopes, richer seccomp predicates, resource observability, observed-output enforcement, descendant time namespace, static/preflight observability, runtime enforcement receipt, and private-PID-procfs phases are sealed. Milestone 27C static authority-delta and 27D runtime receipt-gate tooling are also integrated and remain deliberately narrower than runtime attestation. The current 24C candidate adds positive isolated primitive evidence while keeping complete launch preflight indeterminate; after it integrates, do not farm probe-stage aliases. Milestone 4A cgroup-v2 aggregate process accounting remains blocked by missing unprivileged delegation; supplementary-group isolation also remains blocked on a viable mapping architecture. Future promotion must target a materially different executable authority/enforcement frontier or safely close a genuinely unprobed prerequisite without overstating evidence.",
    "threat phase promotion status",
)
