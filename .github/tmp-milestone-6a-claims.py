from pathlib import Path


def replace_one(path: str, old: str, new: str, label: str) -> None:
    p = Path(path)
    text = p.read_text()
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{label}: expected exactly one match, got {count}")
    p.write_text(text.replace(old, new, 1))


# README: seal 5A and describe only evidence-backed 6A guarantees.
replace_one(
    "README.md",
    "`security-lab` is a correctness-first systems-security laboratory. Milestone 1 established a bounded Linux process sandbox; Milestone 2 sealed ambient descriptor, launch, filesystem/identity, stdio, redirection, and bounded-capture authority; Milestone 3 sealed PID-tree lifecycle ownership plus a launcher-owned monotonic wall-clock deadline; Milestones 4B–4C added isolated Linux network and IPC namespace baselines. Milestone 4D added an **owned UTS identity boundary** with a validated launcher-installed sandbox hostname. The current Milestone 5A candidate adds **masked seccomp syscall-argument filtering**: policy may narrow an already-allowed syscall by numeric 64-bit argument values, and the x86_64 cBPF program enforces those constraints before allowing the call. The project is **not** a penetration-testing toolkit, malware framework, container runtime, or production multi-tenant isolation boundary.\n",
    "`security-lab` is a correctness-first systems-security laboratory. Milestone 1 established a bounded Linux process sandbox; Milestone 2 sealed ambient descriptor, launch, filesystem/identity, stdio, redirection, and bounded-capture authority; Milestone 3 sealed PID-tree lifecycle ownership plus a launcher-owned monotonic wall-clock deadline; Milestones 4B–4C added isolated Linux network and IPC namespace baselines; Milestone 4D added owned UTS nodename identity; and Milestone 5A added full-64-bit masked numeric seccomp argument narrowing. The current Milestone 6A candidate adds **explicit selected non-stdio handle passing**: the launcher may pin an already-open non-directory object before fork and expose it only at one declared target descriptor while undeclared descriptors remain sanitized. The project is **not** a penetration-testing toolkit, malware framework, container runtime, or production multi-tenant isolation boundary.\n",
    "README milestone summary",
)
replace_one(
    "README.md",
    "1. **Policy validation** requires a host `filesystem.root`, a validated `identity.hostname`, sandbox-internal executable/cwd paths, explicit stdio disposition, resource limits, environment entries, and a syscall allowlist. `identity.hostname` is 1–63 bytes, ASCII letters/digits/`-`/`.` only, and must begin/end with an alphanumeric byte. Optional scratch, stdout redirection, stdout capture, and `limit.wall_clock_milliseconds` are validated fail-closed. A declared wall-clock deadline must be 1–86,400,000 ms (24 hours).\n2. **Parent preparation** pins the root, cwd, and initial executable before `fork`. `openat2` rejects symlink/magic-link traversal and constrains configured paths beneath the selected root. The target inode is retained for `execveat(AT_EMPTY_PATH)`.\n",
    "1. **Policy validation** requires a host `filesystem.root`, a validated `identity.hostname`, sandbox-internal executable/cwd paths, explicit stdio disposition, resource limits, environment entries, and a syscall allowlist. `identity.hostname` is 1–63 bytes, ASCII letters/digits/`-`/`.` only, and must begin/end with an alphanumeric byte. Optional scratch, stdout redirection, stdout capture, selected non-stdio handles, and `limit.wall_clock_milliseconds` are validated fail-closed. Selected target descriptors are limited to 3–63, must remain below `limit.open_files`, and no more than 16 mappings are accepted. A declared wall-clock deadline must be 1–86,400,000 ms (24 hours).\n2. **Parent preparation** pins the root, cwd, initial executable, and every declared selected-handle source before `fork`. `openat2` rejects symlink/magic-link traversal and constrains configured paths beneath the selected root. The target inode is retained for `execveat(AT_EMPTY_PATH)`. Selected source descriptors are duplicated with `CLOEXEC`, inspected with `fstat`, and directory descriptors are rejected; launcher-owned storage descriptors are placed above every declared target destination to prevent remap collisions.\n",
    "README policy and preparation",
)
replace_one(
    "README.md",
    "9. **Target enforcement** the direct target alone applies explicit stdio, rlimits, capability reduction, `no_new_privs`, default-deny seccomp, and pinned `execveat`. Optional `seccomp.arg.<syscall>.<0..5>` rules further narrow already-allowed syscalls with full 64-bit masked-equality checks. Launcher namespace/deadline operations are not silently added to the target syscall allowlist. A policy may explicitly grant target `socket`/`connect`, but those syscalls execute inside the isolated network namespace.\n",
    "9. **Target enforcement** the direct target alone applies explicit stdio, installs declared selected handles with `dup3`, then applies rlimits, capability reduction, `no_new_privs`, default-deny seccomp, and pinned `execveat`. Optional `seccomp.arg.<syscall>.<0..5>` rules further narrow already-allowed syscalls with full 64-bit masked-equality checks. Handle installation is launcher setup before target seccomp and does not add `dup3` to `seccomp.allow`; later operations on an exposed object still require the corresponding target syscalls. A policy may explicitly grant target `socket`/`connect`, but those syscalls execute inside the isolated network namespace.\n",
    "README target enforcement",
)
replace_one(
    "README.md",
    "- Arbitrary inherited descriptors >= 3 do not survive successful target exec.\n",
    "- Undeclared inherited descriptors >= 3 do not survive successful target exec. Only policy-selected target descriptors are deliberately made non-`CLOEXEC`; their original source descriptor numbers and unrelated inherited high descriptors remain absent after exec.\n- `handle.<target_fd> = <source_fd>` grants an already-open kernel object capability, not a pathname. The launcher rejects directory descriptor sources, pins the source before fork, installs it only in the direct target, and does not retain its own duplicate in the host parent, bootstrap, or namespace PID 1 while the target runs.\n",
    "README FD invariants",
)
replace_one(
    "README.md",
    "`identity.hostname` is required. It must contain 1–63 ASCII bytes using letters, digits, `-`, or `.`, with an alphanumeric first and last byte. The launcher installs this value as the sandbox UTS nodename before the untrusted target starts.\n\nOptional syscall-argument rules use `seccomp.arg.<syscall>.<0..5> = <mask>:<value>`. Mask/value integers may be decimal or `0x` hexadecimal. The syscall must also appear in `seccomp.allow`, the mask must be non-zero, `value` may not set bits outside the mask, and the launcher-critical `execveat`, `exit`, and `exit_group` syscalls may not receive argument rules. At most 64 argument rules are accepted.\n",
    "`identity.hostname` is required. It must contain 1–63 ASCII bytes using letters, digits, `-`, or `.`, with an alphanumeric first and last byte. The launcher installs this value as the sandbox UTS nodename before the untrusted target starts.\n\nOptional selected handles use `handle.<target_fd> = <source_fd>`, where `source_fd` names an already-open descriptor in the calling process and `target_fd` is the descriptor number exposed to the direct target. Target descriptors are restricted to 3–63, must be below `limit.open_files`, are unique, and at most 16 mappings are accepted. Source descriptors are duplicated rather than consumed. Directory descriptors are rejected. Because an FD denotes an existing kernel object, explicitly selecting one can intentionally expose an object that is not reachable by pathname inside `filesystem.root`; the sandbox does not attenuate that object's existing open-file-description access mode, offset/state, or status flags.\n\nOptional syscall-argument rules use `seccomp.arg.<syscall>.<0..5> = <mask>:<value>`. Mask/value integers may be decimal or `0x` hexadecimal. The syscall must also appear in `seccomp.allow`, the mask must be non-zero, `value` may not set bits outside the mask, and the launcher-critical `execveat`, `exit`, and `exit_group` syscalls may not receive argument rules. At most 64 argument rules are accepted.\n",
    "README selected handle policy syntax",
)
replace_one(
    "README.md",
    "- a raw target exercises one `lseek` syscall under `seccomp.arg.lseek.1 = 0xffffffff0000000f:0x0000000100000008`: offset `0x0000000112345678` succeeds, while a low masked-bit mismatch (`...79`) and a high-32-bit mismatch (`0x00000002...78`) each receive seccomp `EPERM`, proving both halves of the 64-bit argument are enforced;\n",
    "- a raw target exercises one `lseek` syscall under `seccomp.arg.lseek.1 = 0xffffffff0000000f:0x0000000100000008`: offset `0x0000000112345678` succeeds, while a low masked-bit mismatch (`...79`) and a high-32-bit mismatch (`0x00000002...78`) each receive seccomp `EPERM`, proving both halves of the 64-bit argument are enforced;\n- a host-created pipe read end is duplicated to a high source descriptor, explicitly mapped to target fd 9, and the raw target reads the exact `selected-handle-ok` marker only from fd 9. The original high source descriptor and a separate undeclared high descriptor both return `EBADF` after exec; a directory source is independently rejected before launch;\n",
    "README selected handle evidence",
)
replace_one(
    "README.md",
    "Real enforcement is implemented only for **Linux x86_64**. Required mechanisms include `openat2`, `open_tree`, `mount_setattr`, `move_mount`, tmpfs, user/mount/PID/network/IPC/UTS namespaces, `sethostname`, UID/GID maps, capability operations, `close_range`, `pipe2`, `dup2`, seccomp, `execveat`, shared anonymous mappings, `fork`, `kill`, `wait4`, and `waitpid`. When a wall-clock deadline is declared, `pidfd_open`, `timerfd_create`/`timerfd_settime`, `CLOCK_MONOTONIC`, and `poll` are additionally required.\n",
    "Real enforcement is implemented only for **Linux x86_64**. Required mechanisms include `openat2`, `open_tree`, `mount_setattr`, `move_mount`, tmpfs, user/mount/PID/network/IPC/UTS namespaces, `sethostname`, UID/GID maps, capability operations, `close_range`, `pipe2`, `dup2`, seccomp, `execveat`, shared anonymous mappings, `fork`, `kill`, `wait4`, and `waitpid`. Selected handles additionally use `fcntl(F_DUPFD_CLOEXEC)`, `fstat`, and `dup3`. When a wall-clock deadline is declared, `pidfd_open`, `timerfd_create`/`timerfd_settime`, `CLOCK_MONOTONIC`, and `poll` are additionally required.\n",
    "README platform primitives",
)
replace_one(
    "README.md",
    "- deliberate selected non-stdio descriptor passing is not implemented;\n",
    "- selected handles are launch-time mappings only. There is no post-launch `SCM_RIGHTS`/broker API, descriptor revocation, rights attenuation, arbitrary remapping language, or directory-handle support. A deliberately selected already-open object can bypass pathname visibility because that object capability already exists;\n",
    "README selected handle limitations",
)

# Threat model.
replace_one(
    "THREAT_MODEL.md",
    "# Milestones 1–5A threat model\n",
    "# Milestones 1–6A threat model\n",
    "threat model title",
)
replace_one(
    "THREAT_MODEL.md",
    "`security-lab` is an educational, correctness-first Linux sandbox. Milestone 1 established syscall/resource/environment controls; Milestone 2 sealed descriptor, launch, filesystem/identity, stdio, redirection, and bounded-capture authority; Milestone 3 sealed PID-tree lifecycle ownership plus a policy-owned monotonic wall-clock deadline; Milestones 4B–4C added isolated network and IPC namespace baselines. Milestone 4D added launcher-owned UTS nodename identity. The current Milestone 5A candidate adds masked numeric syscall-argument constraints to the default-deny seccomp boundary. Every claimed property must correspond to a kernel mechanism and executable evidence.\n",
    "`security-lab` is an educational, correctness-first Linux sandbox. Milestone 1 established syscall/resource/environment controls; Milestone 2 sealed ambient descriptor, launch, filesystem/identity, stdio, redirection, and bounded-capture authority; Milestone 3 sealed PID-tree lifecycle ownership plus a policy-owned monotonic wall-clock deadline; Milestones 4B–4D added network/IPC/UTS namespace and identity baselines; and Milestone 5A added masked numeric syscall-argument constraints. The current Milestone 6A candidate adds explicit launch-time selected non-stdio object capabilities without reopening ambient descriptor inheritance. Every claimed property must correspond to a kernel mechanism and executable evidence.\n",
    "threat model purpose",
)
replace_one(
    "THREAT_MODEL.md",
    "The trusted host parent launches one direct target through launcher-owned bootstrap and namespace-init processes. On supported Linux x86_64, the launcher constrains initial filesystem visibility/mutability, namespace identity including a policy-owned UTS nodename, network/IPC/UTS namespace membership, capabilities, target syscall numbers and selected numeric syscall arguments, selected resources, environment, cwd, inherited descriptors, stdio, bounded capture, process-tree lifecycle, and—when declared—a wall-clock execution deadline while preserving fail-closed launch/lifecycle reporting.\n",
    "The trusted host parent launches one direct target through launcher-owned bootstrap and namespace-init processes. On supported Linux x86_64, the launcher constrains initial filesystem visibility/mutability, namespace identity including a policy-owned UTS nodename, network/IPC/UTS namespace membership, capabilities, target syscall numbers and selected numeric syscall arguments, selected resources, environment, cwd, ambient inherited descriptors, explicit selected non-stdio object handles, stdio, bounded capture, process-tree lifecycle, and—when declared—a wall-clock execution deadline while preserving fail-closed launch/lifecycle reporting.\n",
    "threat protected boundary",
)
replace_one(
    "THREAT_MODEL.md",
    "- **Inherited-FD minimization / explicit stdio:** arbitrary inherited descriptors >= 3 do not survive target exec; stdio disposition is explicit; launcher-owned redirect/capture sources are tightly remapped and closed.\n",
    "- **Inherited-FD minimization / explicit handle authority:** undeclared inherited descriptors >= 3 do not survive target exec. Stdio disposition is explicit; launcher-owned redirect/capture sources are tightly remapped and closed; only `handle.<target_fd>` destinations declared by policy are intentionally made visible as additional descriptors.\n- **Selected-object ownership:** each selected source is duplicated and inspected before fork, directory descriptors are rejected, and launcher storage descriptors are kept above every target destination. Host parent, bootstrap, and namespace PID 1 do not retain launcher-owned selected duplicates while the direct target runs.\n",
    "threat FD properties",
)
replace_one(
    "THREAT_MODEL.md",
    "- **No target-policy widening:** namespace management, pidfd/timerfd/poll, mounts, capture/remapping, and teardown execute in trusted launcher processes outside target seccomp. `socket` and `connect` are target syscalls only when the policy explicitly names them.\n",
    "- **No target-policy widening:** namespace management, pidfd/timerfd/poll, mounts, capture/remapping, selected-handle installation, and teardown execute in trusted launcher processes outside target seccomp. `dup3` used to install a selected target descriptor is not silently added to `seccomp.allow`; subsequent operations on that object still require the target syscalls explicitly granted by policy. `socket` and `connect` are target syscalls only when the policy explicitly names them.\n",
    "threat no target widening",
)
replace_one(
    "THREAT_MODEL.md",
    "## Deadline and lifecycle orchestration\n",
    "## Selected handle semantics\n\nMilestone 6A adds launch-time `handle.<target_fd> = <source_fd>` mappings. The source names an already-open descriptor in the trusted calling process; the target destination must be 3–63, must be below `limit.open_files`, and at most 16 mappings are accepted. Before fork, the launcher duplicates each source with `F_DUPFD_CLOEXEC`, rejects directory objects with `fstat`, and stores the duplicate above every target-visible destination. The pinned executable uses the same collision-free storage floor.\n\nAfter the namespace PID 1 forks the direct target, only that direct target remaps selected sources with `dup3(..., 0)` after stdio setup and before rlimits/capability/seccomp setup. The source-storage duplicates are then closed. The host parent drops its prepared duplicates immediately after fork; bootstrap and namespace PID 1 close all descriptors >= 3 on their non-target paths. Consequently a selected object does not gain hidden launcher/PID1 lifetime ownership while the target runs.\n\nThis is an explicit object-capability grant. It preserves the underlying open-file-description authority and state rather than mediating a new pathname lookup. Therefore a selected FD may intentionally expose an object outside the chroot/path namespace, and Milestone 6A does not claim rights attenuation, revocation, pathname confinement of that already-open object, post-launch descriptor transfer, or support for directory handles.\n\n## Deadline and lifecycle orchestration\n",
    "threat selected handle semantics",
)
replace_one(
    "THREAT_MODEL.md",
    "- deliberate selected non-stdio descriptor passing or a general arbitrary FD-remapping language;\n",
    "- post-launch descriptor brokering/`SCM_RIGHTS`, selected-handle revocation or rights attenuation, a general arbitrary FD-remapping language, or selected directory handles;\n",
    "threat selected handle limitation",
)
replace_one(
    "THREAT_MODEL.md",
    "- The policy author is trusted to choose filesystem exposure, stdio exposure, target data/syscall grants, resource ceilings, capture ceilings, and any wall-clock deadline.\n",
    "- The policy author is trusted to choose filesystem exposure, stdio exposure, selected already-open object handles, target data/syscall grants, resource ceilings, capture ceilings, and any wall-clock deadline. Selecting a handle intentionally grants the authority already represented by that open file description.\n",
    "threat trust assumption",
)
replace_one(
    "THREAT_MODEL.md",
    "- masked seccomp argument-rule parser/validator regressions plus a raw `lseek` oracle whose allowed offset matches the declared low/high 64-bit mask while separate low-bit and high-32-bit mismatches both return `EPERM`;\n",
    "- masked seccomp argument-rule parser/validator regressions plus a raw `lseek` oracle whose allowed offset matches the declared low/high 64-bit mask while separate low-bit and high-32-bit mismatches both return `EPERM`;\n- selected-handle policy regressions plus a raw pipe oracle in which target fd 9 reads the exact marker while the original selected source descriptor and an unrelated undeclared high descriptor both return `EBADF`; a directory descriptor source is separately rejected before launch;\n",
    "threat selected handle evidence",
)
replace_one(
    "THREAT_MODEL.md",
    "Invalid policy is rejected before launch. Namespace creation, UTS hostname installation, deadline support preflight, pidfd creation, timer creation/arming, supervision poll, namespace/bootstrap/init forks, descriptor cleanup, capture reads, mount/capability/seccomp setup, process-tree kill/reap, lifecycle publication, and target exec failures are terminal. A failed network/IPC/UTS namespace transition or hostname installation never falls back to the corresponding host namespace/identity.\n",
    "Invalid policy is rejected before launch. Namespace creation, UTS hostname installation, selected-source pin/inspection, selected-target remapping, deadline support preflight, pidfd creation, timer creation/arming, supervision poll, namespace/bootstrap/init forks, descriptor cleanup, capture reads, mount/capability/seccomp setup, process-tree kill/reap, lifecycle publication, and target exec failures are terminal. A failed selected-handle setup never silently preserves ambient source descriptors or retries without the declared mapping. A failed network/IPC/UTS namespace transition or hostname installation never falls back to the corresponding host namespace/identity.\n",
    "threat failure semantics",
)
replace_one(
    "THREAT_MODEL.md",
    "Milestone 4A cgroup-v2 aggregate process accounting remains blocked by missing unprivileged delegation on the current GitHub-hosted runner. Milestones 4B–4D are complete on `main`, including network/IPC namespace separation and launcher-owned UTS nodename identity. The current Milestone 5A frontier increases seccomp precision from syscall-number allowlisting to evidence-backed masked equality on full 64-bit numeric arguments. After 5A integrates, do not farm copied predicates across more syscalls. Supplementary-group clearing remains a separate architecture problem under the current unprivileged `setgroups=deny`/`gid_map` flow; other promotions should introduce a materially different object-authority, controlled-connectivity, persistence, or lifecycle boundary.\n",
    "Milestone 4A cgroup-v2 aggregate process accounting remains blocked by missing unprivileged delegation on the current GitHub-hosted runner. Milestones 4B–4D and 5A are complete on `main`, including network/IPC/UTS isolation and evidence-backed full-64-bit masked seccomp argument narrowing. The current Milestone 6A frontier turns selected non-stdio descriptors into an explicit launch-time object-capability surface while preserving ambient FD sanitization. After 6A integrates, do not farm more destination-number variants; promote to a materially different controlled-connectivity, persistence, or lifecycle/control-plane boundary. Supplementary-group clearing remains a separate architecture problem under the current unprivileged `setgroups=deny`/`gid_map` flow.\n",
    "threat phase promotion",
)

# Roadmap: seal 5A and add 6A.
replace_one(
    "ROADMAP.md",
    "**Current verified candidate.** Extend default-deny seccomp from syscall-number allowlisting to optional masked equality over selected numeric syscall arguments without widening launcher management authority.\n",
    "**Status: complete on `main`.** Extends default-deny seccomp from syscall-number allowlisting to optional masked equality over selected numeric syscall arguments without widening launcher management authority.\n",
    "roadmap 5A complete",
)
replace_one(
    "ROADMAP.md",
    "### Milestone 5 promotion rule\n\nAfter 5A integrates, do not farm identical argument masks across unrelated syscalls. Promote only when a new policy primitive or cross-layer integration is justified by a concrete authority boundary and executable evidence. Supplementary-group clearing requires a different user-namespace mapping architecture under the current nonprivileged `setgroups=deny` flow; 4A remains blocked on cgroup delegation.\n\n## Later frontiers\n\nExternal asynchronous cancellation, selected-handle passing, supplementary-group isolation with a viable mapping architecture, broader persistent-volume policy, and controlled networking remain separate evidence-backed frontiers. Do not add configuration-only names without executable kernel behavior and integration evidence.\n",
    "### Milestone 5 promotion rule\n\nMilestone 5A is sealed on `main`; do not farm identical argument masks across unrelated syscalls. Further seccomp work needs a materially new predicate model and executable authority boundary rather than copied rules. Supplementary-group clearing requires a different user-namespace mapping architecture under the current nonprivileged `setgroups=deny` flow; 4A remains blocked on cgroup delegation.\n\n## Milestone 6 — explicit object capabilities\n\n### Slice 6A — selected non-stdio handle passing\n\n**Current verified candidate.** Add an explicit launch-time object-capability surface without reopening ambient descriptor inheritance.\n\nAcceptance evidence is executable:\n\n- policy accepts `handle.<target_fd> = <source_fd>` for at most 16 unique target descriptors; target descriptors are restricted to 3–63 and must remain below `limit.open_files`;\n- the launcher duplicates each already-open source before fork with `F_DUPFD_CLOEXEC`, rejects directory descriptor sources with `fstat`, and leaves the caller-owned source descriptor untouched;\n- launcher-owned selected sources and the pinned executable are stored above every target-visible destination using a dynamically derived floor, avoiding destination collisions without imposing an unconditional fd>=64 requirement;\n- after stdio setup, only the direct target installs selected destinations with `dup3(..., 0)` before rlimits/capability/seccomp setup. Host parent, bootstrap, and namespace PID 1 do not retain launcher-owned selected duplicates while the target runs;\n- existing `close_range(..., CLOEXEC)` sanitization remains active, so undeclared inherited descriptors disappear at exec rather than being implicitly preserved;\n- a raw target reads `selected-handle-ok` from declared target fd 9 while both the original high source descriptor and a separate undeclared high descriptor return `EBADF`; a directory source is rejected before launch;\n- all Milestones 1–5A regressions, stable format/Clippy/full tests, and the full Rust 1.74 suite remain green.\n\nBoundary: 6A is a deliberate grant of an already-open kernel object. It does not attenuate the source open-file-description rights/state, mediate pathname access to that object, revoke the handle after launch, transfer new descriptors after launch, or support directory handles/general arbitrary FD remapping.\n\n### Milestone 6 promotion rule\n\nAfter 6A integrates, do not farm more descriptor numbers or object types merely to repeat the same remap path. Promote to a different executable boundary such as an external cancellation/control-plane primitive, evidence-backed persistent-volume policy, or controlled networking.\n\n## Later frontiers\n\nExternal asynchronous cancellation, supplementary-group isolation with a viable mapping architecture, broader persistent-volume policy, and controlled networking remain separate evidence-backed frontiers. Do not add configuration-only names without executable kernel behavior and integration evidence.\n",
    "roadmap milestone 6A",
)
