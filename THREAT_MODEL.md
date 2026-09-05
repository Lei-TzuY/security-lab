# Milestones 1–2F-B threat model

## Purpose

`security-lab` is an educational, correctness-first Linux sandbox. Milestone 1 established syscall/resource/environment controls; 2A removed inherited non-stdio descriptor leakage; 2B made launch/error reporting an owned control-plane protocol; 2C added filesystem-path and process-identity isolation; 2D added a recursively read-only root plus bounded private scratch; 2E made standard-descriptor disposition explicit; 2F-A added launcher-owned stdout redirection; and the current 2F-B candidate adds bounded launcher-owned stdout capture. Every claimed property must correspond to a kernel mechanism and executable evidence.

## Protected boundary

The trusted parent launches one direct child under a trusted policy. On supported Linux x86_64, the launcher constrains initial filesystem visibility/mutability, namespace identity, capabilities, syscalls, selected resources, environment, cwd, inherited non-stdio descriptors, explicit standard-descriptor disposition, launcher-owned stdout redirection, and bounded retained stdout capture while preserving fail-closed launch reporting.

## Security properties claimed

- **Pinned root/cwd/target:** configured sandbox paths are fail-closed; the initial executable is pinned and launched with `execveat(AT_EMPTY_PATH)`.
- **Current-mount root revalidation:** after mount-namespace creation the selected root is reopened and must match the pre-fork `(st_dev, st_ino)` pin.
- **User/mount namespace isolation:** namespace UID/GID 0 map only to the launching effective UID/GID; mount propagation is private.
- **Filesystem mutability:** the revalidated root is recursively cloned/read-only; at most one declared bounded private `nosuid,nodev,noexec` scratch tmpfs is writable.
- **Filesystem path boundary:** the target is chrooted into the constructed root and switches to a re-pinned cwd.
- **Inherited-FD minimization:** arbitrary inherited descriptors >= 3 are marked `CLOEXEC` and do not survive successful target exec.
- **Explicit stdio:** inherited descriptors must exist and not be directories; closed descriptors are explicitly closed. stdout additionally supports launcher-owned redirection and capture.
- **Owned stdout redirection:** the launcher opens only a path strictly beneath private scratch after scratch exists, normalizes temporary low descriptors with `F_DUPFD_CLOEXEC`, maps only the source to fd 1 using `dup2`, then closes the source.
- **Bounded owned stdout capture:** capture creates a new pre-fork `pipe2(O_CLOEXEC)` rather than exposing an arbitrary parent descriptor. Both pipe ends are normalized above fd 2 before fork. The child closes the read end, maps the write end only to fd 1, then closes the high source. The parent closes its own write end and drains the read end before waiting for the direct child.
- **Bounded retained memory:** `stdio.stdout_capture_bytes` is limited to 1 byte–16 MiB. At most that many bytes are retained in `CapturedOutput`; additional bytes are drained and discarded and set `truncated = true`.
- **Pipe-pressure liveness for the direct child:** because the parent drains before `waitpid`, a target that emits more than the kernel pipe capacity is not blocked merely because the retained capture buffer reached its policy ceiling.
- **No target-policy widening:** launcher management operations for redirection/capture/remapping happen before target seccomp installation. The target receives only its named syscall allowlist.
- **Capability/resource controls:** capability sets are reduced, `no_new_privs` is enabled, configured rlimits are applied, and seccomp remains default-deny.
- **Owned launch-error reporting:** pre-exec phase+errno travels through shared anonymous memory and does not depend on target stdout/stderr or a target `write` grant.
- **Fail-closed enforcement:** failed or unsupported mandatory enforcement never triggers an unrestricted retry.

## Parent/child orchestration

Potentially allocating policy data, argv/envp, seccomp instructions, pinned descriptors, and capture-pipe creation occur before `fork`. Capture endpoints are normalized above fd 2 before fork so a launcher-created endpoint cannot accidentally make a previously absent inherited standard descriptor appear valid. In the child, the capture read end is closed immediately and the write source remains `CLOEXEC` until explicit stdout remapping.

In the parent, capture is drained to EOF **before `waitpid`**. Retention stops at the policy ceiling but draining continues. This ordering is a correctness requirement: waiting first could deadlock if the direct child fills the pipe and blocks in `write(2)` while the parent waits for it to exit.

## Explicit non-goals and limitations

This sandbox is **not** a production multi-tenant container boundary. It does not provide:

- confinement of objects explicitly exposed through `stdio.* = inherit`;
- stdin/stderr redirect or capture;
- a total-output byte ceiling for captured stdout. The configured ceiling limits retained parent memory only; excess output is discarded after being read;
- direct-child-only capture lifetime when target-created descendants are possible. Pipe EOF occurs only after every process retaining the stdout writer closes it. Because PID/process-tree isolation is not yet implemented, a descendant can prolong `run_report()` completion if policy grants the process-creation syscalls needed to create that descendant;
- deliberate selected non-stdio descriptor passing or a general arbitrary FD remapping language;
- persistence of private-scratch redirect output after the mount namespace disappears;
- PID, network, IPC, UTS, or cgroup namespaces;
- cgroup-based aggregate memory/CPU/process accounting;
- a device namespace, network endpoint policy, syscall argument filtering, or persistent data-volume policy;
- an immutable or cryptographic snapshot of the selected root subtree;
- a guarantee that inherited supplementary groups are empty;
- persistent executable allowlisting after the initial pinned transition;
- multi-architecture seccomp, side-channel resistance, or protection from sufficiently privileged external ptrace/signal interference.

## Trust assumptions

- The Linux kernel and trusted parent are trusted.
- The policy author is trusted to choose the filesystem root/scratch, explicit stdio exposure, target data, syscall grants, and realistic resource/capture ceilings.
- Choosing `inherit` intentionally grants the existing parent descriptor.
- Choosing `redirect` intentionally grants writes to the declared private-scratch file.
- Choosing `capture` intentionally creates a launcher-owned stdout channel and accepts that descendants retaining the writer affect EOF until process-tree isolation exists.
- The selected root contains only content the operator intends to expose; root device/inode revalidation is not a subtree integrity proof.

## Test strategy and evidence

The integration probe is statically linked with `-nostdlib` and uses raw Linux x86_64 syscalls. The full suite runs on stable Rust and Rust 1.74.

Evidence includes:

- exact allowed/denied syscall behavior and fail-closed malformed policy handling;
- inherited high-FD non-leakage;
- all-closed and selective-inherit stdio behavior;
- owned stdout redirection with target readback from private scratch and parent verification of no host write-through;
- exact small stdout capture returning the target bytes with `truncated = false`;
- a stress target writing 4096 raw 64-byte chunks (**256 KiB**) with a **1 KiB** capture ceiling. The target exits successfully, the parent retains exactly 1 KiB of the expected byte, and `truncated = true`, proving excess output is drained rather than allowed to block on a full pipe;
- owned launch-error reporting, filesystem hiding/read-only enforcement, private scratch, namespace UID/GID and capability reduction, environment/cwd, all four rlimits, `RLIMIT_NOFILE`, `no_new_privs`, and exit-vs-signal regressions.

CI explicitly enables the user-namespace settings required by its disposable Ubuntu runner. The runtime itself never weakens host policy when mandatory primitives are unavailable.

## Failure semantics

Invalid capture policy is rejected before launch. Pipe creation, endpoint normalization, child-side remapping, capture reads, namespace/mount/capability/seccomp setup, and target exec failures are terminal. A capture read error is not converted into successful execution. No failure path retries the target without the requested restrictions.

## Phase promotion

After 2F-B integrates, the descriptor phase has enough executable depth to stop farming stdout/FD variants: inherited high-FD authority is removed, stdio is explicit, and the launcher owns both a private-file output path and a bounded capture path. Deliberate selected non-stdio handle passing remains a possible future capability, but it is intentionally deferred rather than expanded into a generic FD-remapping language without a concrete integration need.

The next architectural frontier is **Milestone 3A — PID/process-tree isolation**. The design must address Linux PID-namespace semantics correctly: `CLONE_NEWPID` affects subsequently created children, so the launcher needs an explicit namespace-child/init orchestration rather than merely adding another `unshare` flag. Acceptance must include executable PID identity/process-tree behavior, deterministic descendant cleanup/reaping semantics, preserved launch-error reporting, and integration with captured-output lifetime rather than a configuration-only namespace toggle.
