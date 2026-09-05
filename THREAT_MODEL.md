# Milestones 1–2E threat model

## Purpose

`security-lab` is an educational, correctness-first Linux sandbox. Milestone 1 established syscall/resource/environment controls; 2A removed inherited non-stdio descriptor leakage; 2B made launch/error reporting an owned control-plane protocol; 2C added filesystem-path and process-identity isolation; 2D added explicit filesystem mutability with a recursively read-only root plus optional bounded private scratch; and 2E makes standard-descriptor disposition explicit. Every claimed property must correspond to a kernel mechanism and executable evidence.

## Protected boundary

The trusted parent launches one child under a trusted policy. The target may be buggy or intentionally attempt operations outside its grant. On supported Linux x86_64, the launcher constrains initial filesystem visibility and mutability, namespace identity, capabilities, syscalls, selected resources, environment, working directory, inherited non-stdio descriptors, and whether each standard descriptor is inherited or closed while preserving fail-closed launch reporting.

## Security properties claimed

- **Pinned root/cwd/target:** `filesystem.root` is opened without symlink traversal. Sandbox-internal executable, cwd, and optional scratch paths are validated beneath that root with `openat2` resolve constraints.
- **Current-mount root revalidation:** after creating the child mount namespace, the configured root is reopened there and its `(st_dev, st_ino)` must match the pre-fork root pin or launch fails closed.
- **Initial executable identity:** the executable inode is pinned before `fork` and launched with `execveat(AT_EMPTY_PATH)`.
- **User/mount namespace isolation:** the child creates new user and mount namespaces. Namespace UID/GID 0 map only to the launching effective UID/GID.
- **Private mount propagation:** propagation is made recursively private before the sandbox mount tree is constructed.
- **Recursively read-only root:** the revalidated root is recursively cloned with `open_tree`, receives recursive `MOUNT_ATTR_RDONLY`, and is attached only inside the child mount namespace.
- **Explicit writable scratch:** policy may declare one existing scratch path plus size ceiling. That location is overlaid with a private `nosuid,nodev,noexec` tmpfs bounded by `filesystem.scratch_bytes`.
- **Filesystem path boundary:** the target is chrooted into the constructed root and switches to a cwd re-pinned from that mount tree.
- **Inherited non-stdio descriptor minimization:** inherited descriptors >= 3 are marked `CLOEXEC`, so arbitrary parent descriptors in that range do not survive successful target exec.
- **Explicit stdio disposition:** stdin/stdout/stderr have no implicit default. Each must be `inherit` or `closed`. Inherited stdio must exist and must not be a directory; closed stdio is explicitly closed before target exec. Enforcement occurs only after launcher operations that may allocate file descriptors, preventing setup work from silently repopulating 0/1/2.
- **Capability reduction:** capability bounding and ambient sets are cleared, and effective/permitted/inheritable sets are zeroed.
- **No privilege gain across exec:** `PR_SET_NO_NEW_PRIVS` is enabled before target exec.
- **Environment minimization:** only policy environment entries appear in target `envp`.
- **Resource ceilings:** configured CPU-time, address-space, regular-file-size, and open-file limits are applied as soft and hard rlimits.
- **Syscall least privilege:** classic seccomp-BPF validates the x86_64 audit architecture, permits only named syscalls, and returns `EPERM` for other x86_64 syscalls. The initial transition requires policy-authorized `execveat` plus `exit` or `exit_group`.
- **Owned launch-error reporting:** setup errors publish a bounded phase plus errno through pre-fork shared anonymous memory. Reporting does not depend on target stdio or target `write(2)` permission.
- **Fail-closed enforcement:** unsupported or failed mandatory enforcement never triggers an unrestricted retry.
- **Observable termination:** absent a launch error, normal exit and signal death are surfaced distinctly.

## Post-fork discipline

Potentially allocating data is prepared before `fork`: pinned descriptors, path C strings, tmpfs options, UID/GID map strings, argv/envp arrays, and the seccomp program. The child path uses direct libc/syscall operations and stack/local state. After stdio disposition is applied, subsequent launcher stages do not open new descriptors; launch errors remain observable through shared memory even if all stdio descriptors are closed.

## Explicit non-goals and limitations

This sandbox is **not** a production multi-tenant container boundary. It does not provide:

- confinement of an object deliberately exposed through `stdio.* = inherit`; the policy decision is explicit, but an inherited pipe/socket/terminal/file may still refer outside the filesystem root;
- stdio redirection to newly owned files/pipes or deliberate selected non-stdio descriptor passing;
- an immutable or cryptographic snapshot of the selected root subtree;
- a general persistent writable-volume policy beyond one ephemeral private tmpfs scratch;
- PID, network, IPC, UTS, or cgroup namespaces;
- cgroup-based aggregate memory/CPU/process accounting;
- a separate device namespace or network endpoint policy;
- syscall argument filtering;
- a guarantee that inherited supplementary groups are empty;
- persistent executable allowlisting after the initial pinned transition;
- multi-architecture seccomp;
- protection from sufficiently privileged external ptrace/signal interference;
- side-channel resistance;
- physical-memory accounting equivalent to cgroups;
- deterministic pipe/terminal output limits.

## Trust assumptions

- The Linux kernel and parent process are trusted.
- The policy author is trusted to choose filesystem root/scratch, stdio exposure, target data, syscall grants, and realistic resource ceilings.
- Choosing `stdio.* = inherit` is an intentional grant of the corresponding existing parent descriptor.
- The selected root contains only content the operator intends the target to see; choosing `/` provides no path minimization even though the private clone is read-only.
- `(st_dev, st_ino)` is used only as a root-directory identity revalidation signal, not as a subtree integrity proof.
- The kernel correctly implements the required openat2/mount/namespace/capability/close_range/seccomp/execveat semantics.

## Test strategy and evidence

The integration probe is statically linked with `-nostdlib` and uses raw Linux x86_64 syscalls, keeping target policies small and auditable. CI executes the entire suite on both stable Rust and Rust 1.74.

Evidence includes:

- allowed and denied syscall profiles, including omitted `getpid` returning `EPERM`;
- fail-closed malformed/unknown policy behavior and invalid scratch declarations;
- inherited high-FD non-leakage;
- all-closed stdio: raw `fcntl(F_GETFD)` observes `EBADF` for descriptors 0, 1, and 2;
- selective stdio: stdin/stderr are `EBADF`, stdout remains valid, and a raw `write(1, ...)` succeeds;
- owned `execveat` error reporting without target `write` permission;
- executable symlink escape rejection and host-path hiding;
- namespace UID/GID 0 plus zero effective, permitted, inheritable, bounding, and ambient capability sets;
- ordinary-root `O_CREAT` returning `EROFS`, scratch create/write succeeding, and parent verification that scratch is private;
- environment/cwd controls, all four rlimit readbacks, active `RLIMIT_NOFILE`, target-observed `no_new_privs`, and exit-vs-signal reporting.

CI explicitly enables user-namespace settings on its disposable Ubuntu runner so namespace/mount enforcement is exercised rather than skipped. The runtime itself does not alter host policy; unavailable mandatory primitives produce explicit unsupported/setup failures.

## Failure semantics

Invalid policy is rejected before launch. Mandatory namespace/mount/descriptor/capability/seccomp failures are terminal and carry bounded launch phases where possible. If an inherited stdio descriptor is missing or is a directory, launch fails during the explicit stdio phase. Closing a descriptor already closed with `EBADF` is accepted because the requested final state is satisfied. No failure path re-executes the target without the requested boundary.

## Next hardening direction

After explicit standard-descriptor disposition integrates, the next descriptor frontier is **owned redirection and deliberate selected handle passing** without weakening the existing invariant that arbitrary inherited descriptors >= 3 do not survive. The design should distinguish launcher-owned channels from ambient parent authority, prove target usability for declared handles, and prove undeclared handles remain absent. PID/process-tree isolation, network policy, and stronger aggregate resource accounting remain later independent frontiers.
