# Milestones 1–2F-A threat model

## Purpose

`security-lab` is an educational, correctness-first Linux sandbox. Milestone 1 established syscall/resource/environment controls; 2A removed inherited non-stdio descriptor leakage; 2B made launch/error reporting an owned control-plane protocol; 2C added filesystem-path and process-identity isolation; 2D added a recursively read-only root plus optional bounded private scratch; 2E made standard-descriptor disposition explicit; and 2F-A adds a launcher-owned stdout file redirection path inside that private scratch. Every claimed property must correspond to a kernel mechanism and executable evidence.

## Protected boundary

The trusted parent launches one child under a trusted policy. The target may be buggy or intentionally attempt operations outside its grant. On supported Linux x86_64, the launcher constrains initial filesystem visibility and mutability, namespace identity, capabilities, syscalls, selected resources, environment, working directory, inherited non-stdio descriptors, standard-descriptor disposition, and the first launcher-owned stdout destination while preserving fail-closed launch reporting.

## Security properties claimed

- **Pinned root/cwd/target:** `filesystem.root` is opened without symlink traversal. Sandbox-internal executable, cwd, optional scratch, and optional stdout-redirection paths are validated with fail-closed path rules.
- **Current-mount root revalidation:** after creating the child mount namespace, the configured root is reopened there and its `(st_dev, st_ino)` must match the pre-fork root pin or launch fails closed.
- **Initial executable identity:** the executable inode is pinned before `fork` and launched with `execveat(AT_EMPTY_PATH)`.
- **User/mount namespace isolation:** the child creates new user and mount namespaces. Namespace UID/GID 0 map only to the launching effective UID/GID.
- **Private mount propagation:** propagation is made recursively private before the sandbox mount tree is constructed.
- **Recursively read-only root:** the revalidated root is recursively cloned with `open_tree`, receives recursive `MOUNT_ATTR_RDONLY`, and is attached only inside the child mount namespace.
- **Explicit writable scratch:** policy may declare one existing scratch path plus size ceiling. That location is overlaid with a private `nosuid,nodev,noexec` tmpfs bounded by `filesystem.scratch_bytes`.
- **Filesystem path boundary:** the target is chrooted into the constructed root and switches to a cwd re-pinned from that mount tree.
- **Inherited non-stdio descriptor minimization:** arbitrary inherited descriptors >= 3 are marked `CLOEXEC`, so they do not survive successful target exec.
- **Explicit stdio disposition:** stdin/stdout/stderr have no implicit default. Inherited stdio must exist and must not be a directory; closed stdio is explicitly closed before target exec.
- **Owned stdout redirection:** `stdio.stdout = redirect` requires a `stdio.stdout_path` strictly beneath the declared private scratch path. The launcher opens the file with `openat2` only after the private tmpfs is mounted, using no-symlink and beneath constraints. If the temporary file descriptor occupies 0/1/2, it is first moved above stdio using `F_DUPFD_CLOEXEC`; the source remains `CLOEXEC` through descriptor sanitization, is mapped only to fd 1 with `dup2`, and is then closed.
- **No target-policy widening for redirection:** launcher `openat2`, `fcntl`, and `dup2` operations occur before target seccomp installation. The target still receives exactly its policy-named syscall allowlist.
- **Capability reduction:** capability bounding and ambient sets are cleared, and effective/permitted/inheritable sets are zeroed.
- **No privilege gain across exec:** `PR_SET_NO_NEW_PRIVS` is enabled before target exec.
- **Environment minimization:** only policy environment entries appear in target `envp`.
- **Resource ceilings:** configured CPU-time, address-space, regular-file-size, and open-file limits are applied as soft and hard rlimits.
- **Syscall least privilege:** classic seccomp-BPF validates the x86_64 audit architecture, permits only named syscalls, and returns `EPERM` for other x86_64 syscalls. The initial transition requires policy-authorized `execveat` plus `exit` or `exit_group`.
- **Owned launch-error reporting:** setup errors publish a bounded phase plus errno through pre-fork shared anonymous memory. Reporting does not depend on target stdio or target `write(2)` permission.
- **Fail-closed enforcement:** unsupported or failed mandatory enforcement never triggers an unrestricted retry.
- **Observable termination:** absent a launch error, normal exit and signal death are surfaced distinctly.

## Post-fork discipline

Potentially allocating data is prepared before `fork`: pinned descriptors, path C strings, tmpfs options, redirect path, UID/GID map strings, argv/envp arrays, and the seccomp program. The child path uses direct libc/syscall operations and stack/local state. Launcher-owned stdout is opened before final stdio disposition, then normalized to a temporary fd >= 3 so a missing inherited standard descriptor cannot be silently satisfied by setup fd allocation. After stdio disposition, subsequent launcher stages do not open new descriptors; launch errors remain observable through shared memory.

## Explicit non-goals and limitations

This sandbox is **not** a production multi-tenant container boundary. It does not provide:

- confinement of an object deliberately exposed through `stdio.* = inherit`; an inherited pipe/socket/terminal/file may still refer outside the filesystem root;
- stdin or stderr redirection in 2F-A;
- launcher-owned pipe capture or a parent API that retrieves redirected stdout bytes;
- deliberate selected non-stdio descriptor passing; arbitrary inherited descriptors >= 3 remain removed by the existing boundary;
- persistence of the redirected file after the private mount namespace disappears;
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
- The policy author is trusted to choose filesystem root/scratch, stdio exposure/redirection, target data, syscall grants, and realistic resource ceilings.
- Choosing `stdio.* = inherit` is an intentional grant of the corresponding existing parent descriptor.
- Choosing stdout `redirect` intentionally grants target writes to the declared private scratch file; the path must remain strictly under the scratch mount.
- The selected root contains only content the operator intends the target to see; choosing `/` provides no path minimization even though the private clone is read-only.
- `(st_dev, st_ino)` is used only as a root-directory identity revalidation signal, not as a subtree integrity proof.
- The kernel correctly implements the required openat2/mount/namespace/capability/close_range/dup2/seccomp/execveat semantics.

## Test strategy and evidence

The integration probe is statically linked with `-nostdlib` and uses raw Linux x86_64 syscalls, keeping target policies small and auditable. CI executes the entire suite on both stable Rust and Rust 1.74.

Evidence includes:

- allowed and denied syscall profiles, including omitted `getpid` returning `EPERM`;
- fail-closed malformed/unknown policy behavior and invalid scratch/redirection declarations;
- inherited high-FD non-leakage;
- all-closed stdio: raw `fcntl(F_GETFD)` observes `EBADF` for descriptors 0, 1, and 2;
- selective stdio: stdin/stderr are `EBADF`, stdout remains valid, and a raw `write(1, ...)` succeeds;
- owned stdout redirection: the raw target writes one byte through fd 1, reopens `/scratch/stdout.log`, reads the same byte back, and exits successfully; the parent verifies the corresponding host scratch path does not exist;
- owned `execveat` error reporting without target `write` permission;
- executable symlink escape rejection and host-path hiding;
- namespace UID/GID 0 plus zero effective, permitted, inheritable, bounding, and ambient capability sets;
- ordinary-root `O_CREAT` returning `EROFS`, scratch create/write succeeding, and parent verification that scratch is private;
- environment/cwd controls, all four rlimit readbacks, active `RLIMIT_NOFILE`, target-observed `no_new_privs`, and exit-vs-signal reporting.

CI explicitly enables user-namespace settings on its disposable Ubuntu runner so namespace/mount enforcement is exercised rather than skipped. The runtime itself does not alter host policy; unavailable mandatory primitives produce explicit unsupported/setup failures.

## Failure semantics

Invalid policy is rejected before launch. Stdout redirect is rejected unless its path is present, absolute, and strictly below the declared scratch path; redirect on stdin/stderr is rejected in this slice. Mandatory namespace/mount/descriptor/redirection/capability/seccomp failures are terminal and carry bounded launch phases where possible. No failure path re-executes the target without the requested boundary.

## Next hardening direction

After owned stdout redirection integrates, the next descriptor frontier is **deliberate selected handle passing and/or launcher-owned pipe capture** without weakening the invariant that arbitrary inherited descriptors >= 3 do not survive. A selected-handle design must normalize source descriptors safely, reserve deterministic target fd numbers below `RLIMIT_NOFILE`, avoid collisions with stdio/redirection, prove declared-handle usability, and independently prove undeclared inheritable descriptors remain absent. PID/process-tree isolation, network policy, and stronger aggregate resource accounting remain later frontiers.
