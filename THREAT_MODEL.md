# Milestones 1–2C threat model

## Purpose

`security-lab` is an educational, correctness-first Linux sandbox. Milestone 1 established syscall/resource/environment controls, 2A removed inherited non-stdio descriptor leakage, 2B made launch/error reporting an owned control-plane protocol, and 2C adds filesystem-path and process-identity isolation. Every claimed property must correspond to a kernel mechanism and executable evidence.

## Protected boundary

The trusted parent launches one child under a trusted policy. The target may be buggy or intentionally attempt operations outside its grant. On supported Linux x86_64, the launcher is expected to constrain initial filesystem visibility, namespace identity, capabilities, syscalls, selected resources, environment, working directory, and inherited non-stdio descriptors while preserving fail-closed launch reporting.

## Security properties claimed

- **Pinned root/cwd/target:** `filesystem.root` is opened without symlink traversal. Sandbox-internal executable and cwd paths are resolved beneath that root with `openat2` using `RESOLVE_BENEATH`, `RESOLVE_NO_XDEV`, `RESOLVE_NO_MAGICLINKS`, and `RESOLVE_NO_SYMLINKS`.
- **Initial executable identity:** the executable inode is pinned before `fork` and launched with `execveat(AT_EMPTY_PATH)`. The initial transition does not re-resolve the executable pathname after validation.
- **User/mount namespace isolation:** the child creates new user and mount namespaces. Namespace UID/GID 0 map to the launching effective UID/GID only. Namespace root is not host root.
- **Private mount propagation:** the child makes mount propagation recursively private before entering the selected root.
- **Filesystem path boundary:** after switching to the pinned root and `chroot`, target absolute pathname resolution starts inside that root; the pinned cwd is selected with `fchdir`.
- **Directory-FD escape prevention:** directory-valued stdio descriptors are rejected. Non-stdio inherited descriptors are marked `CLOEXEC`, so a successful target exec retains no arbitrary descriptor >= 3 from the parent.
- **Capability reduction:** capability bounding and ambient sets are cleared, and effective/permitted/inheritable sets are zeroed before target exec.
- **No privilege gain across exec:** `PR_SET_NO_NEW_PRIVS` is enabled before target exec.
- **Environment minimization:** inherited environment variables are not passed; only policy entries appear in target `envp`.
- **Resource ceilings:** configured CPU-time, address-space, regular-file-size and open-file limits are applied as both soft and hard rlimits.
- **Syscall least privilege:** classic seccomp-BPF validates the x86_64 audit architecture, permits only policy-named syscalls, and returns `EPERM` for other x86_64 syscalls. The initial transition requires policy-authorized `execveat` and at least one of `exit`/`exit_group`; the launcher does not secretly widen the target filter.
- **Owned launch-error reporting:** child setup errors publish a bounded phase plus errno to a pre-fork shared anonymous page. The parent reads it after `waitpid`, so post-seccomp failure reporting does not require target `write(2)` permission.
- **Fail-closed enforcement:** unsupported or failed mandatory enforcement never triggers an unrestricted retry.
- **Observable termination:** when no launch error is recorded, normal exit status and signal death are surfaced distinctly.

## Post-fork discipline

Potentially allocating data is prepared before `fork`: pinned descriptors, UID/GID map strings, C strings, argv/envp arrays and the seccomp program. The child path is intentionally limited to direct libc/syscall operations and stack/local state. It does not format errors, acquire application locks, allocate policy data, run an unrestricted retry path, or depend on a pipe-based launch protocol.

## Explicit non-goals and limitations

This sandbox is **not** a production multi-tenant container boundary.

It does not provide:

- automatic read-only protection for `filesystem.root` or a declared read/write mount policy;
- isolation from changes made concurrently to arbitrary non-pinned files inside the selected root;
- PID, network, IPC, UTS or cgroup namespaces;
- cgroup-based aggregate memory/CPU/process accounting;
- device isolation or a network endpoint policy;
- syscall argument filtering;
- confinement of non-directory stdio handles. FDs 0/1/2 may intentionally retain pipes, sockets, terminals or file handles that refer outside the selected root;
- a policy for intentionally passing selected non-stdio descriptors;
- a guarantee that inherited supplementary groups are empty. The unprivileged GID-map path writes `setgroups=deny` and maps the primary effective GID only;
- persistent executable allowlisting. The initial target is pinned, but a target policy that grants later `execve`/`execveat` may execute another path visible within the root;
- immutable root/cwd directory contents. Their directory objects are pinned, but entries under them can still change according to host/filesystem permissions;
- multi-architecture seccomp;
- protection from sufficiently privileged external ptrace/signal interference;
- side-channel resistance;
- physical-memory accounting equivalent to cgroups (`RLIMIT_AS` is an address-space ceiling);
- deterministic pipe/terminal output limits (`RLIMIT_FSIZE` applies to regular-file growth).

## Trust assumptions

- The Linux kernel and parent process are trusted.
- The policy author is trusted to choose `filesystem.root`, target data, syscall grants and realistic resource ceilings.
- The selected root contains only content the operator intends the target to see. Choosing `/` intentionally provides no host-path hiding.
- Non-directory stdio handles intentionally exposed by the parent are trusted ambient channels.
- The kernel correctly implements required `openat2`, namespaces, UID/GID mapping, capability, `close_range`, seccomp and `execveat` semantics.

## Test strategy and evidence

The integration probe is statically linked with `-nostdlib` and uses raw Linux x86_64 syscalls, keeping each target policy small and auditable. Current CI executes the entire suite on both stable Rust and the declared Rust 1.74 MSRV.

Evidence includes:

- allowed and denied syscall profiles, including an omitted `getpid` returning `EPERM`;
- fail-closed malformed/unknown policy behavior;
- inherited high-FD non-leakage;
- owned `execveat` error reporting without target `write` permission;
- rejection of an executable symlink that points outside the selected root;
- an absolute host-only pathname outside the selected root returning `ENOENT` from the target;
- namespace UID/GID 0 plus zero effective, permitted, inheritable, bounding and ambient capability sets;
- environment/cwd controls;
- all four rlimit readbacks and active `RLIMIT_NOFILE` enforcement;
- target-observed `no_new_privs`;
- exit-vs-signal reporting.

GitHub's Ubuntu 24.04 runner has an AppArmor policy that can restrict unprivileged user namespaces. CI explicitly enables the relevant user-namespace sysctls on the disposable runner so the namespace enforcement path is executed rather than skipped. The runtime itself does not change host policy; inability to create the mandatory namespaces is reported explicitly.

## Failure semantics

Invalid policy is rejected before launch. Missing required kernel primitives or denied mandatory namespace creation returns an explicit unsupported/setup failure; setup failures carry a bounded phase where possible. No failure path re-executes the target without the requested root, identity, capability, descriptor, rlimit, `no_new_privs`, or seccomp boundary.

## Next hardening direction

With path visibility and initial identity now bounded, the largest remaining filesystem authority is **mutability inside the selected root** and deliberately inherited I/O. The next architectural slice should investigate an enforceable mount policy—such as a read-only root plus explicitly writable scratch/data mounts—while retaining user-namespace compatibility and deterministic CI evidence. A subsequent frontier can make stdio/intentional descriptor passing explicit and then add process/network namespace policy where it can be proven rather than merely named.
