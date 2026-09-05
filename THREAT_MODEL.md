# Milestones 1–2B threat model

## Purpose

Milestone 1 established enforceable Linux least-privilege properties before executing a child process. Milestone 2A removed arbitrary inherited non-stdio descriptors as ambient authority. Milestone 2B makes launch/error reporting an owned control-plane mechanism rather than borrowing a target-granted `write(2)` syscall. The objective is educational correctness: every claimed boundary must correspond to an operating-system mechanism, and unsupported or failed enforcement must be visible.

## Protected boundary

The sandbox controls the initial launch of one child process from a trusted parent. The policy is assumed to be supplied by a trusted operator, but policy text may be malformed and must therefore fail closed.

The child may be buggy or intentionally attempt an operation outside its syscall grant. The sandbox is expected to deny syscalls outside the seccomp allowlist, prevent privilege gain through set-user-ID/set-group-ID bits or file capabilities on later exec via `no_new_privs`, cap selected process resources, remove ambient environment variables and non-stdio inherited descriptors, force the selected initial cwd, and report child-side setup/exec errors without requiring a target `write` grant.

## Security properties claimed

On a supported Linux x86_64 kernel:

- **Initial invocation integrity:** the launcher constructs executable path, argv, and envp from the validated policy before `fork`; the post-fork child has no caller-side launch override.
- **Environment minimization:** inherited environment variables are not passed; only policy variables are present in target `envp`.
- **Working-directory control:** the child changes to the configured absolute directory before target exec.
- **Descriptor minimization:** every descriptor numbered 3 or higher in the post-fork child is marked `CLOEXEC` atomically with `close_range` before target exec. It therefore cannot survive into the successfully executed target image. Descriptors 0/1/2 are deliberately retained.
- **Resource ceilings:** CPU time, address space, regular-file growth, and file-descriptor count receive the configured soft and hard `setrlimit` values.
- **No privilege gain across exec:** `PR_SET_NO_NEW_PRIVS` is set before the child program image is executed, blocking set-ID/file-capability privilege gain across later exec.
- **Syscall least privilege:** seccomp-BPF allows only policy-named syscalls and returns `EPERM` for all other x86_64 syscalls. The policy must name `execve` and at least one of `exit`/`exit_group`; the launcher does not insert an unlisted management syscall into the filter.
- **ABI fail-closed behavior:** a seccomp architecture mismatch kills the process instead of evaluating x86_64 syscall numbers on another ABI.
- **Owned launch-error reporting:** before `fork`, the parent allocates a small `MAP_SHARED|MAP_ANONYMOUS` record. A child-side setup or `execve` failure stores errno and a bounded phase identifier in that mapping, then terminates using a policy-authorized termination syscall. The parent reads the record after `waitpid`. Therefore precise post-seccomp exec-failure reporting does not depend on `write(2)` being granted to the target.
- **Policy/enforcement fail-closed behavior:** malformed policy and unknown syscall names are rejected; failure to inspect paths, prepare launch data, allocate launch state, fork, change cwd, sanitize descriptors, apply limits, set `no_new_privs`, install seccomp, exec the program, or wait for the child terminates the attempt. The launcher never retries without the requested boundary.
- **Observable termination:** when launch state reports no setup error, normal target exits and signal deaths are reported distinctly.

The shared launch-state page exists only across the fork boundary. A successful `execve` replaces the child address space, so the target does not retain the mapping. Error state is read by the trusted parent only after `waitpid`, avoiding a concurrent parent/child protocol after successful exec.

## Post-fork discipline

All potentially allocating launch preparation is completed in the trusted parent before `fork`: executable/cwd C strings, argument strings, environment strings, argv/envp pointer arrays, and the seccomp program. The child path performs direct libc/syscall operations and stack/local-memory construction only; it does not format error messages, acquire application locks, run destructors, or retry through an unrestricted path. This bounded discipline is important because the parent process may be multithreaded when `fork` occurs.

## Explicit non-goals and limitations

This sandbox is not a production security boundary and is not intended to safely run arbitrary hostile code in a multi-tenant environment.

It does not provide:

- filesystem isolation (`chroot`, pivot-root, mount namespaces, bind mounts, Landlock, or path-based read/write policy);
- user, PID, mount, IPC, UTS, cgroup, or network namespaces;
- network allow/deny policy beyond whatever syscalls the seccomp policy includes;
- cgroup-based memory/CPU/process accounting;
- Linux capability bounding-set or securebits management beyond `no_new_privs`;
- UID/GID changes or user-namespace mapping;
- device isolation;
- protection against ptrace/debugging or signal injection from a sufficiently privileged outside process;
- confinement of standard descriptors 0, 1, and 2, which intentionally remain connected to the parent environment;
- an explicit policy for intentionally passing selected non-stdio descriptors into the target;
- TOCTOU-resistant executable identity. The launcher validates a path and later executes that path; it does not pin an inode with `openat2`/`execveat`;
- persistent executable allowlisting. `execve` must be permitted for the initial transition into the configured target, and the current syscall-number-only filter cannot distinguish that initial exec from a later one performed by the target;
- syscall argument filtering. The current seccomp filter grants or denies by syscall number only;
- multi-architecture seccomp support;
- side-channel resistance;
- deterministic limits on data written to inherited pipes/terminals. `RLIMIT_FSIZE` constrains regular-file growth, not pipe volume;
- a guarantee that `RLIMIT_AS` equals physical-memory consumption or that rlimits provide cgroup-like aggregate accounting;
- a general-purpose fork-safe runtime. The owned child path is intentionally narrow and audited; future features must preserve that property or move to a stronger spawn architecture.

## Trust assumptions

- The parent process and kernel are trusted.
- The policy author is trusted to choose a sufficiently narrow allowlist and realistic resource limits.
- The executable path and working-directory path are not concurrently replaced by an attacker between preflight and `execve`; that race is a known limitation.
- The Linux kernel provides `close_range(..., CLOSE_RANGE_CLOEXEC)`, shared anonymous mappings, `fork`, seccomp, and `waitpid` semantics. Kernels missing required descriptor-sanitization support are rejected explicitly.

## Test strategy

The Linux x86_64 integration fixture is assembled as a static `-nostdlib` executable and performs raw syscalls. This deliberately avoids granting unreviewed loader/runtime syscalls just to make tests pass. Individual tests use exact profiles such as `execve/write/exit` or `execve/prctl/exit`, and a forbidden raw `getpid` must observe `-EPERM` for the denial test to pass. Separate fixture modes read back all four configured rlimits, observe `no_new_privs`, inspect the initial environment/cwd, exercise exit/signal reporting, and verify that a deliberately inheritable high-numbered descriptor is absent after exec.

Milestone 2B adds two launch-protocol checks: a policy without either `exit` or `exit_group` is rejected before execution, and an executable with a missing shebang interpreter must return a phase-specific `execve` setup error under a seccomp profile containing only `execve` and `exit`. The second check proves launcher error reporting no longer depends on target `write` permission.

## Failure semantics

Failing closed is part of the design, not an error-recovery option. Invalid policy is rejected before launch. Unsupported operating systems, architectures, or required kernel features return `UnsupportedPlatform`. Linux setup/enforcement and owned-launch errors return `SetupFailed`. There is no branch that converts any of those states into unrestricted execution.

## Next hardening direction

The next Milestone 2 frontier is a real filesystem/identity boundary: user and mount namespaces, explicit UID/GID mapping and capability dropping, a deliberately constructed minimal root with read-only/read-write mount policy, explicit treatment of standard/intentional descriptors, and TOCTOU-resistant target selection. Tests should prove denied path access, symlink/path-escape resistance, reduced identity/capability state, and fail-closed behavior when namespace or mount setup is unavailable.
