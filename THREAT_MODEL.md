# Milestone 1 threat model

## Purpose

Milestone 1 demonstrates that a small launcher can enforce several Linux least-privilege properties before executing a child process, and can prove those properties with executable tests. The objective is educational correctness: every claimed boundary must correspond to an operating-system mechanism, and unsupported or failed enforcement must be visible.

## Protected boundary

The sandbox controls the initial launch of one child process from a trusted parent. The policy is assumed to be supplied by a trusted operator, but policy text may be malformed and must therefore fail closed.

The child may be buggy or intentionally attempt an operation outside its syscall grant. The sandbox is expected to deny syscalls outside the seccomp allowlist, prevent privilege gain through set-user-ID/set-group-ID bits or file capabilities on later exec via `no_new_privs`, cap selected process resources, remove ambient environment variables, and force the selected initial cwd.

## Security properties claimed

On Linux x86_64, after a successful launch:

- **Initial invocation integrity:** the launcher starts the executable path and arguments from the validated policy; there is no caller-side launch override.
- **Environment minimization:** inherited environment variables are removed; only policy variables are present.
- **Working-directory control:** the child starts from the configured absolute directory.
- **Resource ceilings:** CPU time, address space, regular-file growth, and file-descriptor count receive the configured soft and hard `setrlimit` values.
- **No privilege gain across exec:** `PR_SET_NO_NEW_PRIVS` is set before the child program image is executed, blocking set-ID/file-capability privilege gain across later exec.
- **Syscall least privilege:** seccomp-BPF allows only policy-named syscalls and returns `EPERM` for all other x86_64 syscalls.
- **ABI fail-closed behavior:** a seccomp architecture mismatch kills the process instead of evaluating x86_64 syscall numbers on another ABI.
- **Policy/enforcement fail-closed behavior:** malformed policy and unknown syscall names are rejected; failure to inspect paths, apply limits, set `no_new_privs`, install seccomp, or launch the program terminates the attempt. The launcher never retries without the requested boundary.
- **Observable termination:** normal exits and signal deaths are reported distinctly.

## Explicit non-goals and limitations

This sandbox is not a production security boundary and is not intended to safely run arbitrary hostile code in a multi-tenant environment.

Milestone 1 does not provide:

- filesystem isolation (`chroot`, pivot-root, mount namespaces, bind mounts, Landlock, or path-based read/write policy);
- user, PID, mount, IPC, UTS, cgroup, or network namespaces;
- network allow/deny policy beyond whatever syscalls the seccomp policy includes;
- cgroup-based memory/CPU/process accounting;
- Linux capability bounding-set or securebits management beyond `no_new_privs`;
- UID/GID changes or user-namespace mapping;
- device isolation;
- protection against ptrace/debugging or signal injection from a sufficiently privileged outside process;
- automatic closure or inventory of arbitrary inherited file descriptors. A trusted parent must not expose sensitive descriptors without close-on-exec;
- TOCTOU-resistant executable identity. Milestone 1 validates a path and later executes that path; it does not pin an inode with `openat2`/`execveat`;
- persistent executable allowlisting. `execve` must be permitted for the initial transition into the configured target, and the current syscall-number-only filter cannot distinguish that initial exec from a later one performed by the target;
- syscall argument filtering. The current seccomp filter grants or denies by syscall number only;
- multi-architecture seccomp support;
- side-channel resistance;
- deterministic limits on data written to inherited pipes/terminals. `RLIMIT_FSIZE` constrains regular-file growth, not pipe volume;
- a guarantee that `RLIMIT_AS` equals physical-memory consumption or that rlimits provide cgroup-like aggregate accounting.

## Trust assumptions

- The parent process and kernel are trusted.
- The policy author is trusted to choose a sufficiently narrow allowlist and realistic resource limits.
- The executable path and working-directory path are not concurrently replaced by an attacker between preflight and `execve`; that race is a known limitation.
- The parent does not expose security-sensitive non-close-on-exec file descriptors to the child.

## Test strategy

The Linux x86_64 integration fixture is assembled as a static `-nostdlib` executable and performs raw syscalls. This deliberately avoids granting unreviewed loader/runtime syscalls just to make tests pass. Individual tests use exact profiles such as `execve/write/exit` or `execve/prctl/exit`, and a forbidden raw `getpid` must observe `-EPERM` for the denial test to pass. Separate fixture modes read back all four configured rlimits, observe `no_new_privs`, inspect the initial environment/cwd, and exercise exit/signal reporting.

## Failure semantics

Failing closed is part of the design, not an error-recovery option. Invalid policy is rejected before launch. Unsupported platforms return `UnsupportedPlatform`. Linux setup/enforcement errors return `SetupFailed`. There is no branch that converts any of those states into unrestricted execution.

## Next hardening direction

Milestone 2 should add a real filesystem/identity boundary without weakening Milestone 1: user and mount namespaces, explicit UID/GID mapping and capability dropping, a deliberately constructed minimal root with read-only/read-write mount policy, explicit inherited-FD closure, and TOCTOU-resistant target selection. Tests should prove denied path access, symlink/path-escape resistance, descriptor non-leakage, and reduced identity/capability state. Syscall argument filtering and additional architecture support can build on that boundary once their semantics are testable.
