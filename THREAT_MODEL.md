# Milestone 1 threat model

## Purpose

Milestone 1 demonstrates that a small launcher can enforce several Linux least-privilege properties before executing a child process, and can prove those properties with executable tests. The objective is educational correctness: every claimed boundary must correspond to an operating-system mechanism, and unsupported or failed enforcement must be visible.

## Protected boundary

The sandbox controls one child process launched by a trusted parent. The policy is assumed to be supplied by a trusted operator, but policy text may be malformed and must therefore fail closed.

The child may be buggy or intentionally attempt an operation outside its syscall grant. The sandbox is expected to prevent syscalls outside the seccomp allowlist, prevent privilege gain through later exec, cap selected process resources, remove ambient environment variables, and force the selected initial cwd.

## Security properties claimed

On Linux x86_64, after a successful launch:

- **Invocation integrity:** executable path and arguments come only from the validated policy.
- **Environment minimization:** inherited environment variables are removed; only policy variables are present.
- **Working-directory control:** the child starts from the configured absolute directory.
- **Resource ceilings:** CPU time, address space, output file size, and file-descriptor count are bounded with `setrlimit`.
- **No privilege gain across exec:** `PR_SET_NO_NEW_PRIVS` is set before the child program image is executed.
- **Syscall least privilege:** seccomp-BPF allows only policy-named syscalls and returns `EPERM` for all other x86_64 syscalls.
- **ABI fail-closed behavior:** a seccomp architecture mismatch kills the process instead of evaluating x86_64 syscall numbers on another ABI.
- **Setup fail-closed behavior:** failure to inspect paths, apply limits, set `no_new_privs`, install seccomp, or launch the program terminates the attempt; the launcher never retries without the requested boundary.
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
- protection against all same-UID ambient resources that remain reachable through already-open descriptors inherited by the launcher environment;
- TOCTOU-resistant executable identity. Milestone 1 validates a path and later executes that path; it does not pin an inode with `openat2`/`execveat`;
- syscall argument filtering. The current seccomp filter grants or denies by syscall number only;
- multi-architecture seccomp support;
- side-channel resistance;
- deterministic limits on data written to inherited pipes/terminals. `RLIMIT_FSIZE` constrains regular-file growth, not pipe volume.

## Trust assumptions

- The parent process and kernel are trusted.
- The policy author is trusted to choose a sufficiently narrow allowlist and realistic resource limits.
- The executable path and working-directory path are not concurrently replaced by an attacker between preflight and `execve`; that race is a known limitation.
- The child does not start with security-sensitive inherited file descriptors. Milestone 1 relies on normal `Command` close-on-exec behavior and does not implement a complete descriptor inventory/closure policy.

## Failure semantics

Failing closed is part of the design, not an error-recovery option. Invalid policy is rejected before launch. Unsupported platforms return `UnsupportedPlatform`. Linux setup/enforcement errors return `SetupFailed`. There is no branch that converts any of those states into unrestricted execution.

## Next hardening direction

The next security milestone should add filesystem and identity isolation without weakening the current invariants: user + mount namespaces, a deliberately constructed root filesystem, explicit descriptor handling, and TOCTOU-resistant executable selection. Seccomp should then gain syscall argument constraints and architecture coverage where testable.
