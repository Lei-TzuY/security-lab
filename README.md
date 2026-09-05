# security-lab

`security-lab` is a correctness-first systems-security laboratory. Milestone 1 established a bounded Linux process sandbox; Milestones 2A–2D added inherited-FD minimization, an owned launch/error protocol, a filesystem/identity boundary, and a recursively read-only root with an optional bounded private writable scratch mount. Milestone 2E makes standard-descriptor authority explicit: stdin/stdout/stderr must each be declared as `inherit` or `closed`. The project is **not** a penetration-testing toolkit, malware framework, container runtime, or production multi-tenant isolation boundary.

## Current sandbox pipeline

The Linux x86_64 implementation launches exactly one child from an explicit policy:

1. **Policy validation** (`src/policy.rs`) requires a host `filesystem.root`, sandbox-internal executable and working-directory paths, explicit `stdio.stdin`, `stdio.stdout`, and `stdio.stderr` disposition, resource limits, environment entries, and a syscall allowlist. Optional writable scratch requires both `filesystem.scratch` and `filesystem.scratch_bytes`; malformed, incomplete, overlapping, or oversized scratch declarations fail closed.
2. **Parent preparation** pins the root directory, working directory, and initial executable before `fork`. `openat2` rejects symlink traversal; executable/cwd/scratch resolution is constrained beneath the pinned root and may not cross a mount point. The target inode is retained for `execveat(AT_EMPTY_PATH)`.
3. **Owned child filesystem setup** creates user and mount namespaces, maps namespace UID/GID 0 to the launching effective UID/GID, makes mount propagation private, reopens the configured root in the child mount namespace, and verifies `(st_dev, st_ino)` against the pre-fork pin. It recursively clones that root with `open_tree`, applies recursive `MOUNT_ATTR_RDONLY`, and attaches the clone only inside the private mount namespace.
4. **Optional writable scratch** overlays the declared sandbox path with a private tmpfs after the root tree is read-only. The tmpfs is bounded by policy size and mounted `nosuid,nodev,noexec`.
5. **Descriptor authority and remaining setup** enters the constructed root/cwd, marks every inherited descriptor >= 3 `CLOEXEC`, then applies the explicit stdio policy. `inherit` requires the corresponding parent descriptor to exist and not be a directory; `closed` closes it and accepts only the already-closed `EBADF` case. Rlimits, capability reduction, `no_new_privs`, and seccomp follow without reopening 0/1/2.
6. **Pinned execution** uses `execveat` on the pre-opened executable descriptor, so the initial executable identity does not depend on re-resolving its pathname after validation.
7. **Owned error/result reporting** transports pre-exec phase+errno through shared anonymous memory and waits with `waitpid`. Reporting therefore remains available even when stdout/stderr are closed or target `write(2)` is not granted.
8. **Deterministic tests** use a statically linked raw-syscall x86_64 probe, avoiding hidden libc/Rust-runtime syscall requirements.

## Security invariants

For a successful `run(policy)` on a supported Linux x86_64 kernel:

- `filesystem.root` is pinned without following symlinks. Executable, cwd, and optional scratch paths are absolute paths inside that root and are constrained with `openat2` resolve flags where applicable.
- After entering a new mount namespace, the configured root is reopened there and its `(st_dev, st_ino)` must match the pre-fork root pin or launch fails closed.
- The initial executable inode is pinned before `fork` and started with `execveat(..., AT_EMPTY_PATH)`.
- User and mount namespaces are mandatory; namespace UID/GID 0 map only to the launching process's effective UID/GID.
- Mount propagation is private before constructing the sandbox mount tree.
- The selected root mount tree is recursively cloned and recursively marked read-only before target execution.
- Optional scratch is exactly one declared private tmpfs, bounded by `filesystem.scratch_bytes` and mounted `nosuid,nodev,noexec`.
- The target is chrooted into the constructed root and switches to a cwd re-pinned from that mount tree.
- Every inherited descriptor >= 3 is marked `CLOEXEC` and cannot survive successful target exec.
- Descriptors 0/1/2 have no implicit default: each must be declared `inherit` or `closed`. Inherited stdio must exist and must not be a directory; closed stdio is actually closed before target exec.
- The capability bounding and ambient sets are cleared, and effective/permitted/inheritable capability sets are zeroed.
- `RLIMIT_CPU`, `RLIMIT_AS`, `RLIMIT_FSIZE`, and `RLIMIT_NOFILE` soft/hard ceilings are applied.
- `PR_SET_NO_NEW_PRIVS=1` is enabled before target exec.
- Seccomp-BPF validates the x86_64 audit architecture, permits only policy-named syscalls, and returns `EPERM` for other x86_64 syscalls. The policy must authorize `execveat` plus `exit` or `exit_group`; launcher management syscalls are not added to the target filter.
- Target `envp` contains only policy entries.
- Setup/enforcement failures never retry without the requested restrictions.

## Policy format

`filesystem.root` is a host path selected by the trusted operator. `executable`, `working_dir`, and optional `filesystem.scratch` are paths interpreted inside that root. Scratch path and byte ceiling must be specified together; scratch cannot replace the root or contain the executable/cwd, and its size is limited to 4 KiB–1 GiB.

Each standard descriptor must explicitly use one of:

- `inherit`: retain the existing parent descriptor, but fail if it is missing or a directory;
- `closed`: guarantee the target starts with that descriptor closed.

```text
filesystem.root = /
# Optional private writable area; the directory must already exist in the root.
# filesystem.scratch = /var/tmp
# filesystem.scratch_bytes = 16777216
executable = /usr/bin/echo
arg = hello from the sandbox
working_dir = /tmp
env.LANG = C
stdio.stdin = closed
stdio.stdout = inherit
stdio.stderr = inherit
limit.cpu_seconds = 2
limit.address_space_bytes = 536870912
limit.file_size_bytes = 1048576
limit.open_files = 32
seccomp.allow = execveat,read,write,close,fstat,lseek,mmap,mprotect,munmap,brk,rt_sigaction,rt_sigprocmask,rt_sigreturn,pread64,access,madvise,arch_prctl,set_tid_address,set_robust_list,prlimit64,getrandom,openat,newfstatat,exit,exit_group
```

`filesystem.root = /` still exposes the host pathname namespace to the sandbox, although the private root clone presented to the child is read-only. Real path minimization requires a deliberately prepared smaller root.

Run the included example with:

```bash
cargo run --bin security-lab -- run examples/policies/echo.conf
```

The CLI prints `sandbox-result: exited code=N` or `sandbox-result: signaled signal=N`. Policy/setup errors are printed as `sandbox-error: ...` and exit with status 125. Policy read/parse errors exit with status 2.

### Syscall policy behavior

The filter is installed before the pinned `execveat`, so a usable policy must allow `execveat`, at least one termination syscall (`exit` or `exit_group`), and every syscall required by the target and its loader. Unknown syscall names are rejected before launch; omitted syscalls receive `EPERM`.

The initial target is pinned, but the sandbox does **not** claim persistent executable allowlisting. A target policy granting later `execve`/`execveat` may launch another executable visible within the filesystem boundary.

## Test evidence

Linux x86_64 integration tests prove that:

- an exact `execveat/write/exit` profile completes an allowed raw-syscall operation;
- an omitted raw `getpid` receives `-EPERM`;
- malformed policies, unknown syscalls, invalid scratch declarations, and policies without an authorized termination syscall are rejected;
- setup failure never retries or executes the target unrestricted;
- a deliberately inheritable high descriptor is absent after target exec;
- a raw target with all three stdio descriptors declared `closed` observes `EBADF` for 0, 1, and 2;
- a raw target with only stdout declared `inherit` observes stdin/stderr as `EBADF` and successfully writes through fd 1;
- a missing shebang interpreter produces an `execveat` setup error without target `write` permission;
- executable symlink escape and host-path visibility escape attempts are rejected/hidden;
- namespace UID/GID 0 are visible while effective, permitted, inheritable, bounding, and ambient capability sets are empty;
- ordinary-root `O_CREAT` receives `EROFS`, while declared scratch remains writable and private from the host directory;
- environment, cwd, all four rlimits, `RLIMIT_NOFILE`, and `no_new_privs` are target-observable;
- exit code and signal termination remain distinct outcomes.

The probe is assembled with `cc -nostdlib -static`, so supported integration tests require a native Linux x86_64 C toolchain.

## Platform support

Real enforcement is implemented only for **Linux x86_64**. The boundary requires Linux support for `openat2`, `open_tree`, `mount_setattr`, `move_mount`, tmpfs mounts, `close_range(..., CLOSE_RANGE_CLOEXEC)`, user/mount namespaces, UID/GID maps, capability operations, seccomp, `execveat`, shared anonymous mappings, `fork`, and `waitpid`.

If mandatory namespace/mount primitives are unavailable or denied, launch returns an explicit unsupported/setup failure rather than dropping the boundary. CI enables the required user-namespace settings on its disposable Ubuntu 24.04 runner so the enforcement path is exercised rather than skipped.

## What this is not

This remains an educational sandbox, not a production container boundary. In particular:

- `inherit` is still an explicit decision to expose an existing parent pipe/socket/terminal/file handle; the sandbox does not confine the external object behind that handle;
- stdio redirection to newly owned files/pipes and deliberate selected descriptor passing >= 3 are not implemented yet;
- only one optional writable tmpfs scratch location is modeled; there is no general persistent bind/data-volume policy;
- root revalidation is a device/inode identity check, not an immutable or cryptographic snapshot of the whole subtree;
- PID, network, IPC, UTS, and cgroup namespaces are not created;
- there is no cgroup accounting, network endpoint allowlist, device namespace, or syscall argument filtering;
- supplementary groups are not claimed to be empty;
- later execution syscalls remain usable when explicitly granted;
- side-channel resistance and hostile same-UID debugger protection are out of scope;
- `RLIMIT_AS` is not cgroup-like physical-memory accounting, and `RLIMIT_FSIZE` does not cap pipe/terminal output.

See [THREAT_MODEL.md](THREAT_MODEL.md) for the full boundary and [ROADMAP.md](ROADMAP.md) for the next architectural frontier.

## Development

```bash
cargo fmt --all -- --check
cargo clippy --locked --all-targets --all-features -- -D warnings
cargo test --locked --all-targets --all-features
```

`Cargo.lock` is committed. CI pins action revisions, runs locked stable fmt/Clippy/tests, and separately executes the full locked suite on Rust 1.74.
