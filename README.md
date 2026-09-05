# security-lab

`security-lab` is a correctness-first systems-security laboratory. Milestone 1 established a bounded Linux process sandbox; Milestones 2A and 2B removed inherited non-stdio descriptor leakage and replaced the standard-library launch transition with an owned error protocol; Milestone 2C added a real filesystem/identity boundary. The current Milestone 2D candidate adds an enforceable recursively read-only root plus an optional private writable scratch mount. The project is **not** a penetration-testing toolkit, malware framework, container runtime, or production multi-tenant isolation boundary.

## Current sandbox pipeline

The Linux x86_64 implementation launches exactly one child from an explicit policy:

1. **Policy validation** (`src/policy.rs`) requires a host `filesystem.root`, a sandbox-internal absolute executable path, a sandbox-internal absolute working directory, resource limits, environment entries, and a syscall allowlist. An optional writable scratch requires both `filesystem.scratch` and `filesystem.scratch_bytes`; malformed, incomplete, overlapping, or oversized scratch declarations fail closed.
2. **Parent preparation** pins the root directory, working directory, and initial executable before `fork`. `openat2` rejects symlink traversal; executable/cwd/scratch resolution is constrained beneath the pinned root and may not cross a mount point. The target inode is retained as a file descriptor for `execveat(AT_EMPTY_PATH)`.
3. **Owned child filesystem setup** creates user and mount namespaces, maps namespace UID/GID 0 to the launching effective UID/GID, makes mount propagation private, reopens the configured root in the child's mount namespace and verifies its device/inode identity against the pre-fork root pin. It recursively clones that current-namespace root with `open_tree`, applies recursive `MOUNT_ATTR_RDONLY`, and attaches the clone only inside the private mount namespace.
4. **Optional writable scratch** overlays the declared sandbox path with a private tmpfs after the root tree is read-only. The tmpfs is bounded by the policy size and mounted `nosuid,nodev,noexec`. With no scratch declaration, the target receives no policy-created writable filesystem area.
5. **Remaining child setup** rejects directory-valued stdio handles, enters the read-only root with `chroot`, re-pins and selects the cwd from that root, sanitizes inherited non-stdio descriptors, applies rlimits, drops capability sets, enables `no_new_privs`, and installs seccomp.
6. **Pinned execution** uses `execveat` on the pre-opened executable descriptor. The initial executable identity therefore does not depend on re-resolving its pathname after validation.
7. **Owned error/result reporting** transports pre-exec phase+errno through a pre-fork shared anonymous page and waits with `waitpid`. Error reporting does not require a target `write(2)` grant; normal exits and signal deaths remain distinct.
8. **Deterministic tests** use a statically linked raw-syscall x86_64 probe, avoiding hidden libc/Rust-runtime syscall requirements.

## Security invariants

For a successful `run(policy)` on a supported Linux x86_64 kernel:

- `filesystem.root` is pinned without following symlinks. The configured executable, cwd and optional scratch path are absolute paths **inside that root** and are opened with `RESOLVE_BENEATH | RESOLVE_NO_XDEV | RESOLVE_NO_MAGICLINKS | RESOLVE_NO_SYMLINKS` where applicable.
- After entering a new mount namespace, the root pathname is reopened there and its `(st_dev, st_ino)` is compared with the pre-fork pinned root. A mismatch fails closed instead of silently cloning a different root object.
- The initial executable inode is pinned before `fork` and started with `execveat(..., AT_EMPTY_PATH)`, closing the initial-target pathname TOCTOU gap.
- The child creates user and mount namespaces. Namespace UID/GID 0 map only to the launching process's effective UID/GID; this is namespace root, not host root.
- Mount propagation is made private before the sandbox mount tree is constructed.
- The selected root mount tree is recursively cloned and then recursively marked read-only before target execution. Ordinary target creates/writes therefore cannot modify that root through pathname access.
- If `filesystem.scratch` is present, exactly that declared location is overlaid with a private tmpfs whose maximum size is `filesystem.scratch_bytes`; it is mounted `nosuid,nodev,noexec`. Scratch contents do not propagate back into the corresponding host directory.
- The target starts after `chroot` to the constructed root and `fchdir` to a cwd re-pinned from that root. Absolute pathname lookup from the target therefore starts inside the selected root.
- Any stdio descriptor that is itself a directory is rejected before target exec, preventing a retained directory handle from being used to escape the chroot with `fchdir`.
- Every inherited descriptor numbered 3 or higher is marked `CLOEXEC` before target exec and cannot survive a successful exec. Non-directory descriptors 0/1/2 remain intentionally inherited.
- The capability bounding set is dropped, ambient capabilities are cleared, and effective/permitted/inheritable capability sets are zeroed before target exec.
- `RLIMIT_CPU`, `RLIMIT_AS`, `RLIMIT_FSIZE`, and `RLIMIT_NOFILE` soft/hard limits are set to policy values.
- `PR_SET_NO_NEW_PRIVS=1` is set before target exec.
- Seccomp-BPF checks the x86_64 audit architecture, allows only policy-named syscalls, and returns `EPERM` for other x86_64 syscalls. The policy must authorize `execveat` plus `exit` or `exit_group`; the launcher does not add hidden management syscalls to the target filter.
- Inherited environment variables are not passed; target `envp` contains only policy entries.
- Setup/enforcement failures are never retried without restrictions. Missing required kernel enforcement is explicit rather than silently omitted.

## Policy format

`filesystem.root` is a host path selected by the trusted operator. `executable`, `working_dir`, and optional `filesystem.scratch` are absolute paths interpreted inside that root. Scratch path and byte ceiling must be specified together; scratch cannot replace the root or contain the executable/cwd, and its configured size is limited to 4 KiB–1 GiB.

```text
filesystem.root = /
# Optional private writable area; the directory must already exist in the root.
# filesystem.scratch = /var/tmp
# filesystem.scratch_bytes = 16777216
executable = /usr/bin/echo
arg = hello from the sandbox
working_dir = /tmp
env.LANG = C
limit.cpu_seconds = 2
limit.address_space_bytes = 536870912
limit.file_size_bytes = 1048576
limit.open_files = 32
seccomp.allow = execveat,read,write,close,fstat,lseek,mmap,mprotect,munmap,brk,rt_sigaction,rt_sigprocmask,rt_sigreturn,pread64,access,madvise,arch_prctl,set_tid_address,set_robust_list,prlimit64,getrandom,openat,newfstatat,exit,exit_group
```

`filesystem.root = /` still exposes the host pathname namespace to the sandbox, but the Milestone 2D mount tree presented to the child is read-only. Real path minimization requires a deliberately prepared smaller root containing only the executable and loader/libraries/data the target needs.

Run the included example with:

```bash
cargo run --bin security-lab -- run examples/policies/echo.conf
```

The CLI prints `sandbox-result: exited code=N` or `sandbox-result: signaled signal=N`. Policy/setup errors are printed as `sandbox-error: ...` and exit with status 125. Policy read/parse errors exit with status 2.

### Syscall policy behavior

The filter is installed before the pinned `execveat`, so a usable policy must allow `execveat`, at least one termination syscall (`exit` or `exit_group`), and every syscall required by the executed program and its loader. Unknown syscall names are rejected before launch; omitted syscalls receive `EPERM`.

The initial target is pinned, but the sandbox does **not** claim persistent executable allowlisting. If the target policy later grants `execve` or `execveat`, the target may use those syscalls again subject to the filesystem boundary and other Linux checks.

## Test evidence

Linux x86_64 integration tests prove that:

- an exact `execveat/write/exit` profile completes an allowed raw-syscall operation;
- an omitted raw `getpid` receives `-EPERM`;
- malformed policies, unknown syscalls, incomplete/overlapping scratch declarations, and policies without an authorized termination syscall are rejected;
- setup failure never retries or executes the target unrestricted;
- a deliberately inheritable high descriptor is absent after target exec;
- a missing shebang interpreter produces an `execveat` setup error without granting target `write`;
- a symlink inside the selected root pointing at `/bin/true` is rejected as an executable escape attempt;
- a host-only file outside the selected root returns `ENOENT` to the confined target;
- the target observes namespace UID/GID 0 while effective, permitted, inheritable, bounding, and ambient capability sets are empty;
- a raw target `O_CREAT` against the ordinary root receives `EROFS`, while the same target can create and write inside an explicitly declared scratch tmpfs;
- the parent observes that the private scratch write did not create the corresponding file in the host scratch directory;
- environment and sandbox cwd are controlled;
- all four configured rlimits are observable and `RLIMIT_NOFILE` produces `EMFILE` under pressure;
- `PR_GET_NO_NEW_PRIVS == 1` in the target;
- exit code and signal termination remain distinct outcomes.

The probe is assembled with `cc -nostdlib -static`, so supported integration tests require a native Linux x86_64 C toolchain.

## Platform support

Real enforcement is implemented only for **Linux x86_64**. The current candidate requires Linux support for `openat2`, `open_tree`, `mount_setattr`, `move_mount`, private tmpfs mounts, `close_range(..., CLOSE_RANGE_CLOEXEC)`, user and mount namespaces, UID/GID maps, capability operations, seccomp, `execveat`, shared anonymous mappings, `fork`, and `waitpid`.

If mandatory namespace/mount creation or the required detached/read-only mount operations are denied by the host policy, the launcher returns an explicit unsupported/setup failure rather than running without that boundary. Ubuntu 24.04 commonly restricts unprivileged user namespaces through AppArmor; CI explicitly enables the required user-namespace settings on its disposable runner so the enforcement path is actually exercised. That CI setup is not a runtime fallback or production guarantee.

## What this is not

This remains an educational sandbox, not a production container boundary. In particular:

- only one optional writable tmpfs scratch location is currently modeled; there is no general bind/data-volume policy or persistent writable storage policy;
- root revalidation compares the selected root directory's device/inode identity, but does not freeze or authenticate the entire host-side subtree before the private recursive clone is made;
- PID, network, IPC, UTS and cgroup namespaces are not created;
- there is no cgroup accounting, device namespace, network endpoint allowlist, or syscall argument filtering;
- non-directory stdio descriptors 0/1/2 remain inherited and may already reference data, pipes, sockets, terminals, or files outside the selected root;
- no policy exists yet for intentionally passing selected non-stdio descriptors;
- supplementary groups are not claimed to be cleared; the unprivileged GID-mapping flow disables future `setgroups` and maps only the configured primary GID;
- a policy that grants later execution syscalls can still launch another executable visible inside the root;
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
