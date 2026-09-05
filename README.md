# security-lab

`security-lab` is a correctness-first systems-security laboratory. Milestone 1 established a bounded Linux process sandbox; Milestones 2A–2F-A added inherited-FD minimization, an owned launch/error protocol, filesystem/identity isolation, a recursively read-only root with bounded private scratch, explicit standard-descriptor disposition, and launcher-owned stdout redirection. The current Milestone 2F-B candidate adds **bounded launcher-owned stdout capture** with an explicit retained-byte ceiling and truncation reporting. The project is **not** a penetration-testing toolkit, malware framework, container runtime, or production multi-tenant isolation boundary.

## Current sandbox pipeline

The Linux x86_64 implementation launches exactly one direct child from an explicit policy:

1. **Policy validation** requires a host `filesystem.root`, sandbox-internal executable/cwd paths, explicit stdio disposition, resource limits, environment entries, and a syscall allowlist. Optional scratch, stdout redirection, and stdout capture have paired fail-closed fields.
2. **Parent preparation** pins the root, cwd, and initial executable before `fork`. `openat2` rejects symlink/magic-link traversal and constrains configured paths beneath the selected root. The target inode is retained for `execveat(AT_EMPTY_PATH)`.
3. **Owned child filesystem setup** creates user and mount namespaces, maps namespace UID/GID 0 to the launching effective UID/GID, makes mount propagation private, revalidates the selected root by `(st_dev, st_ino)`, recursively clones it, applies recursive `MOUNT_ATTR_RDONLY`, and attaches it only inside the private mount namespace.
4. **Optional writable scratch** overlays one declared sandbox directory with a bounded private `nosuid,nodev,noexec` tmpfs.
5. **Owned stdout redirection** optionally opens `stdio.stdout_path` only after that private scratch exists. The path must be strictly beneath scratch; launcher-only `openat2`/`fcntl`/`dup2` operations occur before target seccomp installation.
6. **Bounded stdout capture** optionally creates a pre-fork `pipe2(O_CLOEXEC)`. Both pipe ends are normalized above fd 2 before `fork`. The child closes the read end, preserves the write source through setup, then maps only that source to fd 1. The parent closes its write end and drains stdout **before `waitpid`**, retains no more than the policy ceiling, discards excess bytes, and reports `truncated = true` when output exceeds that ceiling.
7. **Descriptor authority and remaining setup** marks arbitrary inherited descriptors >= 3 `CLOEXEC`, applies stdio, then applies rlimits, capability reduction, `no_new_privs`, and seccomp. Temporary launcher-owned redirect/capture sources are closed after remapping and do not survive as extra target descriptors.
8. **Pinned execution and reporting** uses `execveat` on the pinned target. Pre-exec failure phase+errno travels through shared anonymous memory. `run_report()` returns terminal status plus captured stdout when configured; the compatibility `run()` path still drains capture safely and returns only `ChildOutcome`.
9. **Deterministic tests** use a statically linked raw-syscall x86_64 probe so syscall grants and observed behavior remain reviewable.

## Security invariants

For successful launch on a supported Linux x86_64 host:

- Initial target, cwd, scratch, and stdout-redirection paths are fail-closed and bounded by the selected filesystem root.
- The child receives user/mount namespace isolation, private mount propagation, a recursively read-only root, chroot/cwd selection, capability clearing, `no_new_privs`, rlimits, and default-deny seccomp.
- Arbitrary inherited descriptors >= 3 do not survive successful target exec.
- stdin/stderr support explicit `inherit` or `closed`. stdout supports `inherit`, `closed`, `redirect`, or `capture`; there is no implicit stdio default.
- `inherit` requires the existing descriptor to be present and not a directory. `closed` leaves the target descriptor closed.
- `redirect` is launcher-owned and may target only a file strictly beneath private scratch; its temporary source stays `CLOEXEC`, is mapped only to fd 1, then closed.
- `capture` is launcher-owned and uses a new pipe, not an arbitrary parent descriptor. The target receives the pipe only as fd 1; no extra capture descriptor >= 3 survives exec.
- `stdio.stdout_capture_bytes` bounds **retained parent memory**, from 1 byte through 16 MiB. It does not cap the amount the target may emit: excess bytes are actively drained and discarded so ordinary pipe-buffer pressure does not deadlock the direct child.
- Launcher management syscalls used for namespaces, mounts, redirection, capture, remapping, and setup are not silently added to the target seccomp allowlist.
- Setup failure never causes an unrestricted retry.

## Policy format

Standard-descriptor modes are:

- `inherit`: retain the corresponding existing parent descriptor;
- `closed`: target starts with the descriptor closed;
- `redirect`: stdout only; requires `stdio.stdout_path` strictly beneath `filesystem.scratch`;
- `capture`: stdout only; requires `stdio.stdout_capture_bytes` in the range 1–16 MiB.

Example using bounded capture:

```text
filesystem.root = /
filesystem.scratch = /var/tmp
filesystem.scratch_bytes = 16777216
executable = /usr/bin/echo
arg = hello from the sandbox
working_dir = /tmp
env.LANG = C
stdio.stdin = closed
stdio.stdout = capture
stdio.stdout_capture_bytes = 65536
stdio.stderr = inherit
limit.cpu_seconds = 2
limit.address_space_bytes = 536870912
limit.file_size_bytes = 1048576
limit.open_files = 32
seccomp.allow = execveat,read,write,close,fstat,lseek,mmap,mprotect,munmap,brk,rt_sigaction,rt_sigprocmask,rt_sigreturn,pread64,access,madvise,arch_prctl,set_tid_address,set_robust_list,prlimit64,getrandom,openat,newfstatat,exit,exit_group
```

Library callers that need captured bytes use `run_report()`:

```rust
let report = security_lab::run_report(&policy)?;
if let Some(stdout) = report.stdout {
    // stdout.bytes contains at most the declared ceiling.
    // stdout.truncated says whether additional bytes were discarded.
}
```

The CLI currently uses the status-only `run()` API, so a policy configured for capture is still drained safely but captured bytes are discarded by the CLI rather than printed back.

## Test evidence

Linux x86_64 integration tests prove that:

- exact allowed/denied syscall profiles behave as declared and an omitted `getpid` receives `EPERM`;
- malformed policies, unknown syscalls, invalid scratch/redirection/capture declarations, and missing mandatory launch syscalls fail closed;
- an intentionally inheritable high descriptor is absent after target exec;
- all-closed and selective-inherit stdio behave exactly as declared;
- owned stdout redirection is writable/readable inside private scratch while the corresponding host scratch path remains absent;
- bounded stdout capture returns the exact small raw-syscall output with `truncated = false`;
- a raw target emits **256 KiB** through stdout with a **1 KiB retention ceiling**; the parent returns exactly 1 KiB, marks `truncated = true`, and the child exits successfully, demonstrating that excess output is drained rather than allowed to fill the pipe and block the child;
- filesystem visibility/mutability, namespace identity/capability reduction, environment/cwd, all four rlimits, `RLIMIT_NOFILE`, `no_new_privs`, launch-error reporting, and exit-vs-signal regressions remain active.

The probe is assembled with `cc -nostdlib -static`, so supported integration tests require a native Linux x86_64 C toolchain.

## Platform support

Real enforcement is implemented only for **Linux x86_64**. Required mechanisms include `openat2`, `open_tree`, `mount_setattr`, `move_mount`, tmpfs, user/mount namespaces, UID/GID maps, capability operations, `close_range(..., CLOSE_RANGE_CLOEXEC)`, `pipe2`, `dup2`, seccomp, `execveat`, shared anonymous mappings, `fork`, and `waitpid`.

If mandatory namespace/mount/kernel primitives are unavailable or denied, launch returns an explicit unsupported/setup failure rather than dropping the boundary. CI enables the required user-namespace settings on its disposable Ubuntu runner so the enforcement path is exercised rather than skipped.

## What this is not

This remains an educational sandbox, not a production container boundary. In particular:

- `inherit` intentionally exposes an existing parent pipe/socket/terminal/file handle; the object behind that handle is not further confined by this policy layer;
- only stdout has launcher-owned redirect/capture modes; stdin/stderr redirection/capture are not implemented;
- the capture ceiling bounds retained bytes, not total bytes the target can write;
- capture completion follows EOF of the launcher-owned pipe. If a target policy later permits process creation and a descendant retains stdout, `run_report()` can remain in the drain phase until **all** writers close the pipe; the sandbox does not yet claim direct-child-only process-tree completion;
- deliberate selected non-stdio descriptor passing is not implemented; a general arbitrary FD-remapping language is intentionally deferred;
- PID, network, IPC, UTS, and cgroup namespaces are not yet created;
- there is no cgroup accounting, network endpoint allowlist, device namespace, syscall argument filtering, or persistent data-volume policy;
- root revalidation is an identity check, not an immutable/cryptographic snapshot of the whole subtree;
- supplementary groups are not claimed to be empty, persistent executable allowlisting is not provided, and multi-architecture seccomp/side-channel resistance are out of scope;
- `RLIMIT_AS` is not cgroup-like physical-memory accounting, and `RLIMIT_FSIZE` does not limit pipe/terminal/captured output.

See [THREAT_MODEL.md](THREAT_MODEL.md) for the full boundary and [ROADMAP.md](ROADMAP.md) for phase promotion.

## Development

```bash
cargo fmt --all -- --check
cargo clippy --locked --all-targets --all-features -- -D warnings
cargo test --locked --all-targets --all-features
```

`Cargo.lock` is committed. CI pins action revisions, runs locked stable fmt/Clippy/tests, and separately executes the full locked suite on Rust 1.74.
