# security-lab

`security-lab` is a correctness-first systems-security laboratory. Milestone 1 established a deliberately small Linux process sandbox; Milestone 2A removes inherited non-stdio file descriptors as ambient authority. The project is **not** a penetration-testing toolkit, malware framework, container runtime, or production isolation boundary.

## Current sandbox pipeline

The sandbox launches exactly one child process described by an explicit policy. The architecture is intentionally split into layers:

1. **Policy layer** (`src/policy.rs`) parses and validates a platform-neutral policy representation. Unknown keys, duplicate singleton keys, missing required security fields, malformed environment names, relative executable/cwd paths, and malformed syscall names fail closed.
2. **Sandbox setup layer** (`src/platform/linux.rs`) preflights the executable/cwd, marks every inherited descriptor above stderr close-on-exec, applies resource limits, sets Linux `PR_SET_NO_NEW_PRIVS`, and installs a seccomp-BPF filter.
3. **Child execution** starts the exact executable and argument vector from the policy. The environment is cleared and rebuilt only from policy entries; the working directory is fixed by policy.
4. **Result reporting** (`src/report.rs`) distinguishes normal exit codes from signal termination. Setup/enforcement failures are returned as errors and never trigger an unrestricted retry.
5. **Tests** use a statically linked, raw-syscall x86_64 fixture (`tests/fixtures/probe.S`) so each security test has a small, auditable syscall profile rather than depending on hidden glibc/Rust-runtime startup behavior.

## Security invariants

For a successful `run(policy)` on a supported Linux x86_64 kernel:

- The **initial child launch** uses exactly the executable path and argv in the validated policy; callers cannot override them at launch time.
- The inherited environment is discarded before the child starts. Only explicitly listed variables are restored.
- The child starts in the policy's absolute working directory.
- Every inherited file descriptor numbered 3 or higher is atomically marked `CLOEXEC` in the post-fork child and therefore does not survive a successful exec into the target. Standard input/output/error (0, 1, 2) remain intentionally inherited.
- `RLIMIT_CPU`, `RLIMIT_AS`, `RLIMIT_FSIZE`, and `RLIMIT_NOFILE` soft and hard limits are set to the policy values before `execve`.
- `PR_SET_NO_NEW_PRIVS=1` is set before `execve`, preventing later exec from gaining privilege through set-user-ID/set-group-ID bits or file capabilities.
- A classic seccomp-BPF filter checks the x86_64 audit architecture, allows only named syscalls in the policy, and returns `EPERM` for every other syscall.
- If architecture checking fails, the process is killed rather than executing under a filter compiled for the wrong ABI.
- Unknown Linux x86_64 syscall names are rejected before the child executes.
- If preflight, inherited-FD sanitization, rlimit, `no_new_privs`, seccomp installation, or launch setup fails, execution is not retried without restrictions.
- Unsupported operating systems, architectures, or kernels missing required enforcement primitives return an explicit `UnsupportedPlatform` error; they are never reported as successfully sandboxed.

Descriptor sanitization uses `close_range(3, UINT_MAX, CLOSE_RANGE_CLOEXEC)` rather than eagerly closing descriptors. This is deliberate: Rust's process launcher keeps a private child-error descriptor during setup, and `CLOEXEC` preserves that channel until a successful exec while still guaranteeing that arbitrary inherited descriptors do not enter the target image.

## Policy format

The parser is intentionally small and strict. It does not support includes, interpolation, shell expansion, or ignored extension keys.

```text
executable = /bin/echo
arg = hello from the sandbox
working_dir = /tmp
env.LANG = C
limit.cpu_seconds = 2
limit.address_space_bytes = 536870912
limit.file_size_bytes = 1048576
limit.open_files = 32
seccomp.allow = execve,read,write,close,fstat,lseek,mmap,mprotect,munmap,brk,rt_sigaction,rt_sigprocmask,rt_sigreturn,pread64,access,madvise,arch_prctl,set_tid_address,set_robust_list,prlimit64,getrandom,openat,newfstatat,exit,exit_group
```

Run it with:

```bash
cargo run --bin security-lab -- run examples/policies/echo.conf
```

The CLI prints `sandbox-result: exited code=N` or `sandbox-result: signaled signal=N`. Policy/setup errors are printed as `sandbox-error: ...` and exit with status 125. Policy read/parse errors exit with status 2.

### Syscall policy behavior

The sandbox deliberately uses an allowlist, not a denylist. The filter is installed before the initial `execve`, so a usable policy must allow `execve` and every syscall needed by the target program and, for dynamically linked programs, its loader. Unknown syscall names are rejected by the Linux x86_64 enforcement layer before launch. Any syscall not on the allowlist receives `EPERM`.

Because `execve` must be allowed for the initial transition into the target image, the sandbox does **not** claim that the target is unable to perform a later `execve`. The launcher controls the initial executable/argv; persistent executable-identity confinement requires a stronger mechanism than this syscall-number-only filter.

This policy is intentionally unforgiving: if a binary needs a syscall that was not granted, the correct outcome is failure, not silent widening of the policy.

## Test evidence

Linux x86_64 integration tests prove that:

- an `execve/write/exit` profile can complete an allowed operation;
- raw `getpid` receives `-EPERM` when it is absent from the allowlist;
- malformed policy and unknown syscall names are rejected;
- an invalid working directory prevents child execution and never falls back to an unrestricted launch;
- a deliberately inheritable descriptor is absent after target exec;
- an exec failure is still reported as setup failure after descriptor sanitization when the policy permits the launcher's error-write syscall;
- exit code 42 and SIGTERM termination are reported distinctly;
- inherited `PATH` is absent while an explicitly granted environment variable is present;
- the child observes the configured working directory;
- all four configured rlimits can be read back with the expected soft/hard values, and `RLIMIT_NOFILE` produces `EMFILE` under pressure;
- the child observes `PR_GET_NO_NEW_PRIVS == 1`.

The fixture is assembled during the supported integration tests with the system `cc` using `-nostdlib -static`; it contains no libc or Rust runtime. A native Linux x86_64 C toolchain is therefore required to run those integration tests locally.

## Platform support

Real enforcement is implemented only for **Linux x86_64**. Milestone 2A additionally requires kernel support for `close_range(..., CLOSE_RANGE_CLOEXEC)` (available on modern Linux kernels; the flag was added in Linux 5.11). Missing support is reported explicitly rather than silently omitting descriptor sanitization. Tests that require Linux enforcement are compiled only on the supported target and CI runs them on Ubuntu Linux.

## What this is not

This sandbox does **not** claim container-grade isolation. In particular, it does not create user/mount/PID/network namespaces, a new root filesystem, bind-mount policy, Landlock rules, cgroups, capability bounding-set management, network policy, filesystem path allowlists, device isolation, or protection from a hostile same-UID parent/debugger. `working_dir` changes the starting directory; it is not filesystem confinement. Standard descriptors 0/1/2 remain inherited, and there is not yet an explicit safe descriptor-passing policy for intentionally shared handles. The sandbox also does not prevent a policy that permits `execve` from using that syscall again after the initial launch.

See [THREAT_MODEL.md](THREAT_MODEL.md) for the complete threat model and limitations.

## Development

```bash
cargo fmt --all -- --check
cargo clippy --locked --all-targets --all-features -- -D warnings
cargo test --locked --all-targets --all-features
```

`Cargo.lock` is committed. CI pins its action revisions, runs the locked quality/test suite on stable Rust, and separately runs the full locked test suite on the declared Rust 1.74 MSRV.
