# security-lab

`security-lab` is a correctness-first systems-security laboratory. Milestone 1 established a bounded Linux process sandbox, Milestone 2A removed inherited non-stdio descriptors as ambient authority, and Milestone 2B owns the launch/error protocol instead of relying on the standard-library child-error pipe. The project is **not** a penetration-testing toolkit, malware framework, container runtime, or production isolation boundary.

## Current sandbox pipeline

The sandbox launches exactly one child process described by an explicit policy. The architecture is intentionally split into layers:

1. **Policy layer** (`src/policy.rs`) parses and validates a platform-neutral policy representation. Unknown keys, duplicate singleton keys, missing required security fields, malformed environment names, relative executable/cwd paths, and malformed syscall names fail closed.
2. **Parent preparation** (`src/platform/linux.rs`) preflights the executable/cwd, compiles seccomp, constructs NUL-terminated executable/argv/environment data, verifies required kernel primitives, and allocates a small shared launch-state page before `fork`.
3. **Owned child setup** performs only low-level operations after `fork`: `chdir`, inherited-FD sanitization, rlimits, `PR_SET_NO_NEW_PRIVS`, seccomp installation, and the initial `execve`. The target environment is built explicitly; inherited environment variables are not passed.
4. **Owned result/error reporting** waits with `waitpid`. Pre-exec and `execve` failures publish phase+errno into the shared page, so reporting does not depend on a target-granted `write(2)` syscall. Normal target exits and signals remain distinct outcomes.
5. **Tests** use a statically linked, raw-syscall x86_64 fixture (`tests/fixtures/probe.S`) so each security test has a small, auditable syscall profile rather than depending on hidden glibc/Rust-runtime startup behavior.

## Security invariants

For a successful `run(policy)` on a supported Linux x86_64 kernel:

- The **initial child launch** uses exactly the executable path and argv in the validated policy; callers cannot override them at launch time.
- The inherited environment is discarded. Only explicitly listed variables are placed in the target `envp`.
- The child changes to the policy's absolute working directory before target exec.
- Every inherited file descriptor numbered 3 or higher is atomically marked `CLOEXEC` in the post-fork child and therefore does not survive a successful exec into the target. Standard input/output/error (0, 1, 2) remain intentionally inherited.
- `RLIMIT_CPU`, `RLIMIT_AS`, `RLIMIT_FSIZE`, and `RLIMIT_NOFILE` soft and hard limits are set to the policy values before `execve`.
- `PR_SET_NO_NEW_PRIVS=1` is set before `execve`, preventing later exec from gaining privilege through set-user-ID/set-group-ID bits or file capabilities.
- A classic seccomp-BPF filter checks the x86_64 audit architecture, allows only named syscalls in the policy, and returns `EPERM` for every other syscall.
- The seccomp allowlist must name `execve` and at least one of `exit` or `exit_group`. The launcher uses one of those already-authorized termination syscalls if setup fails after filter installation; it does not add hidden syscalls to the filter.
- Child-side setup and `execve` errors are transported by ordinary stores into a pre-fork `MAP_SHARED|MAP_ANONYMOUS` record and are read only after `waitpid`. No launcher-management `write` permission is required from the target policy.
- If preflight, inherited-FD sanitization, rlimit setup, `no_new_privs`, seccomp installation, `fork`, `execve`, or waiting fails, execution is not retried without restrictions.
- Unsupported operating systems, architectures, or kernels missing required enforcement primitives return an explicit `UnsupportedPlatform` error; they are never reported as successfully sandboxed.

The shared launch-state mapping is a control-plane mechanism only. A successful `execve` replaces the child address space, so the target does not inherit that anonymous mapping. Arbitrary inherited non-stdio descriptors are still removed from the target by `CLOSE_RANGE_CLOEXEC`.

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

The sandbox deliberately uses an allowlist, not a denylist. The filter is installed before the initial `execve`, so a usable Linux x86_64 policy must allow `execve`, at least one termination syscall (`exit` or `exit_group`), and every syscall needed by the target program and, for dynamically linked programs, its loader. Unknown syscall names are rejected before launch. Any syscall not on the allowlist receives `EPERM`.

Because `execve` must be allowed for the initial transition into the target image, the sandbox does **not** claim that the target is unable to perform a later `execve`. The launcher controls the initial executable/argv; persistent executable-identity confinement requires a stronger mechanism than this syscall-number-only filter.

This policy is intentionally unforgiving: if a binary needs a syscall that was not granted, the correct outcome is failure, not silent widening of the policy.

## Test evidence

Linux x86_64 integration tests prove that:

- an `execve/write/exit` profile can complete an allowed operation;
- raw `getpid` receives `-EPERM` when it is absent from the allowlist;
- malformed policy, unknown syscall names, and a policy without an authorized termination syscall are rejected;
- an invalid working directory prevents child execution and never falls back to an unrestricted launch;
- a deliberately inheritable descriptor is absent after target exec;
- an executable whose shebang interpreter does not exist is reported as an `execve` setup failure with a policy containing only `execve` and `exit`—no `write` grant is needed for launcher error reporting;
- exit code 42 and SIGTERM termination are reported distinctly;
- inherited `PATH` is absent while an explicitly granted environment variable is present;
- the child observes the configured working directory;
- all four configured rlimits can be read back with the expected soft/hard values, and `RLIMIT_NOFILE` produces `EMFILE` under pressure;
- the child observes `PR_GET_NO_NEW_PRIVS == 1`.

The fixture is assembled during the supported integration tests with the system `cc` using `-nostdlib -static`; it contains no libc or Rust runtime. A native Linux x86_64 C toolchain is therefore required to run those integration tests locally.

## Platform support

Real enforcement is implemented only for **Linux x86_64**. Milestone 2A/2B require kernel support for `close_range(..., CLOSE_RANGE_CLOEXEC)`. Missing support is reported explicitly rather than silently omitting descriptor sanitization. The owned launch protocol uses Linux `fork`, shared anonymous `mmap`, seccomp, and `waitpid`; tests are compiled only on the supported target and CI runs them on Ubuntu Linux.

## What this is not

This sandbox does **not** claim container-grade isolation. In particular, it does not create user/mount/PID/network namespaces, a new root filesystem, bind-mount policy, Landlock rules, cgroups, capability bounding-set management, network policy, filesystem path allowlists, device isolation, or protection from a hostile same-UID parent/debugger. `working_dir` changes the starting directory; it is not filesystem confinement. Standard descriptors 0/1/2 remain inherited, and there is not yet an explicit safe descriptor-passing policy for intentionally shared handles. The sandbox also does not prevent a policy that permits `execve` from using that syscall again after the initial launch.

See [THREAT_MODEL.md](THREAT_MODEL.md) for the complete threat model and limitations, and [ROADMAP.md](ROADMAP.md) for the next filesystem/identity boundary.

## Development

```bash
cargo fmt --all -- --check
cargo clippy --locked --all-targets --all-features -- -D warnings
cargo test --locked --all-targets --all-features
```

`Cargo.lock` is committed. CI pins its action revisions, runs the locked quality/test suite on stable Rust, and separately runs the full locked test suite on the declared Rust 1.74 MSRV.
