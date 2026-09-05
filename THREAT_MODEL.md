# Milestones 1–2D threat model

## Purpose

`security-lab` is an educational, correctness-first Linux sandbox. Milestone 1 established syscall/resource/environment controls, 2A removed inherited non-stdio descriptor leakage, 2B made launch/error reporting an owned control-plane protocol, 2C added filesystem-path and process-identity isolation, and the current 2D candidate adds explicit filesystem mutability: a recursively read-only root with an optional bounded private writable scratch mount. Every claimed property must correspond to a kernel mechanism and executable evidence.

## Protected boundary

The trusted parent launches one child under a trusted policy. The target may be buggy or intentionally attempt operations outside its grant. On supported Linux x86_64, the launcher constrains initial filesystem visibility and mutability, namespace identity, capabilities, syscalls, selected resources, environment, working directory, and inherited non-stdio descriptors while preserving fail-closed launch reporting.

## Security properties claimed

- **Pinned root/cwd/target:** `filesystem.root` is opened without symlink traversal. Sandbox-internal executable, cwd and optional scratch paths are validated beneath that root with `openat2`; executable/cwd/scratch resolution rejects symlink or magic-link traversal and cross-mount resolution where applicable.
- **Current-mount root revalidation:** after creating the child mount namespace, the configured root pathname is reopened there and its `(st_dev, st_ino)` is compared with the pre-fork pinned root. A mismatch fails closed with `ESTALE`; the launcher does not silently clone a different root object.
- **Initial executable identity:** the executable inode is pinned before `fork` and launched with `execveat(AT_EMPTY_PATH)`. The initial transition does not re-resolve the executable pathname after validation.
- **User/mount namespace isolation:** the child creates new user and mount namespaces. Namespace UID/GID 0 map to the launching effective UID/GID only. Namespace root is not host root.
- **Private mount propagation:** mount propagation is made recursively private before the sandbox mount tree is constructed.
- **Recursively read-only root:** the revalidated current-namespace root is recursively cloned with `open_tree`, receives recursive `MOUNT_ATTR_RDONLY` with `mount_setattr`, and is attached only inside the private child mount namespace. Ordinary pathname writes/creates against that root are therefore denied by the mount boundary.
- **Explicit writable scratch:** policy may declare one scratch path plus a size ceiling. That existing directory is overlaid after root read-only setup with a private tmpfs mounted `nosuid,nodev,noexec` and bounded by `filesystem.scratch_bytes`. Scratch contents do not modify the corresponding host directory.
- **Filesystem path boundary:** the target is chrooted into the constructed root and switches to a cwd re-pinned from that mount tree. Absolute pathname resolution therefore starts inside the selected root.
- **Directory-FD escape prevention:** directory-valued stdio descriptors are rejected. Non-stdio inherited descriptors are marked `CLOEXEC`, so a successful target exec retains no arbitrary inherited descriptor >= 3.
- **Capability reduction:** capability bounding and ambient sets are cleared, and effective/permitted/inheritable sets are zeroed before target exec.
- **No privilege gain across exec:** `PR_SET_NO_NEW_PRIVS` is enabled before target exec.
- **Environment minimization:** inherited environment variables are not passed; only policy entries appear in target `envp`.
- **Resource ceilings:** configured CPU-time, address-space, regular-file-size and open-file limits are applied as both soft and hard rlimits.
- **Syscall least privilege:** classic seccomp-BPF validates the x86_64 audit architecture, permits only policy-named syscalls, and returns `EPERM` for other x86_64 syscalls. The initial transition requires policy-authorized `execveat` and at least one of `exit`/`exit_group`; launcher management syscalls are not secretly added to the target filter.
- **Owned launch-error reporting:** child setup errors publish a bounded phase plus errno to a pre-fork shared anonymous page. The parent reads it after `waitpid`, so post-seccomp failure reporting does not require target `write(2)` permission.
- **Fail-closed enforcement:** unsupported or failed mandatory enforcement never triggers an unrestricted retry.
- **Observable termination:** when no launch error is recorded, normal exit status and signal death are surfaced distinctly.

## Post-fork discipline

Potentially allocating data is prepared before `fork`: pinned descriptors, the root pathname C string, cwd/scratch C strings, tmpfs option string, UID/GID map strings, argv/envp arrays and the seccomp program. The child path is intentionally limited to direct libc/syscall operations and stack/local state. Reopening/revalidating the root, constructing the detached mount tree, mounting scratch, applying limits/capabilities and executing the target do not require policy-data allocation or a pipe-based launch protocol.

## Explicit non-goals and limitations

This sandbox is **not** a production multi-tenant container boundary. It does not provide:

- a cryptographic or immutable snapshot of the host-side root subtree. Root revalidation proves the selected root directory object matches by device/inode, but arbitrary non-pinned contents or mount topology may still change before the private recursive clone is made;
- a general writable-volume policy. Milestone 2D models at most one ephemeral tmpfs scratch area, not persistent bind/data volumes;
- PID, network, IPC, UTS or cgroup namespaces;
- cgroup-based aggregate memory/CPU/process accounting;
- a separate device namespace or network endpoint policy;
- syscall argument filtering;
- confinement of non-directory stdio handles. FDs 0/1/2 may intentionally retain pipes, sockets, terminals or file handles referring outside the selected root;
- a policy for intentionally passing selected non-stdio descriptors;
- a guarantee that inherited supplementary groups are empty. The unprivileged GID-map path writes `setgroups=deny` and maps the primary effective GID only;
- persistent executable allowlisting. The initial target is pinned, but a policy granting later `execve`/`execveat` may execute another path visible within the filesystem boundary;
- multi-architecture seccomp;
- protection from sufficiently privileged external ptrace/signal interference;
- side-channel resistance;
- physical-memory accounting equivalent to cgroups (`RLIMIT_AS` is an address-space ceiling);
- deterministic pipe/terminal output limits (`RLIMIT_FSIZE` applies to regular-file growth).

## Trust assumptions

- The Linux kernel and parent process are trusted.
- The policy author is trusted to choose `filesystem.root`, optional scratch location/size, target data, syscall grants and realistic resource ceilings.
- The selected root contains only content the operator intends the target to see. Choosing `/` intentionally provides no host-path hiding even though the private clone is made read-only for the child.
- The host-side root directory identity is meaningfully represented by `(st_dev, st_ino)` for the revalidation interval; this is not a subtree integrity proof.
- Non-directory stdio handles intentionally exposed by the parent are trusted ambient channels.
- The kernel correctly implements required `openat2`, `open_tree`, `mount_setattr`, `move_mount`, tmpfs, namespaces, UID/GID mapping, capability, `close_range`, seccomp and `execveat` semantics.

## Test strategy and evidence

The integration probe is statically linked with `-nostdlib` and uses raw Linux x86_64 syscalls, keeping each target policy small and auditable. CI executes the entire suite on both stable Rust and the declared Rust 1.74 MSRV.

Evidence includes:

- allowed and denied syscall profiles, including an omitted `getpid` returning `EPERM`;
- fail-closed malformed/unknown policy behavior and invalid scratch declarations;
- inherited high-FD non-leakage;
- owned `execveat` error reporting without target `write` permission;
- rejection of an executable symlink that points outside the selected root;
- an absolute host-only pathname outside the selected root returning `ENOENT` from the target;
- namespace UID/GID 0 plus zero effective, permitted, inheritable, bounding and ambient capability sets;
- a raw target `O_CREAT` against the ordinary root returning `EROFS`;
- the same target successfully creating/writing a file inside the explicitly declared scratch tmpfs;
- parent-side verification that the scratch file is absent from the corresponding host directory, proving the writable mount is private rather than a host write-through path;
- environment/cwd controls;
- all four rlimit readbacks and active `RLIMIT_NOFILE` enforcement;
- target-observed `no_new_privs`;
- exit-vs-signal reporting.

GitHub's Ubuntu 24.04 runner can restrict unprivileged user namespaces through AppArmor. CI explicitly enables the relevant user-namespace sysctls on the disposable runner so the namespace and mount enforcement path is executed rather than skipped. The runtime itself does not change host policy; inability to create mandatory namespaces or required mount primitives is reported explicitly.

## Failure semantics

Invalid policy is rejected before launch. Missing required kernel primitives or denied mandatory namespace/mount operations return explicit unsupported/setup failures. Child launch failures carry bounded phases, including root revalidation, detached root clone, recursive read-only attributes, root attachment, scratch mount, cwd pinning, capability reduction, seccomp and `execveat`. No failure path re-executes the target without the requested filesystem, identity, capability, descriptor, rlimit, `no_new_privs`, or seccomp boundary.

## Next hardening direction

After Milestone 2D integrates, the largest remaining ambient authority is **standard/intentional descriptor exposure**. The next architectural slice should make stdio disposition explicit and executable—such as inherited versus closed/redirected channels—without weakening the existing invariant that arbitrary inherited descriptors >= 3 do not survive target exec. Deliberate non-stdio descriptor passing, PID/process-tree isolation, network policy and stronger aggregate resource accounting should follow as separate evidence-backed frontiers rather than configuration-only names.
