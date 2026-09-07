from pathlib import Path


def replace_one(path: str, old: str, new: str, label: str) -> None:
    p = Path(path)
    text = p.read_text()
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{label}: expected exactly one match, got {count}")
    p.write_text(text.replace(old, new, 1))


# README: seal integrated 29A and describe only implementation-backed 30A claims.
replace_one(
    "README.md",
    "The current Milestone 29A verified candidate adds **forbidden masked seccomp argument patterns**: a matching raw 64-bit bit pattern is denied with `EPERM`, while non-matching values continue through the existing conjunctive masked-equality/range checks.",
    "Milestone 29A added **forbidden masked seccomp argument patterns**: a matching raw 64-bit bit pattern is denied with `EPERM`, while non-matching values continue through the existing conjunctive masked-equality/range checks. The current Milestone 30A verified candidate adds an optional **bounded ephemeral copy-on-write root**: the trusted launcher keeps the pinned lower tree recursively read-only, overlays it with private bounded tmpfs-backed upper/work state, and discards target-side root mutations with the mount namespace instead of writing them through to the host lower tree.",
    "README milestone summary",
)
replace_one(
    "README.md",
    "Optional `filesystem.proc = enabled|disabled`, read-only or writable volume source/target pairs,",
    "Optional `filesystem.proc = enabled|disabled`, `filesystem.cow_root_bytes`, read-only or writable volume source/target pairs,",
    "README policy list",
)
replace_one(
    "README.md",
    "recursively clones it, applies recursive `MOUNT_ATTR_RDONLY`, and attaches it only inside the private mount namespace.",
    "recursively clones it and always applies recursive `MOUNT_ATTR_RDONLY` to that lower tree. By default the launcher attaches the read-only clone directly. When `filesystem.cow_root_bytes` is declared, it instead creates a private size-bounded tmpfs backing store, prepares `upper`/`work` directories there, constructs an OverlayFS merged mount with the read-only clone as `lowerdir`, and attaches that merged mount as the final root. The tmpfs backing mount is `nosuid,nodev,noexec`; this is not a claim that the merged root is globally `noexec`.",
    "README root construction",
)
replace_one(
    "README.md",
    "private-mount, read-only-root, chroot, FD-sanitization",
    "private-mount, exactly one final-root mode (read-only-root by default or copy-on-write-root when requested), chroot, FD-sanitization",
    "README receipt summary",
)
replace_one(
    "README.md",
    "- The target receives user/mount/PID/network/IPC/UTS namespace isolation, private mount propagation, a recursively read-only root, chroot/cwd selection, capability clearing, `no_new_privs`, rlimits, and default-deny seccomp.\n",
    "- The target receives user/mount/PID/network/IPC/UTS namespace isolation, private mount propagation, chroot/cwd selection, capability clearing, `no_new_privs`, rlimits, and default-deny seccomp. The default final root remains recursively read-only; an explicit `filesystem.cow_root_bytes` policy widens only target-side root pathname mutation into private ephemeral OverlayFS state while keeping the host lower tree read-only.\n- Copy-on-write root state is bounded to 4 KiB–1 GiB by policy, lives in a private tmpfs upper/work layer, and disappears with the sandbox mount namespace. Declared read-only persistent volumes are attached after final-root construction and remain read-only even when COW root is enabled; writable persistent volumes remain the separate explicit persistence authority.\n",
    "README COW invariant",
)
replace_one(
    "README.md",
    "## Test evidence\n\nLinux x86_64 integration tests prove that:\n\n",
    "### Ephemeral copy-on-write root\n\n`filesystem.cow_root_bytes = <bytes>` is an optional final-root mode with a validated range of 4096 through 1 GiB. Without it, the existing recursively read-only root behavior is unchanged. With it, the launcher still pins/revalidates and recursively marks the lower tree read-only, then uses Linux `fsopen`/`fsconfig`/`fsmount` plus `move_mount` to assemble a private OverlayFS root over a bounded tmpfs upper/work layer. Preflight deliberately reports this request as `unprobed` because real user/mount-namespace execution is required; the authority manifest records the declared byte budget, authority-delta treats enabling or enlarging the COW layer as widening, and the runtime receipt/completeness gate require `copy_on_write_root` instead of `readonly_root` for that policy. This is ephemeral mutation authority only: it is not a persistent snapshot, export format, transaction layer, durability guarantee, or cryptographic lower-tree integrity proof.\n\n## Test evidence\n\nLinux x86_64 integration tests prove that:\n\n- a raw target under COW root overwrites an existing lower file, creates a new root file, removes a lower pathname from its merged view, and observes the changed merged state; after two independent runs the trusted parent proves the original host-lower bytes are unchanged and the new file never persisted there;\n- COW root composes with the existing private scratch layer and with a declared read-only persistent volume: the latter still returns exact `EROFS` on mutation, its host marker remains byte-for-byte unchanged, and the runtime receipt reports `copy_on_write_root=true` with `readonly_root=false`;\n- the raw fixture dispatch table is checked for unique one-byte mode selectors, preventing a future milestone from silently reusing the same assembly oracle dispatch byte;\n",
    "README COW evidence section",
)

# Threat model: make the opt-in authority widening and its non-goals explicit.
replace_one(
    "THREAT_MODEL.md",
    "The current Milestone 29A verified candidate adds forbidden masked numeric seccomp predicates that deny a selected bit pattern without widening the underlying syscall allowlist.",
    "Milestone 29A added forbidden masked numeric seccomp predicates that deny a selected bit pattern without widening the underlying syscall allowlist. The current Milestone 30A verified candidate adds an explicitly requested ephemeral copy-on-write final root whose host lower tree remains recursively read-only while target-side root mutations are redirected into private bounded OverlayFS upper/work state.",
    "threat purpose",
)
replace_one(
    "THREAT_MODEL.md",
    "- **Filesystem mutability/path boundary:** the revalidated root is recursively cloned/read-only, optional scratch is private `nosuid,nodev,noexec` tmpfs, and the target is chrooted into the constructed root.\n",
    "- **Filesystem mutability/path boundary:** the revalidated host root is always recursively cloned/read-only. Without COW policy that clone is the final root. With `filesystem.cow_root_bytes`, the launcher constructs a private OverlayFS merged root over that read-only lower using size-bounded tmpfs upper/work state; root mutations then affect only the sandbox mount namespace. Optional scratch remains a separate private `nosuid,nodev,noexec` tmpfs, and the target is chrooted only after final mount construction. The COW backing tmpfs is `nosuid,nodev,noexec`, but the merged root is not claimed globally `noexec`.\n- **COW root evidence boundary:** the runtime receipt publishes exactly one of `readonly_root` or `copy_on_write_root` according to the requested final-root mode, and the receipt-completeness gate rejects the wrong or simultaneous mode. Static preflight leaves COW support `unprobed`; only a real run can produce positive enforcement evidence.\n",
    "threat COW property",
)
replace_one(
    "THREAT_MODEL.md",
    "## Explicit non-goals and limitations\n\nThis sandbox is **not** a production multi-tenant container boundary. It does not provide:\n\n",
    "## Explicit non-goals and limitations\n\nThis sandbox is **not** a production multi-tenant container boundary. Milestone 30A does not turn OverlayFS into a persistence or snapshot subsystem: target-side COW changes disappear with the mount namespace, and there is no export/commit operation, transaction/atomicity/durability guarantee, immutable or cryptographic snapshot, alias-proof subtree identity, or guarantee for special/network filesystems beyond the tested Linux behavior.\n\nIt does not provide:\n\n",
    "threat COW non-goals",
)
replace_one(
    "THREAT_MODEL.md",
    "- The policy author is trusted to choose filesystem exposure, including any declared read-only or writable host-volume source/target;",
    "- The policy author is trusted to choose filesystem exposure, including whether to widen the default read-only root into bounded ephemeral COW-root mutation authority and any declared read-only or writable host-volume source/target;",
    "threat COW trust",
)

# Roadmap: seal 29A and promote the independent executable filesystem frontier.
replace_one(
    "ROADMAP.md",
    "**Current verified candidate.** Adds a negative raw-argument predicate that cannot be expressed by the existing single conjunctive masked-equality/range rule families without enumerating allowed alternatives.",
    "**Status: complete on `main`.** Adds a negative raw-argument predicate that cannot be expressed by the existing single conjunctive masked-equality/range rule families without enumerating allowed alternatives.",
    "roadmap 29A status",
)
replace_one(
    "ROADMAP.md",
    "## Later frontiers\n\nSupplementary-group isolation with a viable mapping architecture, broader/generalized persistent-volume policy, routed/broader network authority beyond the bounded IPv4 brokers, generalized host-local IPC authority beyond the exact-path/peer-credential broker, and delegated aggregate cgroup accounting remain separate evidence-backed frontiers. Do not add configuration-only names without executable kernel behavior and integration evidence.\n",
    "## Milestone 30 — ephemeral filesystem mutation\n\n### Slice 30A — bounded copy-on-write root\n\n**Current verified candidate.** Adds one materially different filesystem authority mode: policy may explicitly widen the default recursively read-only root into bounded, private, ephemeral target-side mutation without granting host-lower write-through authority.\n\nAcceptance evidence is executable:\n\n- `filesystem.cow_root_bytes` is optional and fail-closed validated from 4096 bytes through 1 GiB; absence preserves the existing read-only-root behavior;\n- the launcher pins/revalidates the configured root, recursively clones and marks the lower tree read-only, then for COW mode creates a size-bounded private tmpfs backing mount, `upper`/`work` directories, and an OverlayFS merged mount through `fsopen`/`fsconfig`/`fsmount`, finally attaching it with `move_mount`; every construction phase has explicit launch-error reporting and no writable-host-root fallback;\n- the backing tmpfs receives `nosuid,nodev,noexec`; the project does not claim that the merged OverlayFS root itself is globally `noexec`;\n- a raw target modifies, creates, and removes paths in the merged root while the trusted parent proves the original lower marker remains byte-for-byte unchanged and no new file persists across two independent runs;\n- the existing private scratch mount composes above the COW root, and an explicit read-only persistent volume attached afterward still returns `EROFS` on mutation and leaves its host source unchanged;\n- the runtime enforcement receipt publishes `copy_on_write_root` only after final OverlayFS attachment and rejects simultaneous `readonly_root`; the runtime receipt-completeness gate binds the required final-root bit to policy;\n- static preflight reports requested COW support as `unprobed` because the real user/mount namespace is required, the authority manifest records its byte budget, and authority-delta classifies enabling or enlarging COW authority as widening;\n- fixture dispatch selectors are regression-checked for uniqueness; stable rustfmt/Clippy/full tests and the full Rust 1.74 suite are green on the exact implementation head.\n\nBoundary: 30A is ephemeral root mutation only. It does not provide persistence, export/commit, snapshots, copy-on-write image management, transaction/atomicity/durability semantics, immutable/cryptographic lower-tree identity, or generalized OverlayFS policy.\n\n### Milestone 30 promotion rule\n\nAfter 30A integrates, do not farm byte-ceiling variants, extra upper/work directory names, or repeated mutation path oracles. A later filesystem slice must add materially different executable semantics such as a real bounded export/snapshot/diff lifecycle with integrity evidence; otherwise promote to another independent authority/enforcement frontier.\n\n## Later frontiers\n\nSupplementary-group isolation with a viable mapping architecture, broader/generalized persistent-volume policy, routed/broader network authority beyond the bounded IPv4 brokers, generalized host-local IPC authority beyond the exact-path/peer-credential broker, and delegated aggregate cgroup accounting remain separate evidence-backed frontiers. Do not add configuration-only names without executable kernel behavior and integration evidence.\n",
    "roadmap 30A section",
)
