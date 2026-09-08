from pathlib import Path


def replace_one(path: str, old: str, new: str, label: str) -> None:
    p = Path(path)
    text = p.read_text()
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{label}: expected exactly one match, got {count}")
    p.write_text(text.replace(old, new, 1))


replace_one(
    "README.md",
    "When `filesystem.cow_root_bytes` is declared, it instead creates a private size-bounded tmpfs backing store, prepares `upper`/`work` directories there, constructs an OverlayFS merged mount with the read-only clone as `lowerdir`, and attaches that merged mount as the final root. The COW backing tmpfs is `nosuid,nodev,noexec`, but the merged root is not claimed globally `noexec`.",
    "When `filesystem.cow_root_bytes` is declared, it instead creates a private size-bounded tmpfs backing store, prepares `upper`/`work` directories there, constructs an OverlayFS merged mount with the read-only clone as `lowerdir`, and attaches that merged mount as the final root. The launcher explicitly configures `metacopy=off` and `redirect_dir=nofollow` rather than inheriting host OverlayFS defaults: metadata-only changes therefore copy file data into the private upper tree, and lower/merged directory renames keep `EXDEV` semantics instead of being encoded through redirect xattrs that the diff contract does not export. The COW backing tmpfs is `nosuid,nodev,noexec`, but the merged root is not claimed globally `noexec`.",
    "README pinned OverlayFS semantics",
)
replace_one(
    "README.md",
    "- **Bounded COW diff contract:** `filesystem.cow_diff_bytes` is valid only with COW root mode and bounds the launcher's canonical exported record stream. `RunReport.cow_diff` / `run-json` expose supported file, directory, symlink, remove/whiteout, and opaque-directory changes. File/directory records preserve Unix permission bits (`st_mode & 0o7777`); ownership, timestamps, xattrs/ACLs, hard-link identity, device/FIFO/socket nodes, and a replay/commit executor remain outside the contract.",
    "- **Bounded COW diff contract:** `filesystem.cow_diff_bytes` is valid only with COW root mode and bounds the launcher's canonical exported record stream. The COW mount pins `metacopy=off` and `redirect_dir=nofollow`, so supported upper records are self-contained rather than depending on omitted OverlayFS metacopy/redirect xattrs. `RunReport.cow_diff` / `run-json` expose supported file, directory, symlink, remove/whiteout, and opaque-directory changes. File/directory records preserve Unix permission bits (`st_mode & 0o7777`); ownership, timestamps, other xattrs/ACLs, hard-link identity, device/FIFO/socket nodes, and a replay/commit executor remain outside the contract.",
    "README bounded COW diff semantics",
)

replace_one(
    "THREAT_MODEL.md",
    "- **Filesystem mutability/path boundary:** the revalidated host root is always recursively cloned/read-only. Without COW policy that clone is the final root. With `filesystem.cow_root_bytes`, the launcher constructs a private OverlayFS merged root over that read-only lower using size-bounded tmpfs upper/work state; root mutations then affect only the sandbox mount namespace. Optional scratch remains a separate private `nosuid,nodev,noexec` tmpfs, and the target is chrooted only after final mount construction. The COW backing tmpfs is `nosuid,nodev,noexec`, but the merged root is not claimed globally `noexec`.",
    "- **Filesystem mutability/path boundary:** the revalidated host root is always recursively cloned/read-only. Without COW policy that clone is the final root. With `filesystem.cow_root_bytes`, the launcher constructs a private OverlayFS merged root over that read-only lower using size-bounded tmpfs upper/work state and explicitly sets `metacopy=off` plus `redirect_dir=nofollow`; root mutations then affect only the sandbox mount namespace, metadata-only copy-up retains complete file data in the upper tree, and lower/merged directory rename cannot silently depend on an unexported redirect xattr. Optional scratch remains a separate private `nosuid,nodev,noexec` tmpfs, and the target is chrooted only after final mount construction. The COW backing tmpfs is `nosuid,nodev,noexec`, but the merged root is not claimed globally `noexec`.",
    "threat pinned OverlayFS semantics",
)
replace_one(
    "THREAT_MODEL.md",
    "- **Bounded post-run COW diff:** when requested, launcher-owned namespace PID 1 retains the private upper descriptor outside target authority, waits for the direct target and all remaining descendants to converge, then walks only that upper tree. Supported records encode regular-file content plus `st_mode & 0o7777`, directory permission modes, symlink targets, whiteout removals, and opaque-directory topology. The byte ceiling applies to the canonical encoded stream; overflow and unsupported object kinds fail closed before lifecycle readiness is published. This is not ownership/timestamp/xattr/ACL/hard-link identity preservation, a replay engine, atomic commit, or cryptographic snapshot integrity.",
    "- **Bounded post-run COW diff:** when requested, launcher-owned namespace PID 1 retains the private upper descriptor outside target authority, waits for the direct target and all remaining descendants to converge, then walks only that upper tree. Because COW setup fixes `metacopy=off` and `redirect_dir=nofollow`, a metadata-only lower-file mutation produces a self-contained upper regular file and a lower/merged directory rename receives `EXDEV` instead of being represented by an omitted redirect xattr. Supported records encode regular-file content plus `st_mode & 0o7777`, directory permission modes, symlink targets, whiteout removals, and opaque-directory topology. The byte ceiling applies to the canonical encoded stream; overflow and unsupported object kinds fail closed before lifecycle readiness is published. This is not ownership/timestamp/other-xattr/ACL/hard-link identity preservation, a replay engine, atomic commit, or cryptographic snapshot integrity.",
    "threat bounded COW diff semantics",
)

replace_one(
    "ROADMAP.md",
    "- namespace PID 1 retains the private upper-tree descriptor outside target authority and exports only after the direct target has terminated and remaining descendants have been killed/reaped, so the walk observes converged post-run COW state;",
    "- namespace PID 1 retains the private upper-tree descriptor outside target authority and exports only after the direct target has terminated and remaining descendants have been killed/reaped, so the walk observes converged post-run COW state;\n- COW mount construction explicitly fixes `metacopy=off` and `redirect_dir=nofollow` instead of inheriting host OverlayFS defaults, keeping supported upper records self-contained for the exporter rather than relying on omitted metacopy/redirect xattrs;",
    "roadmap pinned OverlayFS semantics",
)
replace_one(
    "ROADMAP.md",
    "- the raw COW oracle replaces an existing file, creates `/cow-new` with mode `0600`, removes an existing child, and leaves the trusted host lower tree unchanged across independent runs; the public `RunReport` regression requires exact file bytes, the exact exported `0600` permission mode, and the removal record;",
    "- the raw COW oracle replaces an existing file, creates `/cow-new` with mode `0600`, chmods an unchanged lower file to `0640`, requires exact `EXDEV` for lower/merged directory rename, removes an existing child, and leaves the trusted host lower tree content/mode/topology unchanged across independent runs; the public `RunReport` regression requires exact replaced/created bytes, the metadata-only file's original bytes plus exported `0640` mode, the exact new-file `0600` mode, and the removal record;",
    "roadmap overlay semantic evidence",
)
replace_one(
    "ROADMAP.md",
    "Boundary: 31A is a bounded content/topology/permission-mode export for supported upper-layer object classes. It does not preserve UID/GID ownership, timestamps, xattrs/ACLs, hard-link identity, device/FIFO/socket nodes, or filesystem aliases; it does not supply a replay/commit executor, transaction/atomicity/durability semantics, persistent image lifecycle, or cryptographic snapshot integrity.",
    "Boundary: 31A is a bounded content/topology/permission-mode export for supported upper-layer object classes under the explicitly pinned `metacopy=off` / `redirect_dir=nofollow` COW semantics. It does not preserve UID/GID ownership, timestamps, other xattrs/ACLs, hard-link identity, device/FIFO/socket nodes, or filesystem aliases; it does not supply a replay/commit executor, transaction/atomicity/durability semantics, persistent image lifecycle, or cryptographic snapshot integrity.",
    "roadmap 31A boundary",
)
