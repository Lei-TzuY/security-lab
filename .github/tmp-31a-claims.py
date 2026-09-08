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
    "The current Milestone 30A verified candidate adds an optional **bounded ephemeral copy-on-write root**: the trusted launcher keeps the pinned lower tree recursively read-only, overlays it with private bounded tmpfs-backed upper/work state, and discards target-side root mutations with the mount namespace instead of writing them through to the host lower tree.",
    "Milestone 30A added an optional **bounded ephemeral copy-on-write root**: the trusted launcher keeps the pinned lower tree recursively read-only, overlays it with private bounded tmpfs-backed upper/work state, and discards target-side root mutations with the mount namespace instead of writing them through to the host lower tree. The current Milestone 31A verified candidate adds a **bounded post-run COW diff export**: launcher-owned PID 1 walks the private upper tree after target/descendant convergence and reports supported content/topology changes plus regular-file/directory Unix permission bits without persisting the upper layer.",
    "README milestone summary",
)
replace_one(
    "README.md",
    "Optional `filesystem.proc = enabled|disabled`, `filesystem.cow_root_bytes`, read-only or writable volume source/target pairs,",
    "Optional `filesystem.proc = enabled|disabled`, `filesystem.cow_root_bytes`, `filesystem.cow_diff_bytes`, read-only or writable volume source/target pairs,",
    "README policy list",
)
replace_one(
    "README.md",
    "The COW backing tmpfs is `nosuid,nodev,noexec`, but the merged root is not claimed globally `noexec`.",
    "The COW backing tmpfs is `nosuid,nodev,noexec`, but the merged root is not claimed globally `noexec`. When `filesystem.cow_diff_bytes` is requested, launcher-owned PID 1 exports the private upper tree only after direct-target termination and descendant teardown have converged. The bounded diff carries regular-file bytes and `st_mode & 0o7777`, directory permission modes, symlink targets, removals/whiteouts, and opaque-directory topology; overflow or unsupported upper-layer object kinds fail closed rather than returning a partial successful diff.",
    "README COW export semantics",
)
replace_one(
    "README.md",
    "- **COW root evidence boundary:** the runtime receipt publishes exactly one of `readonly_root` or `copy_on_write_root` according to the requested final-root mode, and the receipt-completeness gate rejects the wrong or simultaneous mode. Static preflight leaves COW support `unprobed`; only a real run can produce positive enforcement evidence.",
    "- **COW root evidence boundary:** the runtime receipt publishes exactly one of `readonly_root` or `copy_on_write_root` according to the requested final-root mode, and the receipt-completeness gate rejects the wrong or simultaneous mode. Static preflight leaves COW support `unprobed`; only a real run can produce positive enforcement evidence.\n- **Bounded COW diff contract:** `filesystem.cow_diff_bytes` is valid only with COW root mode and bounds the launcher's canonical exported record stream. `RunReport.cow_diff` / `run-json` expose supported file, directory, symlink, remove/whiteout, and opaque-directory changes. File/directory records preserve Unix permission bits (`st_mode & 0o7777`); ownership, timestamps, xattrs/ACLs, hard-link identity, device/FIFO/socket nodes, and a replay/commit executor remain outside the contract.",
    "README COW diff boundary",
)

replace_one(
    "THREAT_MODEL.md",
    "The current Milestone 30A verified candidate adds an explicitly requested ephemeral copy-on-write final root whose host lower tree remains recursively read-only while target-side root mutations are redirected into private bounded OverlayFS upper/work state.",
    "Milestone 30A added an explicitly requested ephemeral copy-on-write final root whose host lower tree remains recursively read-only while target-side root mutations are redirected into private bounded OverlayFS upper/work state. The current Milestone 31A verified candidate optionally exports that private upper as a bounded post-run content/topology/permission-mode change-set after PID-tree convergence.",
    "threat purpose",
)
replace_one(
    "THREAT_MODEL.md",
    "- **COW root evidence boundary:** the runtime receipt publishes exactly one of `readonly_root` or `copy_on_write_root` according to the requested final-root mode, and the receipt-completeness gate rejects the wrong or simultaneous mode. Static preflight leaves COW support `unprobed`; only a real run can produce positive enforcement evidence.",
    "- **COW root evidence boundary:** the runtime receipt publishes exactly one of `readonly_root` or `copy_on_write_root` according to the requested final-root mode, and the receipt-completeness gate rejects the wrong or simultaneous mode. Static preflight leaves COW support `unprobed`; only a real run can produce positive enforcement evidence.\n- **Bounded post-run COW diff:** when requested, launcher-owned namespace PID 1 retains the private upper descriptor outside target authority, waits for the direct target and all remaining descendants to converge, then walks only that upper tree. Supported records encode regular-file content plus `st_mode & 0o7777`, directory permission modes, symlink targets, whiteout removals, and opaque-directory topology. The byte ceiling applies to the canonical encoded stream; overflow and unsupported object kinds fail closed before lifecycle readiness is published. This is not ownership/timestamp/xattr/ACL/hard-link identity preservation, a replay engine, atomic commit, or cryptographic snapshot integrity.",
    "threat COW diff property",
)

replace_one(
    "ROADMAP.md",
    "**Current verified candidate.** Adds one materially different filesystem authority mode: policy may explicitly widen the default recursively read-only root into bounded, private, ephemeral target-side mutation without granting host-lower write-through authority.",
    "**Status: complete on `main`.** Adds one materially different filesystem authority mode: policy may explicitly widen the default recursively read-only root into bounded, private, ephemeral target-side mutation without granting host-lower write-through authority.",
    "roadmap 30A status",
)
replace_one(
    "ROADMAP.md",
    "### Milestone 30 promotion rule\n\nAfter 30A integrates, do not farm byte-ceiling variants, extra upper/work directory names, or repeated mutation path oracles. A later filesystem slice must add materially different executable semantics such as a real bounded export/snapshot/diff lifecycle with integrity evidence; otherwise promote to another independent authority/enforcement frontier.\n",
    "### Milestone 30 promotion rule\n\n30A is sealed on `main`; do not farm byte-ceiling variants, extra upper/work directory names, or repeated mutation path oracles. Promotion requires materially different executable semantics.\n\n## Milestone 31 — bounded ephemeral filesystem change export\n\n### Slice 31A — bounded post-run COW diff\n\n**Current verified candidate.** Adds a launcher-owned, bounded change-export capability for the existing ephemeral COW root without turning the private upper layer into persistent host state.\n\nAcceptance evidence is executable:\n\n- `filesystem.cow_diff_bytes` is optional, valid only with `filesystem.cow_root_bytes`, and fail-closed bounded; an undersized export budget returns a setup failure rather than a truncated successful `CowDiff`;\n- namespace PID 1 retains the private upper-tree descriptor outside target authority and exports only after the direct target has terminated and remaining descendants have been killed/reaped, so the walk observes converged post-run COW state;\n- the raw COW oracle replaces an existing file, creates `/cow-new` with mode `0600`, removes an existing child, and leaves the trusted host lower tree unchanged across independent runs; the public `RunReport` regression requires exact file bytes, the exact exported `0600` permission mode, and the removal record;\n- supported canonical records cover regular-file upserts, directory existence/mode, symlink targets, whiteout removals, and opaque-directory topology; regular files and directories preserve Unix permission bits as `st_mode & 0o7777`;\n- `run-json` exposes the same file/directory permission modes numerically, with a deterministic unit regression proving `0600`/`0750` serialization rather than asking a consumer to guess creator umask;\n- unsupported upper-layer object kinds fail closed with `EOPNOTSUPP`, and the canonical encoding budget includes the exported mode metadata;\n- stable rustfmt/Clippy/full tests and the full Rust 1.74 suite are green on the exact implementation head.\n\nBoundary: 31A is a bounded content/topology/permission-mode export for supported upper-layer object classes. It does not preserve UID/GID ownership, timestamps, xattrs/ACLs, hard-link identity, device/FIFO/socket nodes, or filesystem aliases; it does not supply a replay/commit executor, transaction/atomicity/durability semantics, persistent image lifecycle, or cryptographic snapshot integrity.\n\n### Milestone 31 promotion rule\n\nAfter 31A integrates, do not farm more record tags or metadata fields unless they close a demonstrated replay/integrity boundary. Promote to a materially different capability such as a verified replay/apply lifecycle with confinement and failure atomicity, stronger snapshot identity/integrity evidence, or another independent authority/enforcement frontier.\n",
    "roadmap 31A section",
)
