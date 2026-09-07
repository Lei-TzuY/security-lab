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
    "The current Milestone 24C verified candidate adds an **isolated mandatory launch-primitive probe**: a throwaway helper exercises representative namespace, mount, descriptor, resource, capability, `no_new_privs`, and seccomp setup primitives without touching the configured policy root or executing the target, while the overall mandatory launch core deliberately remains `unprobed`.",
    "Milestone 24C added an **isolated mandatory launch-primitive probe**: a throwaway helper exercises representative namespace, mount, descriptor, resource, capability, `no_new_privs`, and seccomp setup primitives without touching the configured policy root or executing the target. The current Milestone 24D verified candidate adds a separate **read-only configured-filesystem anchor probe** for the selected root, executable, cwd, optional scratch/proc targets, and declared persistent-volume sources/targets. Positive anchor evidence still does not upgrade the complete mandatory launch core from `unprobed`.",
    "README milestone summary",
)
replace_one(
    "README.md",
    "- `preflight` / `preflight-json` match one validated policy against safely obtained host evidence and may run a throwaway isolated helper that exercises representative mandatory namespace/mount/descriptor/resource/capability/`no_new_privs`/seccomp primitives. The helper creates only its own child namespaces and private mounts, never materializes or inspects the configured policy root, and never executes the target. Its staged result is reported separately from `mandatory_launch_core`, which intentionally remains `unprobed`; therefore the real preflight path still reports `indeterminate` / exit status 4 rather than treating primitive compatibility as complete launch compatibility. `launch_attempted=false` and `launch_preflight_complete=false` remain explicit. Known unavailable represented requirements still produce `incompatible` / exit status 3.\n",
    "- `preflight` / `preflight-json` match one validated policy against safely obtained host evidence. Milestone 24C may run a throwaway isolated helper that exercises representative mandatory namespace/mount/descriptor/resource/capability/`no_new_privs`/seccomp primitives; that helper creates only its own child namespaces/private mounts, never receives the configured root, and never executes the target. Milestone 24D separately performs read-only `openat2`/`fstat` checks against the configured root, executable, cwd, optional scratch/proc targets, and declared persistent-volume source/target anchors without creating namespaces, mounting, writing configured state, or executing the target. A known configured-filesystem failure is `incompatible` / exit status 3; positive configured-anchor evidence still leaves `mandatory_launch_core` intentionally `unprobed`, so the production path remains `indeterminate` / exit status 4 rather than treating point-in-time path compatibility as complete launch compatibility. `launch_attempted=false` and `launch_preflight_complete=false` remain explicit.\n",
    "README preflight command semantics",
)
replace_one(
    "README.md",
    "Linux x86_64 integration tests prove that:\n\n",
    "Linux x86_64 integration tests prove that:\n\n- policy preflight reports a deliberately missing configured root as `incompatible` with `configured_filesystem_probe.stage=root_open` and `ENOENT`, while the separate 24C isolated-helper probe still completes and the missing path remains unmaterialized; a positive fixture separately resolves an executable regular file with an execute bit, cwd, scratch, proc target, both volume targets, and disjoint read-only/writable host volume sources, reports the configured-filesystem probe `supported`, preserves all fixture bytes/state, and still returns `indeterminate` because the complete mandatory launch core remains unprobed;\n",
    "README configured filesystem evidence",
)

replace_one(
    "THREAT_MODEL.md",
    "The current Milestone 24C verified candidate adds a throwaway isolated helper that positively probes representative mandatory namespace/mount/descriptor/resource/capability/`no_new_privs`/seccomp primitives without inspecting the configured root or executing the target; its result remains separate from the still-unprobed complete mandatory launch core.",
    "Milestone 24C added a throwaway isolated helper that positively probes representative mandatory namespace/mount/descriptor/resource/capability/`no_new_privs`/seccomp primitives without inspecting the configured root or executing the target. The current Milestone 24D verified candidate separately inspects configured filesystem anchors with read-only `openat2`/`fstat` operations, while keeping point-in-time path evidence distinct from the still-unprobed complete mandatory launch core.",
    "threat purpose preflight summary",
)
replace_one(
    "THREAT_MODEL.md",
    "- **Conservative policy-specific host preflight:** `preflight` / `preflight-json` validate policy and combine independently safe host observations with an optional throwaway Linux x86_64 helper that exercises representative mandatory namespace/mount/descriptor/resource/capability/`no_new_privs`/seccomp primitives. The helper mutates only its own child namespaces/private tmpfs, never materializes or inspects the configured policy root, and never executes the target. Its staged success/failure is reported separately; the complete `mandatory_launch_core` remains `unprobed`, so production preflight can still report known incompatibility or indeterminate evidence but cannot claim full satisfaction. `launch_attempted=false` and `launch_preflight_complete=false` remain explicit.\n",
    "- **Conservative policy-specific host preflight:** `preflight` / `preflight-json` validate policy and combine independently safe host observations with two distinct evidence paths. The 24C throwaway Linux x86_64 helper exercises representative mandatory namespace/mount/descriptor/resource/capability/`no_new_privs`/seccomp primitives while mutating only child-owned namespaces/private tmpfs and never receiving the configured root. The 24D configured-filesystem probe intentionally inspects the selected root, executable, cwd, optional scratch/proc targets, and declared persistent-volume source/target anchors using only read-only `openat2`/`fstat` operations; it creates no namespaces or mounts, writes no configured filesystem state, and executes no target. A known anchor failure is incompatible evidence, but successful anchor resolution is only a point-in-time prerequisite observation: the complete `mandatory_launch_core` remains `unprobed`, so production preflight still cannot claim full satisfaction. `launch_attempted=false` and `launch_preflight_complete=false` remain explicit.\n",
    "threat preflight property",
)

replace_one(
    "ROADMAP.md",
    "**Current verified candidate.** Adds positive compatibility evidence for a representative mandatory Linux setup core without relabeling that evidence as a complete launch preflight.",
    "**Status: complete on `main`.** Adds positive compatibility evidence for a representative mandatory Linux setup core without relabeling that evidence as a complete launch preflight.",
    "roadmap 24C status",
)
replace_one(
    "ROADMAP.md",
    "### Milestone 24 promotion rule\n\n24A–24B are sealed on `main`; 24C is the current integration candidate. After 24C integrates, do not farm additional syscall aliases or fixture variants around the same isolated-helper mechanism. A later preflight slice is justified only if it safely closes a currently unprobed prerequisite toward a sound complete verdict; otherwise promote to a materially different executable authority/enforcement frontier. Milestone 25A remains a separate evidence class because it records stages positively observed during an actual run.\n",
    "### Slice 24D — configured filesystem anchor preflight\n\n**Current verified candidate.** Adds a policy-specific read-only prerequisite probe for configured filesystem anchors without converting preflight into a launch dry-run.\n\nAcceptance evidence is executable:\n\n- production `preflight` / `preflight-json` independently probe `filesystem.root`, the sandbox executable and working directory, optional scratch and `/proc` targets, and any declared read-only/writable persistent-volume source and target anchors;\n- host root/volume-source directories use `openat2(O_PATH|O_DIRECTORY|O_CLOEXEC)` with symlink/magic-link traversal forbidden, while sandbox-internal anchors are resolved beneath the opened root with `RESOLVE_BENEATH|RESOLVE_NO_XDEV|RESOLVE_NO_MAGICLINKS|RESOLVE_NO_SYMLINKS`;\n- the executable must additionally `fstat` as a regular file with at least one execute bit, mirroring the corresponding parent-preparation prerequisite without executing it;\n- the configured-filesystem probe creates no namespaces or mounts, writes no configured state, and never executes the target; its machine report explicitly carries `read_only=true`, `namespaces_created=false`, and `target_executed=false`;\n- a deliberately nonexistent root now yields `incompatible` / exit status 3 with `stage=root_open` and `ENOENT`, while the independent 24C isolated helper can still report `supported` and the missing path remains absent;\n- a positive fixture resolves executable/cwd/scratch/proc plus both volume source/target pairs, preserves fixture bytes and empty writable target state, reports the configured-filesystem probe `supported`, but the overall preflight remains `indeterminate` / exit status 4 because `mandatory_launch_core` is still `unprobed`;\n- stable rustfmt/Clippy/full tests and the full Rust 1.74 suite are green on the exact implementation head.\n\nBoundary: 24D is point-in-time read-only path/type/mode prerequisite evidence. It does not pin these descriptors for a later launch, prove cross-time inode identity, inspect the final post-mount Landlock tree, establish time/procfs mount success, reproduce PID1/target orchestration, validate the exact production seccomp program, or prove successful `execveat`.\n\n### Milestone 24 promotion rule\n\n24A–24C are sealed on `main`; 24D is the current integration candidate. After 24D integrates, do not farm more path aliases, errno cases, or anchor spellings around the same read-only preflight mechanism. Another preflight slice is justified only if it closes a materially different mandatory prerequisite without turning preflight into a privileged/destructive launch simulation; otherwise promote to a different executable authority/enforcement frontier. Milestone 25A remains a separate evidence class because it records stages positively observed during an actual run.\n",
    "roadmap 24D insertion",
)
