from pathlib import Path


def replace_one(path: str, old: str, new: str, label: str) -> None:
    p = Path(path)
    text = p.read_text()
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{label}: expected exactly one match, got {count}")
    p.write_text(text.replace(old, new, 1))


# README: seal 9B and describe only the verified 10A read/execute envelope.
replace_one(
    "README.md",
    "Milestone 9A added **policy-owned isolated loopback networking** inside the private network namespace. The current Milestone 9B verified candidate adds **one launcher-brokered host-loopback TCP endpoint capability**: the trusted parent connects to exactly `127.0.0.1:<declared-port>` in the host network namespace and remaps that already-connected socket to one declared target descriptor without attaching the target network namespace to the host.",
    "Milestone 9A added **policy-owned isolated loopback networking** inside the private network namespace. Milestone 9B added **one launcher-brokered host-loopback TCP endpoint capability** without attaching the target network namespace to the host. The current Milestone 10A verified candidate adds an optional **Landlock read/execute pathname envelope** that further narrows which already-visible sandbox paths may be read or executed after trusted setup.",
    "README milestone summary",
)
replace_one(
    "README.md",
    "Optional read-only or writable volume source/target pairs, `network.loopback`, one brokered host-loopback TCP port/target-fd pair, scratch, stdout redirection, stdout capture, selected non-stdio handles, and `limit.wall_clock_milliseconds` are validated fail-closed.",
    "Optional read-only or writable volume source/target pairs, repeatable `landlock.read_execute` paths, `network.loopback`, one brokered host-loopback TCP port/target-fd pair, scratch, stdout redirection, stdout capture, selected non-stdio handles, and `limit.wall_clock_milliseconds` are validated fail-closed. A non-empty Landlock list is limited to 32 absolute sandbox paths, rejects `/` and duplicates, and must cover the initial executable.",
    "README policy validation",
)
replace_one(
    "README.md",
    "9. **Target enforcement** the direct target alone applies explicit stdio, installs declared selected handles and any brokered connected socket with `dup3`, then applies rlimits, capability reduction, `no_new_privs`, default-deny seccomp, and pinned `execveat`.",
    "9. **Target enforcement** the direct target alone optionally builds a Landlock ruleset against the final mounted root, applies explicit stdio, installs declared selected handles and any brokered connected socket with `dup3`, then applies rlimits, capability reduction, `no_new_privs`, activates the Landlock restriction when configured, installs default-deny seccomp, and performs pinned `execveat`.",
    "README target enforcement",
)
replace_one(
    "README.md",
    "- The target receives user/mount/PID/network/IPC/UTS namespace isolation, private mount propagation, a recursively read-only root, chroot/cwd selection, capability clearing, `no_new_privs`, rlimits, and default-deny seccomp.\n",
    "- The target receives user/mount/PID/network/IPC/UTS namespace isolation, private mount propagation, a recursively read-only root, chroot/cwd selection, capability clearing, `no_new_privs`, rlimits, and default-deny seccomp.\n- When `landlock.read_execute` is non-empty, the launcher preflights Landlock support and the direct target installs a Landlock ruleset handling only `EXECUTE`, `READ_FILE`, and `READ_DIR`. Declared regular files receive read/execute access; declared directories grant those handled rights beneath them. Undeclared visible paths remain in the chroot but pathname reads/executes are denied by Landlock.\n- Landlock is an additional pathname restriction, not revocation of explicit object capabilities: already-open descriptors intentionally exposed through stdio, selected handles, or the brokered socket keep their documented object authority.\n",
    "README Landlock invariants",
)
replace_one(
    "README.md",
    "`network.loopback` is optional and accepts only `enabled` or `disabled`; absence is equivalent to `disabled`.",
    "`landlock.read_execute = <absolute-sandbox-path>` is optional and repeatable up to 32 entries. An empty list disables Landlock and preserves legacy behavior. When enabled, `/` is forbidden, duplicate paths are rejected, and at least one declared path must cover the initial executable. The launcher requires every declared path to exist beneath the selected root as a regular file or directory, then reopens the final mounted object after namespace/mount construction before installing the Landlock rules. This slice handles read/execute rights only; it is not a general write-policy language.\n\n`network.loopback` is optional and accepts only `enabled` or `disabled`; absence is equivalent to `disabled`.",
    "README Landlock policy format",
)
replace_one(
    "README.md",
    "## Test evidence\n\nLinux x86_64 integration tests prove that:\n",
    "## Test evidence\n\nLinux x86_64 integration tests prove that:\n\n- with `/probe` and `/landlock-allowed` declared in `landlock.read_execute`, the raw target reads exact `landlock-allowed\\n` bytes from `/landlock-allowed/marker`, while a separately existing `/landlock-denied/secret` under the same chroot returns exact `EACCES`; this distinguishes Landlock denial from chroot invisibility or seccomp `EPERM`;\n",
    "README Landlock evidence",
)

# Threat model: make the new restriction and its object-capability exception explicit.
replace_one(
    "THREAT_MODEL.md",
    "# Milestones 1–9B threat model",
    "# Milestones 1–10A threat model",
    "threat title",
)
replace_one(
    "THREAT_MODEL.md",
    "Milestone 9A added policy-owned activation of only the isolated network namespace's loopback device. The current Milestone 9B verified candidate adds one launcher-created, already-connected IPv4 TCP socket to a declared host-loopback port while preserving the target network namespace's direct host separation.",
    "Milestone 9A added policy-owned activation of only the isolated network namespace's loopback device, and Milestone 9B added one launcher-created, already-connected IPv4 TCP socket to a declared host-loopback port while preserving the target network namespace's direct host separation. The current Milestone 10A verified candidate adds an optional Landlock layer that narrows read/execute pathname authority within the already-constructed sandbox filesystem.",
    "threat purpose",
)
replace_one(
    "THREAT_MODEL.md",
    "one optional brokered host-loopback TCP socket capability, stdio, bounded capture",
    "one optional brokered host-loopback TCP socket capability, an optional Landlock read/execute pathname envelope, stdio, bounded capture",
    "threat protected boundary",
)
replace_one(
    "THREAT_MODEL.md",
    "- **Filesystem mutability/path boundary:** the revalidated root is recursively cloned/read-only, optional scratch is private `nosuid,nodev,noexec` tmpfs, and the target is chrooted into the constructed root.\n",
    "- **Filesystem mutability/path boundary:** the revalidated root is recursively cloned/read-only, optional scratch is private `nosuid,nodev,noexec` tmpfs, and the target is chrooted into the constructed root.\n- **Optional Landlock read/execute envelope:** when at least one `landlock.read_execute` path is declared, the launcher requires kernel Landlock support, prevalidates each path beneath the selected root, then the direct target constructs rules against the final mounted tree. After capability reduction and `no_new_privs`, `landlock_restrict_self` activates handling for only `EXECUTE`, `READ_FILE`, and `READ_DIR` before seccomp and pinned exec. Undeclared visible paths therefore fail pathname read/execute access rather than becoming invisible.\n- **Object-capability exception:** Landlock does not retroactively attenuate already-open file descriptions or sockets deliberately exposed through stdio, selected handles, or the 9B broker. Those remain separate explicit object capabilities.\n",
    "threat Landlock properties",
)
replace_one(
    "THREAT_MODEL.md",
    "## Network namespace semantics\n",
    "## Landlock pathname-envelope semantics\n\nMilestone 10A is optional: an empty `landlock.read_execute` list performs no Landlock syscalls and preserves the prior filesystem behavior. A non-empty list is bounded to 32 unique absolute sandbox paths, forbids `/`, and must cover the initial executable. Parent-side preparation verifies each configured path beneath the pinned root as a regular file or directory. The direct target later reopens the path against the final cloned/mounted root without `RESOLVE_NO_XDEV`, so an explicitly named final mountpoint can be governed by the same pathname layer.\n\nThe ruleset handles only `LANDLOCK_ACCESS_FS_EXECUTE`, `LANDLOCK_ACCESS_FS_READ_FILE`, and `LANDLOCK_ACCESS_FS_READ_DIR`. Directories receive all three handled rights beneath them; regular files receive execute/read-file. `PR_SET_NO_NEW_PRIVS` is set before `landlock_restrict_self`; setup failure is reported through the owned launch-error channel and never falls back to unrestricted execution. The Linux x86_64 runtime probes the Landlock ABI only when the feature is requested.\n\nLandlock is intentionally complementary to chroot/mount/seccomp/object-capability controls. It does not govern already-open descriptor reads/writes, does not add a general mutation policy in 10A, and does not claim filesystem alias/canonicalization or subtree-integrity proof.\n\n## Network namespace semantics\n",
    "threat Landlock semantics section",
)
replace_one(
    "THREAT_MODEL.md",
    "- seccomp predicates beyond masked equality on numeric syscall argument values, including pointer-target/string inspection, range/relational matching, or pathname-content policy;\n",
    "- seccomp predicates beyond masked equality on numeric syscall argument values, including pointer-target/string inspection, range/relational matching, or pathname-content policy;\n- a general Landlock filesystem policy: Milestone 10A handles only read/execute pathname rights, does not revoke pre-opened object capabilities, does not mediate write/create/remove rights, and does not prove filesystem aliases or subtree immutability;\n",
    "threat Landlock limitations",
)

# Roadmap: seal 9B, add 10A as verified candidate, and promote away from networking variants.
replace_one(
    "ROADMAP.md",
    "**Current verified candidate.** Adds one explicit host endpoint object capability without attaching the target network namespace to the host.",
    "**Status: complete on `main`.** Adds one explicit host endpoint object capability without attaching the target network namespace to the host.",
    "roadmap 9B status",
)
replace_one(
    "ROADMAP.md",
    "## Later frontiers\n",
    "## Milestone 10 — pathname access narrowing\n\n### Slice 10A — Landlock read/execute envelope\n\n**Current verified candidate.** Adds a kernel-enforced pathname access layer inside the already-constructed sandbox filesystem rather than another mount or networking variant.\n\nAcceptance evidence is executable:\n\n- repeatable `landlock.read_execute = <absolute-sandbox-path>` entries are bounded to 32, reject `/`, duplicates, relative paths, and policies that do not cover the initial executable; an empty list preserves the pre-10A behavior;\n- parent preparation fail-closed verifies each declared path beneath the pinned root as a regular file or directory and preallocates sandbox-relative path data before fork;\n- when requested, the runtime queries Landlock support rather than silently dropping the restriction; known unavailable-kernel results are reported as unsupported and other setup errors fail closed;\n- the direct target creates a ruleset handling only `EXECUTE`, `READ_FILE`, and `READ_DIR`, reopens declared paths against the final mounted root, stores the ruleset descriptor above all target-visible descriptor destinations, applies `PR_SET_NO_NEW_PRIVS`, then calls `landlock_restrict_self` before target seccomp and pinned `execveat`;\n- the raw target reads exact `landlock-allowed\\n` bytes from a declared `/landlock-allowed/marker`, while a real `/landlock-denied/secret` that remains present in the same chroot returns exact `EACCES`; seccomp grants `openat` and therefore cannot masquerade as the pathname denial;\n- all Milestones 1–9B regressions remain active; stable format/Clippy/full tests and the full Rust 1.74 suite are green.\n\nBoundary: 10A is a read/execute pathname envelope only. It does not attenuate already-open stdio/selected/brokered object capabilities, does not add write/create/remove Landlock policy, does not prove filesystem aliases/canonicalization or subtree immutability, and is not a production multi-tenant container boundary.\n\n### Milestone 10 promotion rule\n\nAfter 10A integrates, do not farm extra path-count limits or equivalent read/execute aliases. Further Landlock work must add a materially different executable authority dimension, such as an intentionally designed mutation envelope with interactions against scratch/persistent volumes, or the project should promote to another independent frontier.\n\n## Later frontiers\n",
    "roadmap 10A section",
)
