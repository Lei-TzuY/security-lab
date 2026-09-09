from pathlib import Path


def replace_one(path: str, old: str, new: str, label: str) -> None:
    target = Path(path)
    text = target.read_text()
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{label}: expected exactly one match, got {count}")
    target.write_text(text.replace(old, new, 1))


def append_section(path: str, heading: str, section: str) -> None:
    target = Path(path)
    text = target.read_text()
    if heading in text:
        raise SystemExit(f"{path}: section already exists: {heading}")
    target.write_text(text.rstrip() + "\n\n" + section.strip() + "\n")


replace_one(
    "ROADMAP.md",
    "**Current verified candidate.** Adds a cross-run store-membership commitment above the complete 42A integrity audit rather than another malformed-object variant.",
    "**Status: complete on `main`.** Adds a cross-run store-membership commitment above the complete 42A integrity audit rather than another malformed-object variant.",
    "43A status",
)

milestone_44 = r'''## Milestone 44 — cooperative snapshot-store transaction serialization

### Slice 44A — shared-read / exclusive-write store transactions

**Current verified candidate.** Adds an explicit host-local cooperation protocol around durable publication and whole-store read operations instead of pretending the existing read-only audit is a concurrent filesystem snapshot.

Acceptance evidence is executable:

- `SnapshotStoreReadTransaction::{begin,try_begin}` opens the pre-existing store-root directory and holds Linux `flock(LOCK_SH)` on that directory inode for the transaction lifetime; multiple cooperating readers can coexist;
- `SnapshotStoreWriteTransaction::{begin,try_begin}` uses `flock(LOCK_EX)` on the same store-root inode, and nonblocking lock contention returns the typed `SnapshotStoreTransactionError::LockContended` rather than falling through to an unlocked operation;
- read transactions expose the existing complete store audit, deterministic inventory identity, and expected-inventory verification while the shared lock remains live;
- write transactions expose the existing authenticated `fsync`-backed durable publication path while the exclusive lock remains live;
- deterministic Linux regressions prove two shared readers coexist, a writer cannot acquire while either reader is live, a reader or second writer cannot acquire while the writer is live, and locks become available after RAII release;
- a durable two-publication regression proves the cooperating inventory advances from a complete one-object state to a complete two-object state, while nonblocking writers/readers are rejected at the opposite lock boundary;
- legacy direct store/audit/inventory functions remain API-compatible and intentionally do not acquire this lock automatically, avoiding hidden nested-lock semantics. Callers requiring cooperative linearization must enter the transaction API explicitly;
- exact candidate rustfmt, Clippy with `-D warnings`, complete stable tests, and the complete Rust 1.74 suite are green.

Boundary: 44A is advisory cooperation among callers that use these transaction APIs against the same local store-root inode. It is not a mandatory-access-control boundary, does not stop privileged or non-cooperating writers, does not provide a filesystem point-in-time snapshot, database isolation/rollback, distributed leases, remote-filesystem lock guarantees, or independently anchored rollback protection.

### Milestone 44 promotion rule

After 44A integrates, seal the shared/exclusive advisory-lock vocabulary. Do not farm lock-name aliases, timeout knobs, or more reader-count variants. A stronger store-lifecycle phase must introduce materially new semantics such as independently anchored rollback state, hostile/non-cooperating mutation detection, or a genuine point-in-time snapshot/transaction mechanism with deterministic evidence; otherwise promote to another independent authority frontier.
'''
replace_one(
    "ROADMAP.md",
    "## Independent host-local IPC frontier — post-launch object transfer",
    milestone_44 + "\n## Independent host-local IPC frontier — post-launch object transfer",
    "44A insertion",
)

append_section(
    "README.md",
    "## Cooperative snapshot-store transactions",
    r'''## Cooperative snapshot-store transactions

The current Milestone 44A verified candidate makes the store's previous “quiescent or cooperatively serialized” precondition executable for participating callers. `SnapshotStoreReadTransaction` holds a shared Linux `flock` on the already-existing store-root directory and offers the complete store audit, inventory identity, and expected-inventory verification while that lock is live. `SnapshotStoreWriteTransaction` holds an exclusive lock on the same directory inode and offers authenticated durable snapshot publication. Blocking `begin` and nonblocking `try_begin` variants are explicit; a nonblocking conflict returns `SnapshotStoreTransactionError::LockContended` with the requested read/write mode.

This is deliberately an opt-in cooperation protocol rather than a silent semantic change to the existing direct store, audit, or inventory APIs. Legacy direct functions remain available and do not acquire the transaction lock automatically; callers that need read/write linearization must consistently use the transaction types. The lock is advisory and host-local: it does not exclude privileged or non-cooperating writers, create a kernel/filesystem snapshot, provide database rollback or serializable transactions, authenticate/anchor inventory history, or claim distributed/remote-filesystem lease semantics.

Executable regressions prove shared-reader coexistence, read/write and write/write exclusion, typed nonblocking contention, RAII release, authenticated durable publication under the exclusive transaction, and complete one-object → two-object inventory transitions under shared read transactions. The exact candidate remains covered by stable rustfmt/Clippy/full tests and the complete Rust 1.74 suite.''',
)

append_section(
    "THREAT_MODEL.md",
    "## Cooperative snapshot-store transaction boundary",
    r'''## Cooperative snapshot-store transaction boundary

Milestone 44A adds a caller-visible cooperation mechanism for store-wide reads versus durable publication. A read transaction opens the pre-existing store-root directory with `O_NOFOLLOW` and holds `flock(LOCK_SH)` for its lifetime; a write transaction opens the same directory and holds `flock(LOCK_EX)`. Whole-store audit/inventory operations are methods of the shared transaction, and authenticated durable publication is a method of the exclusive transaction, so cooperating callers using the same local store-root inode cannot overlap those operations. `try_begin` uses `LOCK_NB` and reports typed contention instead of performing an unlocked fallback.

This is an advisory serialization claim only. Existing direct snapshot-store APIs remain outside the lock protocol for compatibility, and a caller that bypasses the transaction types is non-cooperating. The boundary does not prevent privileged or malicious filesystem mutation, does not freeze the filesystem against external changes, does not make inventory identity an authenticated rollback anchor, and does not provide database commit/rollback semantics, distributed consensus, leases, or portable network-filesystem locking guarantees. The executable evidence covers cooperation on the Linux host-local filesystem contract used by CI: multiple shared readers coexist, an exclusive writer conflicts with live readers and other writers, readers conflict with a live writer, release is RAII-scoped, and durable publication advances the audited inventory only after the writer transaction can acquire the exclusive lock.''',
)
