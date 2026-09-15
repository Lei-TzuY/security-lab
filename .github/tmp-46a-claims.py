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
    "The current Milestone 45A verified candidate adds **inventory-guarded durable writes** that reject a stale caller-retained whole-store identity before object publication.",
    "Milestone 45A added **inventory-guarded durable writes** that reject a stale caller-retained whole-store identity before object publication. The current Milestone 46A verified candidate adds an **independently persisted authenticated snapshot-store head**: a host-held HMAC key authenticates a generation plus complete audited inventory identity in a state root configured separately from the object store, so store-only rollback or divergence fails closed while that independent state remains intact.",
    "README milestone summary",
)

replace_one(
    "README.md",
    "## Policy observability commands\n",
    """## Authenticated snapshot-store head state

Milestone 46A composes the audited inventory, cooperative transaction, and durable publication layers into an independently persisted host-side head state. `initialize_snapshot_store_head_state` establishes generation 1 from the complete audited store inventory; `load_snapshot_store_head_state` authenticates the persisted state without inspecting the store; `verify_snapshot_store_head_state` authenticates the state and requires a newly audited store inventory to match it; and `store_snapshot_archive_ed25519_durable_with_head_state` performs guarded publication through a `SnapshotStoreHeadPublishRequest`.

The state file commits to a non-zero generation plus the complete `SnapshotStoreInventoryIdentity` and authenticates that fixed representation with HMAC-SHA256 under an exact 32-byte caller-held key. The configured state root and store root must be absolute, non-root, `..`-free, and lexically disjoint. Linux state access is fd-relative and lock-protected; successful state publication is fsync-backed. The guarded publication path acquires the head-state lock before the exclusive store transaction, requires the current audited inventory to equal the authenticated persisted head before object publication, and advances the generation only after a newly inserted object has produced the successor inventory. Exact byte-for-byte deduplication leaves the generation unchanged.

Executable regressions prove wrong-key and state-byte tamper authentication failure, root-overlap rejection, generation advance on a new durable object, stable generation on exact deduplication, and store-only rollback detection: after a previously committed object is removed while the independent state remains intact, verification returns `StoreDiverged` and a later candidate object is rejected before publication.

This is a **host-local independently persisted rollback reference only while the state root and HMAC key remain trustworthy**. The object-store publication and head-state publication are two durable resources, not one crash-atomic transaction; if the store advances and a later state publication fails, the call fails and subsequent verification detects divergence. Coordinated rollback of both store and state roots, compromise/rollback of the host-held key, TPM/secure-counter guarantees, remote witnessing, distributed consensus, hostile-writer point-in-time filesystem snapshots, and general multi-object atomic commits remain outside the claim.

## Policy observability commands
""",
    "README 46A section",
)

replace_one(
    "THREAT_MODEL.md",
    "The current Milestone 43A verified candidate adds a deterministic unkeyed commitment to the complete successfully audited store membership for externally retained comparison.",
    "Milestones 43A–45A added deterministic whole-store inventory identity, cooperative shared/exclusive store serialization, and optimistic inventory-guarded durable publication. The current Milestone 46A verified candidate adds a separately persisted HMAC-authenticated generation plus complete inventory identity, providing fail-closed detection of store-only rollback/divergence while the independent state root and host-held key remain intact.",
    "threat purpose summary",
)

replace_one(
    "THREAT_MODEL.md",
    """Milestones through 44A are integrated on `main`, including bounded COW snapshot lifecycle, authenticated/durable content-addressed frozen-object storage, explicit signer trust-policy rotation/revocation, bounded whole-store audit/inventory identity, and cooperative shared-read/exclusive-write store serialization. Milestone 41B persists and authenticates the exact policy identity while keeping privileged whole-directory rollback outside the claim. The current 45A candidate adds an optimistic expected-inventory precondition to cooperating durable writers; it does not turn that unkeyed inventory value into an independently anchored rollback state. Milestone 4A cgroup-v2 aggregate process accounting remains blocked by missing unprivileged delegation. Future promotion must target materially stronger independently anchored history/rollback semantics, hostile-writer detection, genuine multi-object/point-in-time transactions, or another distinct executable authority/integration frontier without overstating evidence.
""",
    """Milestones through 45A are integrated on `main`, including bounded COW snapshot lifecycle, authenticated/durable content-addressed frozen-object storage, explicit signer trust-policy rotation/revocation, bounded whole-store audit/inventory identity, cooperative shared-read/exclusive-write store serialization, and optimistic inventory-guarded publication. Milestone 41B persists and authenticates the exact signer-policy identity while keeping privileged whole-directory rollback outside that claim. The current 46A candidate separately authenticates and durably persists a store generation plus complete inventory identity outside the store root, so store-only rollback/divergence is detected while that independent state and its host-held HMAC key remain intact. It does not establish coordinated store+state rollback resistance, hardware monotonicity, remote witnessing, or one crash-atomic transaction spanning both durable resources. Milestone 4A cgroup-v2 aggregate process accounting remains blocked by missing unprivileged delegation. Future promotion must add materially stronger hostile-writer/point-in-time semantics, multi-object atomic mutation, hardware/remote monotonic anchoring, or another distinct executable authority/integration frontier without overstating evidence.
""",
    "threat phase promotion",
)

replace_one(
    "THREAT_MODEL.md",
    "## Cooperative snapshot-store transaction boundary\n",
    """## Authenticated snapshot-store head-state boundary

Milestone 46A stores one versioned fixed-size head record in a state root that must be configured lexically disjoint from the snapshot-store root. The record contains a non-zero generation plus the complete 43A inventory tuple and is authenticated with HMAC-SHA256 under an exact 32-byte caller-held key. State-file byte tamper or a wrong key fails authentication before the value is trusted. State-root access and publication are fd-relative, lock-protected, and fsync-backed on Linux.

Initialization takes the head-state exclusive lock and derives generation 1 from the complete store inventory under a cooperative read transaction. Verification takes the state lock, authenticates the persisted head, derives the complete store inventory under a read transaction, and requires exact equality. Guarded publication orders the independent head-state lock before the existing exclusive store transaction, verifies the current inventory against the authenticated head before publishing, and on a new insertion derives and durably writes generation+1 before reporting success. Exact deduplication does not advance the head.

The executable rollback oracle deletes a previously anchored store object while leaving the independent head intact. Verification then returns typed `StoreDiverged`, and a subsequent guarded publication refuses to add its candidate object. This is evidence for store-only rollback/divergence detection under the documented trust assumptions, not proof against a privileged actor that can coherently roll back or replace both roots or obtain/control the HMAC key. Store publication and head-state publication remain separate durable resources rather than a two-resource crash-atomic commit; an error after store advancement leaves a detectable fail-closed mismatch rather than claiming rollback.

## Cooperative snapshot-store transaction boundary
""",
    "threat 46A boundary section",
)

replace_one(
    "ROADMAP.md",
    "**Current verified candidate.** Composes the 43A complete-store commitment, the 44A exclusive transaction, and the 40B authenticated durable publication path into one compare-and-publish boundary for cooperating writers.",
    "**Status: complete on `main`.** Composes the 43A complete-store commitment, the 44A exclusive transaction, and the 40B authenticated durable publication path into one compare-and-publish boundary for cooperating writers.",
    "roadmap 45A status",
)

replace_one(
    "ROADMAP.md",
    "## Independent host-local IPC frontier — post-launch object transfer\n",
    """## Milestone 46 — independently authenticated store head

### Slice 46A — persisted authenticated whole-store head state

**Current verified candidate.** Adds one independently persisted host-side generation/inventory anchor outside the snapshot object store, rather than another caller-retained comparison token.

Acceptance evidence is executable:

- `SnapshotStoreHeadStateKey` holds exactly 32 host-supplied bytes and redacts them from `Debug`; the fixed state encoding authenticates a versioned domain, non-zero generation, complete inventory SHA-256, object count, and aggregate archive bytes with HMAC-SHA256;
- configured `state_root` and `store_root` must be absolute, non-root, `..`-free, and lexically disjoint; Linux state access is fd-relative and protected by a dedicated `flock` lock;
- initialization establishes generation 1 from the complete audited inventory while holding the head-state exclusive lock and a cooperative store read transaction, then publishes the authenticated state with fsync-backed state-file/directory barriers;
- load authenticates persisted state independently of the store, while verify authenticates the state and requires a complete audited store inventory derived under a read transaction to match exactly;
- guarded publication acquires the head-state lock before the exclusive store transaction, rejects pre-existing inventory divergence before candidate publication, reuses the authenticated durable object-store path, advances the generation only for a newly inserted object, and leaves the generation unchanged for exact deduplication;
- deleting a previously anchored object while keeping the independent state intact produces typed `StoreDiverged`; a later guarded publication is rejected before its candidate object appears;
- a wrong HMAC key and direct head-state byte tamper both fail authentication; overlapping configured state/store roots fail validation;
- the public durable-publication API uses a coherent `SnapshotStoreHeadPublishRequest`, and transaction errors are boxed so the public result type does not carry the large underlying transaction error inline;
- exact candidate rustfmt, Clippy with `-D warnings`, complete stable tests, and the complete Rust 1.74 suite are green.

Boundary: 46A detects store-only rollback/divergence only while the separately persisted state root and host-held HMAC key remain trustworthy. It does not resist coordinated rollback/replacement of both roots, provide TPM/secure-counter or remote-witness monotonicity, freeze a hostile live filesystem into a point-in-time view, or make object-store publication plus state-head publication one crash-atomic transaction. If the store advances and a later state write fails, the operation fails and the resulting mismatch is intentionally detected on subsequent verification.

### Milestone 46 promotion rule

After 46A integrates, seal caller-hosted local HMAC head-state rollback detection. Do not farm generation formatting, extra MAC encodings, or retry wrappers. A stronger snapshot-store phase must add materially different hostile-writer/point-in-time semantics, genuine multi-object atomic mutation, or an external/hardware monotonic witness with executable evidence; otherwise promote to another independent authority frontier.

## Independent host-local IPC frontier — post-launch object transfer
""",
    "roadmap 46A section",
)
