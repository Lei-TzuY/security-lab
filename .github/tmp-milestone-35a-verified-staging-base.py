from pathlib import Path
import re

path = Path("src/cow_diff_apply.rs")
text = path.read_text()

text = text.replace(
    "    /// Canonical identity observed immediately before replay setup began.\n    pub base_identity: SnapshotIdentity,",
    "    /// Canonical identity revalidated from the materialized base copy immediately\n    /// before diff replay begins.\n    pub base_identity: SnapshotIdentity,",
    1,
)

public_pattern = re.compile(
    r"/// Replay `diff` only when the current canonical identity of `base` matches\n"
    r"/// `expected_base`\..*?\n"
    r"pub fn apply_cow_diff_atomic_with_expected_base\(.*?\n\}\n\nfn validate_limits",
    re.S,
)
public_replacement = '''/// Replay `diff` only when the current canonical identity of `base` matches
/// `expected_base` both before replay setup and again after the base has been
/// materialized into the private staging tree. The first gate preserves the 34A
/// fail-fast ordering: a stale expected identity is rejected before destination
/// inspection or staging creation. The second gate binds replay to the exact
/// materialized input tree, so a base mutation after the first scan cannot be
/// replayed under the earlier identity.
///
/// This does not make the source tree a hostile-writer snapshot while it is being
/// copied: the materialized tree must itself hash to `expected_base` before replay.
/// The SHA-256 identity is also not an authenticity or provenance statement.
pub fn apply_cow_diff_atomic_with_expected_base(
    base: &Path,
    destination: &Path,
    diff: &CowDiff,
    expected_base: SnapshotIdentity,
    identity_limits: SnapshotIdentityLimits,
    replay_limits: CowDiffApplyLimits,
) -> Result<CowDiffApplyBoundReport, CowDiffApplyError> {
    validate_limits(replay_limits)?;
    let initial = snapshot_sha256(base, identity_limits)
        .map_err(|source| CowDiffApplyError::BaseIdentity { source })?;
    if initial.sha256 != expected_base.sha256 {
        return Err(CowDiffApplyError::BaseIdentityMismatch {
            expected: expected_base,
            actual: initial,
        });
    }

    #[cfg(target_os = "linux")]
    {
        let (replay, materialized) = linux::apply_with_verified_base(
            base,
            destination,
            diff,
            expected_base,
            identity_limits,
            replay_limits,
        )?;
        Ok(CowDiffApplyBoundReport {
            base_identity: materialized,
            replay,
        })
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (destination, diff, expected_base, identity_limits);
        Err(CowDiffApplyError::UnsupportedPlatform(
            "atomic replay requires Linux renameat2 and fd-relative filesystem operations"
                .to_owned(),
        ))
    }
}

fn validate_limits'''
text, count = public_pattern.subn(public_replacement, text, count=1)
if count != 1:
    raise SystemExit(f"public expected-base replacement count={count}")

apply_pattern = re.compile(
    r"    pub\(super\) fn apply\(\n.*?\n    fn validate_diff\(",
    re.S,
)
apply_replacement = '''    pub(super) fn apply(
        base: &Path,
        destination: &Path,
        diff: &CowDiff,
        limits: CowDiffApplyLimits,
    ) -> Result<CowDiffApplyReport, CowDiffApplyError> {
        let (report, materialized) = apply_inner(base, destination, diff, limits, None)?;
        debug_assert!(materialized.is_none());
        Ok(report)
    }

    pub(super) fn apply_with_verified_base(
        base: &Path,
        destination: &Path,
        diff: &CowDiff,
        expected_base: SnapshotIdentity,
        identity_limits: SnapshotIdentityLimits,
        limits: CowDiffApplyLimits,
    ) -> Result<(CowDiffApplyReport, SnapshotIdentity), CowDiffApplyError> {
        let (report, materialized) = apply_inner(
            base,
            destination,
            diff,
            limits,
            Some((expected_base, identity_limits)),
        )?;
        let materialized = materialized.expect("verified replay must return staging identity");
        Ok((report, materialized))
    }

    fn apply_inner(
        base: &Path,
        destination: &Path,
        diff: &CowDiff,
        limits: CowDiffApplyLimits,
        expected_materialized: Option<(SnapshotIdentity, SnapshotIdentityLimits)>,
    ) -> Result<(CowDiffApplyReport, Option<SnapshotIdentity>), CowDiffApplyError> {
        if !base.is_absolute() || !destination.is_absolute() {
            return Err(CowDiffApplyError::InvalidInput(
                "base and destination must be absolute host paths".to_owned(),
            ));
        }
        let validated_paths = validate_diff(diff)?;
        let mut budget = Budget::new(limits, diff.encoded_bytes, diff.entries.len() as u64)?;

        let canonical_base =
            fs::canonicalize(base).map_err(|source| io_error("canonicalize base", source))?;
        let destination_parent = destination.parent().ok_or_else(|| {
            CowDiffApplyError::InvalidInput("destination must have a parent directory".to_owned())
        })?;
        let canonical_parent = fs::canonicalize(destination_parent)
            .map_err(|source| io_error("canonicalize destination parent", source))?;
        if canonical_parent.starts_with(&canonical_base) {
            return Err(CowDiffApplyError::InvalidInput(
                "destination parent must not be the base directory or a descendant of it"
                    .to_owned(),
            ));
        }
        let destination_name = destination.file_name().ok_or_else(|| {
            CowDiffApplyError::InvalidInput(
                "destination must name one snapshot directory".to_owned(),
            )
        })?;
        let destination_name = checked_component(destination_name.as_bytes(), "destination name")?;
        let published_path =
            canonical_parent.join(OsString::from_vec(destination_name.as_bytes().to_vec()));
        match fs::symlink_metadata(&published_path) {
            Ok(_) => {
                return Err(CowDiffApplyError::InvalidInput(
                    "destination already exists".to_owned(),
                ));
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(source) => return Err(io_error("inspect destination", source)),
        }

        let base_fd = open_directory_path(&canonical_base, "open base directory")?;
        let parent_fd = open_directory_path(&canonical_parent, "open destination parent")?;
        let (staging_name, staging_fd) = create_staging(parent_fd.raw())?;

        let replay_result = (|| {
            let mut root_stat = unsafe { std::mem::zeroed::<libc::stat>() };
            if unsafe { libc::fstat(base_fd.raw(), &mut root_stat) } == -1 {
                return Err(io_error("stat base directory", io::Error::last_os_error()));
            }
            let mut directory_modes = BTreeMap::new();
            directory_modes.insert(Vec::new(), (root_stat.st_mode & 0o7777) as u32);
            copy_directory(
                base_fd.raw(),
                staging_fd.raw(),
                &mut budget,
                &mut directory_modes,
                &[],
                0,
            )?;

            let materialized_identity = if let Some((expected, identity_limits)) = expected_materialized
            {
                // The copy phase intentionally keeps directories launcher-writable.
                // Restore the canonical base modes before hashing so the second
                // identity gate observes the same object model as Snapshot 33A.
                restore_directory_modes(staging_fd.raw(), &directory_modes)?;
                let staging_path = canonical_parent
                    .join(OsString::from_vec(staging_name.as_bytes().to_vec()));
                let actual = snapshot_sha256(&staging_path, identity_limits)
                    .map_err(|source| CowDiffApplyError::BaseIdentity { source })?;
                if actual.sha256 != expected.sha256 {
                    return Err(CowDiffApplyError::BaseIdentityMismatch {
                        expected,
                        actual,
                    });
                }
                // Replay mutates this private tree. Re-enable owner write/search
                // authority without changing the canonical modes retained in the
                // directory-mode map; final modes are restored after replay.
                make_directories_writable(staging_fd.raw(), &directory_modes)?;
                Some(actual)
            } else {
                None
            };

            apply_entries(
                staging_fd.raw(),
                diff,
                &validated_paths,
                &mut directory_modes,
            )?;
            restore_directory_modes(staging_fd.raw(), &directory_modes)?;
            atomic_publish(
                parent_fd.raw(),
                staging_name.as_c_str(),
                destination_name.as_c_str(),
            )?;
            Ok((budget.report(), materialized_identity))
        })();

        if let Err(primary) = replay_result {
            if let Err(cleanup) = remove_any(parent_fd.raw(), staging_name.as_c_str()) {
                return Err(CowDiffApplyError::CleanupFailed {
                    primary: primary.to_string(),
                    cleanup: cleanup.to_string(),
                });
            }
            return Err(primary);
        }
        replay_result
    }

    fn validate_diff('''
text, count = apply_pattern.subn(apply_replacement, text, count=1)
if count != 1:
    raise SystemExit(f"linux apply replacement count={count}")

needle = "    fn restore_directory_modes(\n"
insert = '''    fn make_directories_writable(
        root_fd: RawFd,
        directory_modes: &BTreeMap<Vec<u8>, u32>,
    ) -> Result<(), CowDiffApplyError> {
        let mut modes: Vec<_> = directory_modes.iter().collect();
        modes.sort_by(|(left, _), (right, _)| {
            path_depth(left)
                .cmp(&path_depth(right))
                .then_with(|| left.cmp(right))
        });
        for (relative, mode) in modes {
            let directory = open_relative_directory(root_fd, relative)?;
            let writable = *mode | 0o700;
            if unsafe { libc::fchmod(directory.raw(), writable as libc::mode_t) } == -1 {
                return Err(io_error(
                    "prepare verified staging directory for replay",
                    io::Error::last_os_error(),
                ));
            }
        }
        Ok(())
    }

'''
if text.count(needle) != 1:
    raise SystemExit(f"restore_directory_modes needle count={text.count(needle)}")
text = text.replace(needle, insert + needle, 1)

if "materialized_identity_gate_rejects_base_change_after_initial_gate" in text:
    raise SystemExit("test already present")
text += r'''

#[cfg(all(test, target_os = "linux"))]
mod verified_staging_tests {
    use super::*;
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU64, Ordering};

    static COUNTER: AtomicU64 = AtomicU64::new(0);

    struct TempTree(PathBuf);

    impl TempTree {
        fn new() -> Self {
            let id = COUNTER.fetch_add(1, Ordering::Relaxed);
            let root = std::env::temp_dir().join(format!(
                "security-lab-verified-staging-{}-{id}",
                std::process::id()
            ));
            let _ = fs::remove_dir_all(&root);
            fs::create_dir(&root).expect("create verified-staging test root");
            Self(root)
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TempTree {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn identity_limits() -> SnapshotIdentityLimits {
        SnapshotIdentityLimits {
            max_bytes: 1024 * 1024,
            max_nodes: 1024,
        }
    }

    fn replay_limits() -> CowDiffApplyLimits {
        CowDiffApplyLimits {
            max_bytes: 1024 * 1024,
            max_nodes: 1024,
        }
    }

    #[test]
    fn materialized_identity_gate_rejects_base_change_after_initial_gate() {
        let tree = TempTree::new();
        let base = tree.path().join("base");
        let destination = tree.path().join("snapshot");
        fs::create_dir(&base).expect("create base");
        fs::write(base.join("value"), b"expected\n").expect("write expected base");
        let expected = snapshot_sha256(&base, identity_limits()).expect("hash expected base");

        // This private entry point models the exact state immediately after the
        // public 34A early gate has succeeded. A mutation here must be detected
        // by the new materialized-staging gate before diff replay/publication.
        fs::write(base.join("value"), b"mutated-after-first-gate\n")
            .expect("mutate base after simulated first gate");
        let mutated = snapshot_sha256(&base, identity_limits()).expect("hash mutated base");
        assert_ne!(mutated.sha256, expected.sha256);

        let empty = CowDiff {
            entries: Vec::new(),
            encoded_bytes: 6,
        };
        let error = linux::apply_with_verified_base(
            &base,
            &destination,
            &empty,
            expected,
            identity_limits(),
            replay_limits(),
        )
        .expect_err("materialized staging identity must reject post-gate base mutation");

        match error {
            CowDiffApplyError::BaseIdentityMismatch {
                expected: observed_expected,
                actual,
            } => {
                assert_eq!(observed_expected, expected);
                assert_eq!(actual, mutated);
            }
            other => panic!("unexpected verified-staging failure: {other}"),
        }
        assert!(!destination.exists());
        let residue = fs::read_dir(tree.path())
            .expect("read verified-staging parent")
            .filter_map(Result::ok)
            .any(|entry| {
                entry
                    .file_name()
                    .as_encoded_bytes()
                    .starts_with(b".security-lab-cow-apply-")
            });
        assert!(!residue, "verified-staging mismatch left replay residue");
    }
}
'''

path.write_text(text)
