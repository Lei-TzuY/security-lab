use crate::{
    apply_cow_diff_atomic_with_expected_base, CowDiffApplyBoundReport, CowDiffApplyError,
    CowDiffApplyLimits, CowVolumeDiff,
};
use std::error::Error;
use std::fmt;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

/// Evidence returned after one bound COW-volume diff is materialized as a new
/// host-side snapshot directory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CowVolumePublicationReport {
    pub source: Vec<u8>,
    pub target: Vec<u8>,
    pub replay: CowDiffApplyBoundReport,
}

#[derive(Debug)]
pub enum CowVolumePublicationError {
    UnboundDiff,
    IncompleteBinding,
    SourcePathMismatch {
        expected: Vec<u8>,
        actual: Vec<u8>,
    },
    Apply {
        source: CowDiffApplyError,
    },
}

impl fmt::Display for CowVolumePublicationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnboundDiff => f.write_str(
                "COW volume diff is observation-only and has no launch-time base identity binding",
            ),
            Self::IncompleteBinding => f.write_str(
                "COW volume diff has inconsistent base identity evidence",
            ),
            Self::SourcePathMismatch { expected, actual } => write!(
                f,
                "COW volume publication source path mismatch: expected={:?} actual={:?}",
                String::from_utf8_lossy(expected),
                String::from_utf8_lossy(actual)
            ),
            Self::Apply { source } => write!(f, "COW volume publication failed: {source}"),
        }
    }
}

impl Error for CowVolumePublicationError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Apply { source } => Some(source),
            _ => None,
        }
    }
}

impl From<CowDiffApplyError> for CowVolumePublicationError {
    fn from(source: CowDiffApplyError) -> Self {
        Self::Apply { source }
    }
}

/// Materialize one launcher-exported COW-volume diff as a new host snapshot.
///
/// The report must carry the exact trusted host source pathname, launch-time
/// canonical identity, and the exact identity limits used to produce that
/// evidence. The caller-supplied base path must byte-match the report source.
/// Replay then reuses the existing expected-base verifier, which checks the
/// current base identity before staging and again from the exact bytes copied
/// into staging before applying the diff. Publication is one
/// renameat2(RENAME_NOREPLACE) to a previously absent destination.
///
/// This never overwrites or mutates the configured source tree.
pub fn publish_cow_volume_diff_atomic(
    base: &Path,
    destination: &Path,
    volume_diff: &CowVolumeDiff,
    replay_limits: CowDiffApplyLimits,
) -> Result<CowVolumePublicationReport, CowVolumePublicationError> {
    let actual_source = base.as_os_str().as_bytes().to_vec();
    if actual_source != volume_diff.source {
        return Err(CowVolumePublicationError::SourcePathMismatch {
            expected: volume_diff.source.clone(),
            actual: actual_source,
        });
    }

    let (expected_base, identity_limits) = match (
        volume_diff.base_identity,
        volume_diff.base_identity_limits,
    ) {
        (Some(identity), Some(limits)) => (identity, limits),
        (None, None) => return Err(CowVolumePublicationError::UnboundDiff),
        _ => return Err(CowVolumePublicationError::IncompleteBinding),
    };

    let replay = apply_cow_diff_atomic_with_expected_base(
        base,
        destination,
        &volume_diff.diff,
        expected_base,
        identity_limits,
        replay_limits,
    )?;

    Ok(CowVolumePublicationReport {
        source: volume_diff.source.clone(),
        target: volume_diff.target.clone(),
        replay,
    })
}
