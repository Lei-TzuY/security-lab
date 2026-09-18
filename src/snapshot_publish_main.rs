use security_lab::{
    materialize_snapshot_archive_ed25519_atomic, SnapshotArchiveLimits,
    SNAPSHOT_ED25519_PUBLIC_KEY_BYTES, SNAPSHOT_ED25519_SIGNATURE_BYTES,
};
use std::env;
use std::ffi::{OsStr, OsString};
use std::fmt::Write as _;
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process;

const MAX_ARCHIVE_BYTES: u64 = 1024 * 1024 * 1024;
const MAX_IDENTITY_BYTES: u64 = 1024 * 1024 * 1024;
const MAX_ARCHIVE_NODES: u64 = 100_000;

fn main() {
    match run(env::args_os().collect()) {
        Ok(()) => {}
        Err(CliError::Usage(message)) => {
            eprintln!("{message}");
            process::exit(2);
        }
        Err(CliError::Failure(message)) => {
            eprintln!("snapshot-publish-error: {message}");
            process::exit(1);
        }
    }
}

fn run(args: Vec<OsString>) -> Result<(), CliError> {
    if args.len() != 8 {
        return Err(CliError::Usage(usage(
            args.first().map(OsString::as_os_str),
        )));
    }

    let archive_path = PathBuf::from(&args[1]);
    let public_key_path = PathBuf::from(&args[2]);
    let signature_path = PathBuf::from(&args[3]);
    let destination = PathBuf::from(&args[4]);
    let limits = SnapshotArchiveLimits {
        max_archive_bytes: parse_limit(&args[5], "max-archive-bytes", MAX_ARCHIVE_BYTES)?,
        max_identity_bytes: parse_limit(&args[6], "max-identity-bytes", MAX_IDENTITY_BYTES)?,
        max_nodes: parse_limit(&args[7], "max-nodes", MAX_ARCHIVE_NODES)?,
    };

    let archive = read_bounded(&archive_path, limits.max_archive_bytes, "archive")?;
    let public_key =
        read_exact::<SNAPSHOT_ED25519_PUBLIC_KEY_BYTES>(&public_key_path, "Ed25519 public key")?;
    let signature =
        read_exact::<SNAPSHOT_ED25519_SIGNATURE_BYTES>(&signature_path, "Ed25519 signature")?;

    let report = materialize_snapshot_archive_ed25519_atomic(
        &archive,
        &destination,
        &public_key,
        &signature,
        limits,
    )
    .map_err(|error| CliError::Failure(error.to_string()))?;

    println!(
        "snapshot-published identity={} archive_bytes={} nodes={}",
        hex(&report.identity.sha256),
        report.archive_bytes,
        report.nodes
    );
    Ok(())
}

fn usage(program: Option<&OsStr>) -> String {
    let program = program
        .unwrap_or_else(|| OsStr::new("security-lab-snapshot-publish"))
        .to_string_lossy();
    format!(
        "usage: {program} <archive-file> <public-key-file> <signature-file> <destination> <max-archive-bytes> <max-identity-bytes> <max-nodes>"
    )
}

fn parse_limit(value: &OsStr, label: &'static str, maximum: u64) -> Result<u64, CliError> {
    let text = value
        .to_str()
        .ok_or_else(|| CliError::Usage(format!("{label} must be an ASCII decimal integer")))?;
    let parsed = text
        .parse::<u64>()
        .map_err(|_| CliError::Usage(format!("{label} must be an ASCII decimal integer")))?;
    if parsed == 0 || parsed > maximum {
        return Err(CliError::Usage(format!(
            "{label} must be between 1 and {maximum}"
        )));
    }
    Ok(parsed)
}

fn read_bounded(path: &Path, maximum: u64, label: &str) -> Result<Vec<u8>, CliError> {
    let file = File::open(path).map_err(|error| {
        CliError::Failure(format!(
            "failed to open {label} {}: {error}",
            path.display()
        ))
    })?;
    let mut bytes = Vec::new();
    file.take(maximum + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| {
            CliError::Failure(format!(
                "failed to read {label} {}: {error}",
                path.display()
            ))
        })?;
    if bytes.len() as u64 > maximum {
        return Err(CliError::Failure(format!(
            "{label} {} exceeds declared byte limit {maximum}",
            path.display()
        )));
    }
    Ok(bytes)
}

fn read_exact<const N: usize>(path: &Path, label: &str) -> Result<[u8; N], CliError> {
    let file = File::open(path).map_err(|error| {
        CliError::Failure(format!(
            "failed to open {label} {}: {error}",
            path.display()
        ))
    })?;
    let mut bytes = Vec::new();
    file.take(N as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| {
            CliError::Failure(format!(
                "failed to read {label} {}: {error}",
                path.display()
            ))
        })?;
    if bytes.len() != N {
        return Err(CliError::Failure(format!(
            "{label} {} must contain exactly {N} bytes, got {}",
            path.display(),
            bytes.len()
        )));
    }
    let mut exact = [0u8; N];
    exact.copy_from_slice(&bytes);
    Ok(exact)
}

fn hex(bytes: &[u8]) -> String {
    let mut text = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(&mut text, "{byte:02x}").expect("writing to String cannot fail");
    }
    text
}

enum CliError {
    Usage(String),
    Failure(String),
}
