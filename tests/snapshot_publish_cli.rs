#![cfg(target_os = "linux")]

use security_lab::{
    serialize_snapshot_archive, sign_snapshot_ed25519, SnapshotArchiveLimits,
    SnapshotIdentityLimits, SNAPSHOT_ED25519_SIGNING_KEY_BYTES,
};
use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{self, Command, Output};
use std::sync::atomic::{AtomicUsize, Ordering};

static NEXT_WORKSPACE: AtomicUsize = AtomicUsize::new(0);

struct TempWorkspace(PathBuf);

impl TempWorkspace {
    fn new(label: &str) -> Self {
        let sequence = NEXT_WORKSPACE.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "security-lab-snapshot-publish-{}-{sequence}-{label}",
            process::id()
        ));
        let _ = fs::remove_dir_all(&path);
        fs::create_dir(&path).expect("create snapshot publication CLI workspace");
        Self(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempWorkspace {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

struct Fixture {
    _workspace: TempWorkspace,
    source: PathBuf,
    archive: PathBuf,
    public_key: PathBuf,
    signature: PathBuf,
    destination: PathBuf,
    archive_bytes: usize,
    identity_hex: String,
}

fn archive_limits() -> SnapshotArchiveLimits {
    SnapshotArchiveLimits {
        max_archive_bytes: 1024 * 1024,
        max_identity_bytes: 1024 * 1024,
        max_nodes: 64,
    }
}

fn identity_limits() -> SnapshotIdentityLimits {
    SnapshotIdentityLimits {
        max_bytes: 1024 * 1024,
        max_nodes: 64,
    }
}

fn fixture(label: &str) -> Fixture {
    let workspace = TempWorkspace::new(label);
    let source = workspace.path().join("source");
    fs::create_dir(&source).expect("create snapshot source");
    fs::write(source.join("payload"), b"verified-publication\n").expect("write root payload");
    fs::create_dir(source.join("nested")).expect("create nested directory");
    fs::write(source.join("nested/value"), b"nested-value\n").expect("write nested payload");

    let archive = serialize_snapshot_archive(&source, archive_limits()).expect("serialize fixture");
    let signing_seed = [0x42; SNAPSHOT_ED25519_SIGNING_KEY_BYTES];
    let evidence = sign_snapshot_ed25519(&source, &signing_seed, identity_limits())
        .expect("sign fixture snapshot");
    assert_eq!(
        archive.identity, evidence.snapshot,
        "archive and signature must bind the same canonical snapshot identity"
    );

    let archive_path = workspace.path().join("snapshot.archive");
    let public_key_path = workspace.path().join("snapshot.pub");
    let signature_path = workspace.path().join("snapshot.sig");
    fs::write(&archive_path, &archive.bytes).expect("write archive fixture");
    fs::write(&public_key_path, evidence.public_key).expect("write public-key fixture");
    fs::write(&signature_path, evidence.signature).expect("write signature fixture");

    Fixture {
        destination: workspace.path().join("published"),
        archive_bytes: archive.bytes.len(),
        identity_hex: hex(&archive.identity.sha256),
        _workspace: workspace,
        source,
        archive: archive_path,
        public_key: public_key_path,
        signature: signature_path,
    }
}

fn publish(fixture: &Fixture, destination: &Path, max_archive_bytes: u64) -> Output {
    Command::new(env!("CARGO_BIN_EXE_security-lab-snapshot-publish"))
        .arg(&fixture.archive)
        .arg(&fixture.public_key)
        .arg(&fixture.signature)
        .arg(destination)
        .arg(max_archive_bytes.to_string())
        .arg(archive_limits().max_identity_bytes.to_string())
        .arg(archive_limits().max_nodes.to_string())
        .output()
        .expect("run snapshot publication CLI")
}

#[test]
fn authenticated_archive_cli_materializes_exact_tree() {
    let fixture = fixture("success");
    let output = publish(
        &fixture,
        &fixture.destination,
        archive_limits().max_archive_bytes,
    );
    assert_eq!(output.status.code(), Some(0));
    let stdout = String::from_utf8(output.stdout).expect("utf8 stdout");
    assert!(stdout.contains("snapshot-published"));
    assert!(stdout.contains(&format!("identity={}", fixture.identity_hex)));
    assert!(stdout.contains(&format!("archive_bytes={}", fixture.archive_bytes)));
    assert_eq!(
        fs::read(fixture.destination.join("payload")).expect("read published root payload"),
        b"verified-publication\n"
    );
    assert_eq!(
        fs::read(fixture.destination.join("nested/value")).expect("read published nested payload"),
        b"nested-value\n"
    );
}

#[test]
fn wrong_public_key_fails_before_publication() {
    let fixture = fixture("wrong-key");
    let wrong = sign_snapshot_ed25519(
        &fixture.source,
        &[0x43; SNAPSHOT_ED25519_SIGNING_KEY_BYTES],
        identity_limits(),
    )
    .expect("derive wrong public key");
    fs::write(&fixture.public_key, wrong.public_key).expect("replace public key fixture");

    let output = publish(
        &fixture,
        &fixture.destination,
        archive_limits().max_archive_bytes,
    );
    assert_eq!(output.status.code(), Some(1));
    let stderr = String::from_utf8(output.stderr).expect("utf8 stderr");
    assert!(stderr.contains("signature verification failed"));
    assert!(
        !fixture.destination.exists(),
        "unauthenticated archive must not be published"
    );
}

#[test]
fn archive_input_budget_fails_before_publication() {
    let fixture = fixture("archive-budget");
    let smaller_limit = u64::try_from(fixture.archive_bytes - 1).expect("archive length fits u64");
    let output = publish(&fixture, &fixture.destination, smaller_limit);
    assert_eq!(output.status.code(), Some(1));
    let stderr = String::from_utf8(output.stderr).expect("utf8 stderr");
    assert!(stderr.contains("exceeds declared byte limit"));
    assert!(
        !fixture.destination.exists(),
        "over-budget archive must not reach publication"
    );
}

#[test]
fn credential_files_require_exact_lengths() {
    let fixture = fixture("credential-length");
    fs::write(&fixture.public_key, [0u8; 31]).expect("write short public key");
    let key_destination = fixture._workspace.path().join("bad-key-destination");
    let key_output = publish(
        &fixture,
        &key_destination,
        archive_limits().max_archive_bytes,
    );
    assert_eq!(key_output.status.code(), Some(1));
    assert!(String::from_utf8(key_output.stderr)
        .expect("utf8 key stderr")
        .contains("must contain exactly 32 bytes"));
    assert!(!key_destination.exists());

    let signing_seed = [0x42; SNAPSHOT_ED25519_SIGNING_KEY_BYTES];
    let evidence = sign_snapshot_ed25519(&fixture.source, &signing_seed, identity_limits())
        .expect("recreate valid credentials");
    fs::write(&fixture.public_key, evidence.public_key).expect("restore public key");
    fs::write(&fixture.signature, [0u8; 63]).expect("write short signature");
    let signature_destination = fixture._workspace.path().join("bad-signature-destination");
    let signature_output = publish(
        &fixture,
        &signature_destination,
        archive_limits().max_archive_bytes,
    );
    assert_eq!(signature_output.status.code(), Some(1));
    assert!(String::from_utf8(signature_output.stderr)
        .expect("utf8 signature stderr")
        .contains("must contain exactly 64 bytes"));
    assert!(!signature_destination.exists());
}

fn hex(bytes: &[u8]) -> String {
    let mut text = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(&mut text, "{byte:02x}").expect("writing to String cannot fail");
    }
    text
}
