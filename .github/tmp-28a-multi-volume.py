from pathlib import Path
import re


def replace_one(path: str, old: str, new: str, label: str) -> None:
    p = Path(path)
    text = p.read_text()
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{label}: expected exactly one match, got {count}")
    p.write_text(text.replace(old, new, 1))


def sub_one(path: str, pattern: str, repl: str, label: str, flags: int = 0) -> None:
    p = Path(path)
    text = p.read_text()
    new, count = re.subn(pattern, repl, text, count=1, flags=flags)
    if count != 1:
        raise SystemExit(f"{label}: expected exactly one regex match, got {count}")
    p.write_text(new)


# ---------------- policy model / parser / validation ----------------
replace_one(
    "src/policy.rs",
    "const MAX_SELECTED_HANDLES: usize = 16;\n",
    "const MAX_SELECTED_HANDLES: usize = 16;\nconst MAX_PERSISTENT_VOLUMES: usize = 8;\nconst MAX_PERSISTENT_VOLUME_NAME_BYTES: usize = 32;\n",
    "policy constants",
)

replace_one(
    "src/policy.rs",
    "#[derive(Debug, Clone, Copy, PartialEq, Eq)]\npub struct StdioPolicy {\n    pub stdin: StdioMode,\n    pub stdout: StdioMode,\n    pub stderr: StdioMode,\n}\n",
    "#[derive(Debug, Clone, Copy, PartialEq, Eq)]\npub struct StdioPolicy {\n    pub stdin: StdioMode,\n    pub stdout: StdioMode,\n    pub stderr: StdioMode,\n}\n\n#[derive(Debug, Clone, Copy, PartialEq, Eq)]\npub enum PersistentVolumeAccess {\n    ReadOnly,\n    Writable,\n}\n\n#[derive(Debug, Clone, PartialEq, Eq)]\npub struct PersistentVolumePolicy {\n    pub source: PathBuf,\n    pub target: PathBuf,\n    pub access: PersistentVolumeAccess,\n}\n\n#[derive(Default)]\nstruct PendingPersistentVolume {\n    source: Option<String>,\n    target: Option<String>,\n    access: Option<PersistentVolumeAccess>,\n}\n",
    "persistent volume policy types",
)

replace_one(
    "src/policy.rs",
    "    pub writable_volume_source: Option<PathBuf>,\n    pub writable_volume_target: Option<PathBuf>,\n",
    "    pub writable_volume_source: Option<PathBuf>,\n    pub writable_volume_target: Option<PathBuf>,\n    /// Optional bounded graph of named persistent host-directory mounts. Legacy\n    /// single read-only/writable fields remain supported and compose with this map.\n    pub persistent_volumes: BTreeMap<String, PersistentVolumePolicy>,\n",
    "persistent volume policy field",
)

replace_one(
    "src/policy.rs",
    "            for (path, label) in [\n                (&self.scratch_dir, \"filesystem.scratch\"),\n                (&self.readonly_volume_target, \"volume.readonly_target\"),\n                (&self.writable_volume_target, \"volume.writable_target\"),\n            ] {\n                if let Some(path) = path {\n                    if path.starts_with(proc_path) || proc_path.starts_with(path) {\n                        return Err(PolicyError::new(format!(\n                            \"filesystem.proc must not overlap {label}\"\n                        )));\n                    }\n                }\n            }\n",
    "            for (path, label) in [\n                (&self.scratch_dir, \"filesystem.scratch\"),\n                (&self.readonly_volume_target, \"volume.readonly_target\"),\n                (&self.writable_volume_target, \"volume.writable_target\"),\n            ] {\n                if let Some(path) = path {\n                    if path.starts_with(proc_path) || proc_path.starts_with(path) {\n                        return Err(PolicyError::new(format!(\n                            \"filesystem.proc must not overlap {label}\"\n                        )));\n                    }\n                }\n            }\n            for (name, volume) in &self.persistent_volumes {\n                if volume.target.starts_with(proc_path) || proc_path.starts_with(&volume.target) {\n                    return Err(PolicyError::new(format!(\n                        \"filesystem.proc must not overlap volume.mount.{name}.target\"\n                    )));\n                }\n            }\n",
    "procfs named volume overlap",
)

replace_one(
    "src/policy.rs",
    "                let in_writable_volume = self\n                    .writable_volume_target\n                    .as_ref()\n                    .is_some_and(|target| path.starts_with(target));\n                if !in_scratch && !in_writable_volume {\n                    return Err(PolicyError::new(\n                        \"landlock.file_mutate must be within filesystem.scratch or volume.writable_target\",\n                    ));\n                }\n",
    "                let in_writable_volume = self\n                    .writable_volume_target\n                    .as_ref()\n                    .is_some_and(|target| path.starts_with(target))\n                    || self.persistent_volumes.values().any(|volume| {\n                        volume.access == PersistentVolumeAccess::Writable\n                            && path.starts_with(&volume.target)\n                    });\n                if !in_scratch && !in_writable_volume {\n                    return Err(PolicyError::new(\n                        \"landlock.file_mutate must be within filesystem.scratch or a writable persistent volume target\",\n                    ));\n                }\n",
    "Landlock named writable volume containment",
)

# Replace the legacy-only volume validation block with a graph-wide validator.
sub_one(
    "src/policy.rs",
    r"        match \(&self\.readonly_volume_source, &self\.readonly_volume_target\) \{.*?\n        match \(&self\.scratch_dir, self\.scratch_bytes\) \{",
    '''        let legacy_volume_count = usize::from(self.readonly_volume_source.is_some())
            + usize::from(self.writable_volume_source.is_some());
        if legacy_volume_count + self.persistent_volumes.len() > MAX_PERSISTENT_VOLUMES {
            return Err(PolicyError::new(format!(
                "too many persistent volumes: {} > {MAX_PERSISTENT_VOLUMES}",
                legacy_volume_count + self.persistent_volumes.len()
            )));
        }

        let mut persistent_sources: Vec<&Path> = Vec::with_capacity(MAX_PERSISTENT_VOLUMES);
        let mut persistent_targets: Vec<&Path> = Vec::with_capacity(MAX_PERSISTENT_VOLUMES);

        match (&self.readonly_volume_source, &self.readonly_volume_target) {
            (None, None) => {}
            (Some(source), Some(target)) => {
                validate_persistent_volume_paths(self, "volume.readonly", source, target)?;
                persistent_sources.push(source);
                persistent_targets.push(target);
            }
            _ => {
                return Err(PolicyError::new(
                    "volume.readonly_source and volume.readonly_target must be specified together",
                ));
            }
        }

        match (&self.writable_volume_source, &self.writable_volume_target) {
            (None, None) => {}
            (Some(source), Some(target)) => {
                validate_persistent_volume_paths(self, "volume.writable", source, target)?;
                persistent_sources.push(source);
                persistent_targets.push(target);
            }
            _ => {
                return Err(PolicyError::new(
                    "volume.writable_source and volume.writable_target must be specified together",
                ));
            }
        }

        for (name, volume) in &self.persistent_volumes {
            validate_persistent_volume_name(name)?;
            validate_persistent_volume_paths(
                self,
                &format!("volume.mount.{name}"),
                &volume.source,
                &volume.target,
            )?;
            persistent_sources.push(&volume.source);
            persistent_targets.push(&volume.target);
        }

        for index in 0..persistent_sources.len() {
            for other in (index + 1)..persistent_sources.len() {
                let left = persistent_sources[index];
                let right = persistent_sources[other];
                if left.starts_with(right) || right.starts_with(left) {
                    return Err(PolicyError::new(
                        "persistent volume source paths must not overlap",
                    ));
                }
                let left = persistent_targets[index];
                let right = persistent_targets[other];
                if left.starts_with(right) || right.starts_with(left) {
                    return Err(PolicyError::new(
                        "persistent volume target paths must not overlap",
                    ));
                }
            }
        }

        match (&self.scratch_dir, self.scratch_bytes) {''',
    "graph-wide persistent volume validation",
    re.S,
)

replace_one(
    "src/policy.rs",
    "        let mut writable_volume_source = None;\n        let mut writable_volume_target = None;\n",
    "        let mut writable_volume_source = None;\n        let mut writable_volume_target = None;\n        let mut pending_persistent_volumes: BTreeMap<String, PendingPersistentVolume> =\n            BTreeMap::new();\n",
    "parser named volume accumulator",
)

replace_one(
    "src/policy.rs",
    "                \"filesystem.scratch\" => set_once(&mut scratch_dir, value.to_owned(), line_no, key)?,\n",
    "                _ if key.starts_with(\"volume.mount.\") => {\n                    let spec = key\n                        .strip_prefix(\"volume.mount.\")\n                        .expect(\"prefix checked above\");\n                    let (name, field) = spec.rsplit_once('.').ok_or_else(|| {\n                        PolicyError::at(\n                            line_no,\n                            \"named volume key must be volume.mount.<name>.<source|target|access>\",\n                        )\n                    })?;\n                    validate_persistent_volume_name(name)\n                        .map_err(|error| PolicyError::at(line_no, error.message))?;\n                    let pending = pending_persistent_volumes.entry(name.to_owned()).or_default();\n                    match field {\n                        \"source\" => set_once(&mut pending.source, value.to_owned(), line_no, key)?,\n                        \"target\" => set_once(&mut pending.target, value.to_owned(), line_no, key)?,\n                        \"access\" => set_once(\n                            &mut pending.access,\n                            parse_persistent_volume_access(value, line_no, key)?,\n                            line_no,\n                            key,\n                        )?,\n                        _ => {\n                            return Err(PolicyError::at(\n                                line_no,\n                                \"named volume field must be source, target, or access\",\n                            ));\n                        }\n                    }\n                }\n                \"filesystem.scratch\" => set_once(&mut scratch_dir, value.to_owned(), line_no, key)?,\n",
    "parser named volume dynamic keys",
)

replace_one(
    "src/policy.rs",
    "        let policy = Self {\n",
    "        let mut persistent_volumes = BTreeMap::new();\n        for (name, pending) in pending_persistent_volumes {\n            let source = pending.source.ok_or_else(|| {\n                PolicyError::new(format!(\"missing required key: volume.mount.{name}.source\"))\n            })?;\n            let target = pending.target.ok_or_else(|| {\n                PolicyError::new(format!(\"missing required key: volume.mount.{name}.target\"))\n            })?;\n            let access = pending.access.ok_or_else(|| {\n                PolicyError::new(format!(\"missing required key: volume.mount.{name}.access\"))\n            })?;\n            persistent_volumes.insert(\n                name,\n                PersistentVolumePolicy {\n                    source: PathBuf::from(source),\n                    target: PathBuf::from(target),\n                    access,\n                },\n            );\n        }\n\n        let policy = Self {\n",
    "parser finalize named volumes",
)

replace_one(
    "src/policy.rs",
    "            writable_volume_source: writable_volume_source.map(PathBuf::from),\n            writable_volume_target: writable_volume_target.map(PathBuf::from),\n",
    "            writable_volume_source: writable_volume_source.map(PathBuf::from),\n            writable_volume_target: writable_volume_target.map(PathBuf::from),\n            persistent_volumes,\n",
    "parser construct named volumes",
)

replace_one(
    "src/policy.rs",
    "fn set_once<T>(\n",
    '''fn validate_persistent_volume_name(name: &str) -> Result<(), PolicyError> {
    if name.is_empty() || name.len() > MAX_PERSISTENT_VOLUME_NAME_BYTES {
        return Err(PolicyError::new(format!(
            "persistent volume name must contain 1..={MAX_PERSISTENT_VOLUME_NAME_BYTES} bytes"
        )));
    }
    let bytes = name.as_bytes();
    if !bytes[0].is_ascii_alphanumeric()
        || !bytes
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err(PolicyError::new(format!(
            "invalid persistent volume name: {name:?}"
        )));
    }
    Ok(())
}

fn validate_persistent_volume_paths(
    policy: &SandboxPolicy,
    label: &str,
    source: &Path,
    target: &Path,
) -> Result<(), PolicyError> {
    validate_absolute_path(&format!("{label}.source"), source)?;
    validate_absolute_path(&format!("{label}.target"), target)?;
    if source.starts_with(&policy.root_dir) || policy.root_dir.starts_with(source) {
        return Err(PolicyError::new(format!(
            "{label}.source must not overlap filesystem.root"
        )));
    }
    if target == Path::new("/") {
        return Err(PolicyError::new(format!(
            "{label}.target must not replace the sandbox root"
        )));
    }
    if policy.executable.starts_with(target) || policy.working_dir.starts_with(target) {
        return Err(PolicyError::new(format!(
            "{label}.target must not contain the executable or working_dir"
        )));
    }
    if let Some(scratch) = &policy.scratch_dir {
        if target.starts_with(scratch) || scratch.starts_with(target) {
            return Err(PolicyError::new(format!(
                "{label}.target must not overlap filesystem.scratch"
            )));
        }
    }
    if policy.procfs_enabled {
        let proc_path = Path::new("/proc");
        if target.starts_with(proc_path) || proc_path.starts_with(target) {
            return Err(PolicyError::new(format!(
                "{label}.target must not overlap filesystem.proc"
            )));
        }
    }
    Ok(())
}

fn parse_persistent_volume_access(
    value: &str,
    line: usize,
    key: &str,
) -> Result<PersistentVolumeAccess, PolicyError> {
    match value {
        "read-only" => Ok(PersistentVolumeAccess::ReadOnly),
        "writable" => Ok(PersistentVolumeAccess::Writable),
        _ => Err(PolicyError::at(
            line,
            format!("{key} must be read-only or writable"),
        )),
    }
}

fn set_once<T>(
''',
    "persistent volume helpers",
)

# Unit tests: named parsing and graph validation.
insert_marker = "    #[test]\n    fn parses_stdout_redirect_inside_scratch() {\n"
policy_tests = '''    #[test]
    fn parses_bounded_named_persistent_volume_graph() {
        let base = volume_valid();
        let text = format!(
            "{base}\\
volume.mount.assets.source = /srv/assets\\
volume.mount.assets.target = /assets\\
volume.mount.assets.access = read-only\\
volume.mount.state.source = /srv/state\\
volume.mount.state.target = /state\\
volume.mount.state.access = writable"
        );
        let policy: SandboxPolicy = text.parse().unwrap();
        assert_eq!(policy.persistent_volumes.len(), 2);
        assert_eq!(
            policy.persistent_volumes["assets"].access,
            PersistentVolumeAccess::ReadOnly
        );
        assert_eq!(
            policy.persistent_volumes["state"].access,
            PersistentVolumeAccess::Writable
        );
    }

    #[test]
    fn rejects_incomplete_overlapping_or_oversized_named_volume_graph() {
        let base = volume_valid();
        let incomplete = format!(
            "{base}\\
volume.mount.assets.source = /srv/assets\\
volume.mount.assets.target = /assets"
        );
        assert!(incomplete.parse::<SandboxPolicy>().is_err());

        let overlapping_targets = format!(
            "{base}\\
volume.mount.a.source = /srv/a\\
volume.mount.a.target = /data\\
volume.mount.a.access = read-only\\
volume.mount.b.source = /srv/b\\
volume.mount.b.target = /data/nested\\
volume.mount.b.access = writable"
        );
        let error = overlapping_targets.parse::<SandboxPolicy>().unwrap_err();
        assert!(error.to_string().contains("target paths must not overlap"));

        let mut oversized = base;
        for index in 0..9 {
            oversized.push_str(&format!(
                "volume.mount.v{index}.source = /srv/v{index}\\nvolume.mount.v{index}.target = /v{index}\\nvolume.mount.v{index}.access = read-only\\n"
            ));
        }
        let error = oversized.parse::<SandboxPolicy>().unwrap_err();
        assert!(error.to_string().contains("too many persistent volumes"));
    }

'''
replace_one("src/policy.rs", insert_marker, policy_tests + insert_marker, "named volume policy tests")

# ---------------- public exports ----------------
replace_one(
    "src/lib.rs",
    "    PolicyError, ResourceLimits, SandboxPolicy, SeccompArgRangeRule, SeccompArgRule, SeccompPolicy,\n    StdioMode, StdioPolicy,\n",
    "    PersistentVolumeAccess, PersistentVolumePolicy, PolicyError, ResourceLimits, SandboxPolicy,\n    SeccompArgRangeRule, SeccompArgRule, SeccompPolicy, StdioMode, StdioPolicy,\n",
    "public persistent volume exports",
)

# ---------------- Linux runtime preparation ----------------
replace_one(
    "src/platform/linux.rs",
    "        CancellationToken, CapturedOutput, ChildOutcome, EnforcementReceipt, PolicyError,\n        ProcessTreeUsage, ResourceLimits, RunReport, SandboxError, SandboxPolicy,\n",
    "        CancellationToken, CapturedOutput, ChildOutcome, EnforcementReceipt, PersistentVolumeAccess,\n        PolicyError, ProcessTreeUsage, ResourceLimits, RunReport, SandboxError, SandboxPolicy,\n",
    "runtime persistent volume import",
)
replace_one(
    "src/platform/linux.rs",
    "            let mut volumes = Vec::with_capacity(2);\n",
    "            let mut volumes = Vec::with_capacity(2 + policy.persistent_volumes.len());\n",
    "runtime volume capacity",
)
replace_one(
    "src/platform/linux.rs",
    "            let cwd_relative = sandbox_relative(&policy.working_dir)?;\n",
    '''            for (name, volume) in &policy.persistent_volumes {
                let access = match volume.access {
                    PersistentVolumeAccess::ReadOnly => VolumeAccess::ReadOnly,
                    PersistentVolumeAccess::Writable => VolumeAccess::Writable,
                };
                let source_field = format!("volume.mount.{name}.source");
                volumes.push(prepare_volume(
                    root_fd.raw(),
                    &volume.source,
                    &volume.target,
                    &source_field,
                    "named persistent volume source",
                    "named persistent volume target",
                    access,
                )?);
            }

            let cwd_relative = sandbox_relative(&policy.working_dir)?;
''',
    "runtime named volume preparation",
)

# ---------------- configured filesystem preflight ----------------
replace_one(
    "src/policy_preflight/configured_filesystem_probe.rs",
    "        ConfiguredFilesystemProbe::available()\n",
    '''        for volume in policy.persistent_volumes.values() {
            if let Err(result) = require_host_directory(&volume.source, "persistent_volume_source_open") {
                return result;
            }
            if let Err(result) =
                require_beneath_directory(root.raw(), &volume.target, "persistent_volume_target_open")
            {
                return result;
            }
        }

        ConfiguredFilesystemProbe::available()
''',
    "preflight named volumes",
)

# ---------------- static authority manifest ----------------
replace_one(
    "src/authority_manifest.rs",
    "use security_lab::{SandboxPolicy, StdioMode};\n",
    "use security_lab::{PersistentVolumeAccess, SandboxPolicy, StdioMode};\n",
    "manifest access import",
)
replace_one(
    "src/authority_manifest.rs",
    "    output.push('}');\n\n    output.push_str(\",\\\"network\\\":{\\\"isolated_loopback_enabled\\\":\");\n",
    '''    output.push_str(",\\\"persistent_volumes\\\":[");
    let mut first_volume = true;
    for (name, volume) in &policy.persistent_volumes {
        if !first_volume {
            output.push(',');
        }
        first_volume = false;
        output.push_str("{\\\"name\\\":");
        push_json_string(&mut output, name);
        output.push_str(",\\\"source\\\":");
        push_path(&mut output, &volume.source);
        output.push_str(",\\\"target\\\":");
        push_path(&mut output, &volume.target);
        output.push_str(",\\\"access\\\":");
        push_json_string(
            &mut output,
            match volume.access {
                PersistentVolumeAccess::ReadOnly => "read_only",
                PersistentVolumeAccess::Writable => "writable",
            },
        );
        output.push('}');
    }
    output.push_str("]}");

    output.push_str(",\\\"network\\\":{\\\"isolated_loopback_enabled\\\":");
''',
    "manifest named volumes JSON",
)
replace_one(
    "src/authority_manifest.rs",
    "        \"host-filesystem-volumes: read-only={} writable={}\",\n        policy.readonly_volume_source.is_some() as u8,\n        policy.writable_volume_source.is_some() as u8\n",
    "        \"host-filesystem-volumes: read-only={} writable={} named={}\",\n        policy.readonly_volume_source.is_some() as u8,\n        policy.writable_volume_source.is_some() as u8,\n        policy.persistent_volumes.len()\n",
    "manifest named volume human count",
)

# ---------------- static authority delta ----------------
replace_one(
    "src/authority_delta.rs",
    "    compare_positive_bool(\n        \"network.isolated_loopback_enabled\",\n",
    '''    push_change(
        "filesystem.persistent_volumes",
        subset_relation(
            map_is_subset(&baseline.persistent_volumes, &candidate.persistent_volumes),
            map_is_subset(&candidate.persistent_volumes, &baseline.persistent_volumes),
            true,
        ),
        &mut changes,
    );

    compare_positive_bool(
        "network.isolated_loopback_enabled",
''',
    "authority delta named volumes",
)

# ---------------- sandbox integration evidence ----------------
replace_one(
    "tests/sandbox.rs",
    "    SandboxError, SandboxPolicy, SeccompArgRangeRule, SeccompArgRule, SeccompPolicy, StdioMode,\n    StdioPolicy,\n",
    "    PersistentVolumeAccess, PersistentVolumePolicy, SandboxError, SandboxPolicy,\n    SeccompArgRangeRule, SeccompArgRule, SeccompPolicy, StdioMode, StdioPolicy,\n",
    "sandbox persistent volume imports",
)
replace_one(
    "tests/sandbox.rs",
    "        std::fs::create_dir_all(root.join(\"data\")).expect(\"create sandbox volume mountpoint\");\n",
    "        std::fs::create_dir_all(root.join(\"data\")).expect(\"create sandbox volume mountpoint\");\n        std::fs::create_dir_all(root.join(\"data2\"))\n            .expect(\"create second sandbox volume mountpoint\");\n",
    "second volume target fixture",
)
replace_one(
    "tests/sandbox.rs",
    "fn writable_volume_source() -> &'static Path {\n",
    '''fn readonly_volume_source_two() -> &'static Path {
    static SOURCE: OnceLock<PathBuf> = OnceLock::new();
    SOURCE
        .get_or_init(|| {
            let source = std::env::temp_dir()
                .join(format!("security-lab-volume-two-{}", process::id()));
            let _ = std::fs::remove_dir_all(&source);
            std::fs::create_dir_all(&source).expect("create second persistent volume source");
            std::fs::write(source.join("marker"), b"volume-marker\\n")
                .expect("write second persistent volume marker");
            source
        })
        .as_path()
}

fn writable_volume_source() -> &'static Path {
''',
    "second readonly source fixture",
)
replace_one(
    "tests/sandbox.rs",
    "        writable_volume_source: None,\n        writable_volume_target: None,\n",
    "        writable_volume_source: None,\n        writable_volume_target: None,\n        persistent_volumes: BTreeMap::new(),\n",
    "sandbox policy named volumes default",
)

# Insert the multi-volume integration immediately before selected handle tests.
marker = "#[test]\nfn selected_nonstdio_handle_is_exposed_only_at_declared_destination() {\n"
integration = '''#[test]
fn named_persistent_volume_graph_mounts_three_mixed_access_volumes() {
    let first = readonly_volume_source().to_path_buf();
    let second = readonly_volume_source_two().to_path_buf();
    let writable = writable_volume_source().to_path_buf();
    let persisted = writable.join("persisted");
    let _ = std::fs::remove_file(&persisted);
    let forbidden = first.join("write-must-fail");
    let _ = std::fs::remove_file(&forbidden);

    let mut mounted = policy(
        "z",
        &[],
        &["execveat", "openat", "read", "write", "close", "exit"],
    );
    mounted.persistent_volumes.insert(
        "assets-a".to_owned(),
        PersistentVolumePolicy {
            source: first.clone(),
            target: PathBuf::from("/data"),
            access: PersistentVolumeAccess::ReadOnly,
        },
    );
    mounted.persistent_volumes.insert(
        "assets-b".to_owned(),
        PersistentVolumePolicy {
            source: second.clone(),
            target: PathBuf::from("/data2"),
            access: PersistentVolumeAccess::ReadOnly,
        },
    );
    mounted.persistent_volumes.insert(
        "state".to_owned(),
        PersistentVolumePolicy {
            source: writable.clone(),
            target: PathBuf::from("/persist"),
            access: PersistentVolumeAccess::Writable,
        },
    );

    assert_eq!(run(&mounted).unwrap(), ChildOutcome::Exited(0));
    assert_eq!(
        std::fs::read(first.join("marker")).expect("read first named volume marker"),
        b"volume-marker\\n"
    );
    assert_eq!(
        std::fs::read(second.join("marker")).expect("read second named volume marker"),
        b"volume-marker\\n"
    );
    assert!(!forbidden.exists(), "named read-only volume accepted a write");
    assert_eq!(
        std::fs::read(&persisted).expect("read named writable volume output"),
        b"persistent-write\\n"
    );
}

'''
replace_one("tests/sandbox.rs", marker, integration + marker, "multi-volume integration")

# ---------------- raw syscall oracle ----------------
replace_one(
    "tests/fixtures/probe.S",
    "#   w write through a declared persistent volume while root and host source paths stay confined\n",
    "#   w write through a declared persistent volume while root and host source paths stay confined\n#   z prove three named persistent volumes compose: two read-only plus one writable\n",
    "fixture mode documentation",
)
replace_one(
    "tests/fixtures/probe.S",
    "    cmp $119, %al\n    je .writable_volume\n",
    "    cmp $119, %al\n    je .writable_volume\n    cmp $122, %al\n    je .named_volume_graph\n",
    "fixture mode dispatch",
)
replace_one(
    "tests/fixtures/probe.S",
    ".loopback_networking:\n",
    '''.named_volume_graph:
    # First read-only mount.
    mov $257, %eax
    mov $-100, %edi
    lea volume_marker_path(%rip), %rsi
    xor %edx, %edx
    xor %r10d, %r10d
    syscall
    test %rax, %rax
    js .fail49
    mov %rax, %r12
    xor %eax, %eax
    mov %r12, %rdi
    lea volume_buffer(%rip), %rsi
    mov $volume_marker_len, %edx
    syscall
    cmp $volume_marker_len, %rax
    jne .fail49
    mov $3, %eax
    mov %r12, %rdi
    syscall
    test %rax, %rax
    js .fail49

    # Second read-only mount proves the graph exceeds the legacy one-RO slot.
    mov $257, %eax
    mov $-100, %edi
    lea volume_marker_path_two(%rip), %rsi
    xor %edx, %edx
    xor %r10d, %r10d
    syscall
    test %rax, %rax
    js .fail49
    mov %rax, %r12
    xor %eax, %eax
    mov %r12, %rdi
    lea volume_buffer(%rip), %rsi
    mov $volume_marker_len, %edx
    syscall
    cmp $volume_marker_len, %rax
    jne .fail49
    mov $3, %eax
    mov %r12, %rdi
    syscall
    test %rax, %rax
    js .fail49

    # Read-only enforcement remains active.
    mov $257, %eax
    mov $-100, %edi
    lea volume_forbidden_write(%rip), %rsi
    mov $577, %edx
    mov $384, %r10d
    syscall
    cmp $-30, %rax
    jne .fail49

    # Named writable mount persists bytes.
    mov $257, %eax
    mov $-100, %edi
    lea writable_volume_output(%rip), %rsi
    mov $577, %edx
    mov $384, %r10d
    syscall
    test %rax, %rax
    js .fail49
    mov %rax, %r12
    mov $1, %eax
    mov %r12, %rdi
    lea writable_volume_message(%rip), %rsi
    mov $writable_volume_message_len, %edx
    syscall
    cmp $writable_volume_message_len, %rax
    jne .fail49
    mov $3, %eax
    mov %r12, %rdi
    syscall
    test %rax, %rax
    js .fail49

    # Surrounding root stays read-only.
    mov $257, %eax
    mov $-100, %edi
    lea forbidden_create(%rip), %rsi
    mov $577, %edx
    mov $384, %r10d
    syscall
    cmp $-30, %rax
    jne .fail49
    xor %edi, %edi
    jmp .exit

.loopback_networking:
''',
    "named volume raw oracle",
)
replace_one(
    "tests/fixtures/probe.S",
    ".fail48:\n    mov $48, %edi\n\n.exit:\n",
    ".fail48:\n    mov $48, %edi\n    jmp .exit\n.fail49:\n    mov $49, %edi\n\n.exit:\n",
    "fixture fail49",
)
replace_one(
    "tests/fixtures/probe.S",
    "volume_forbidden_write:\n    .asciz \"/data/write-must-fail\"\n",
    "volume_forbidden_write:\n    .asciz \"/data/write-must-fail\"\nvolume_marker_path_two:\n    .asciz \"/data2/marker\"\n",
    "second named volume path",
)

# Add manifest CLI evidence for deterministic named authority visibility.
marker = "#[test]\nfn manifest_json_rejects_invalid_policy_fail_closed() {\n"
manifest_test = '''#[test]
fn manifest_json_lists_named_persistent_volumes_deterministically() {
    let root = root_path("named-volumes");
    let mut text = manifest_policy(&root);
    text.push_str(
        "volume.mount.assets.source = /srv/assets\\nvolume.mount.assets.target = /assets\\nvolume.mount.assets.access = read-only\\nvolume.mount.state.source = /srv/state\\nvolume.mount.state.target = /state\\nvolume.mount.state.access = writable\\n",
    );
    let path = write_policy("named-volumes", &text);
    let output = Command::new(binary())
        .args(["manifest-json", path.to_str().expect("UTF-8 policy path")])
        .output()
        .expect("run named-volume manifest JSON CLI");
    let _ = fs::remove_file(path);
    assert_eq!(output.status.code(), Some(0));
    let stdout = String::from_utf8(output.stdout).expect("manifest JSON is UTF-8");
    assert!(stdout.contains(
        "\\\"persistent_volumes\\\":[{\\\"name\\\":\\\"assets\\\",\\\"source\\\":\\\"/srv/assets\\\",\\\"target\\\":\\\"/assets\\\",\\\"access\\\":\\\"read_only\\\"},{\\\"name\\\":\\\"state\\\",\\\"source\\\":\\\"/srv/state\\\",\\\"target\\\":\\\"/state\\\",\\\"access\\\":\\\"writable\\\"}]"
    ));
}

'''
replace_one("tests/authority_manifest_cli.rs", marker, manifest_test + marker, "manifest named volume test")

# Add authority-delta evidence: exact added named mount is a widening.
marker = "#[test]\nfn authority_delta_requires_exactly_two_policy_arguments() {\n"
delta_test = '''#[test]
fn authority_delta_classifies_added_named_persistent_volume_as_widening() {
    let root = root_path("named-volume-delta");
    let baseline = policy_text(&root);
    let mut candidate = baseline.clone();
    candidate.push_str(
        "volume.mount.assets.source = /srv/assets\\nvolume.mount.assets.target = /assets\\nvolume.mount.assets.access = read-only\\n",
    );
    let baseline_path = write_policy("named-volume-baseline", &baseline);
    let candidate_path = write_policy("named-volume-candidate", &candidate);
    let output = Command::new(binary())
        .args([
            "authority-delta-json",
            baseline_path.to_str().expect("UTF-8 baseline path"),
            candidate_path.to_str().expect("UTF-8 candidate path"),
        ])
        .output()
        .expect("run named-volume authority delta");
    let _ = fs::remove_file(baseline_path);
    let _ = fs::remove_file(candidate_path);
    assert_eq!(output.status.code(), Some(5));
    let stdout = String::from_utf8(output.stdout).expect("delta JSON is UTF-8");
    assert!(stdout.contains("\\\"field\\\":\\\"filesystem.persistent_volumes\\\",\\\"class\\\":\\\"widened\\\""));
}

'''
# This marker may have evolved; make failure explicit rather than silently omitting evidence.
replace_one("tests/authority_delta_cli.rs", marker, delta_test + marker, "authority delta named volume test")
