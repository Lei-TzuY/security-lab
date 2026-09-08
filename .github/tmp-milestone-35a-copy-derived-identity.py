from pathlib import Path
import re

snapshot = Path("src/snapshot_identity.rs")
text = snapshot.read_text()
needle = '#[cfg(target_os = "linux")]\nmod linux {'
replacement = '#[cfg(target_os = "linux")]\npub(crate) use linux::CanonicalHasher;\n\n#[cfg(target_os = "linux")]\nmod linux {'
if text.count(needle) != 1:
    raise SystemExit(f"snapshot module marker count={text.count(needle)}")
text = text.replace(needle, replacement, 1)
text = text.replace('    struct CanonicalHasher {', '    pub(crate) struct CanonicalHasher {', 1)
for sig in [
    '        fn new(limits: SnapshotIdentityLimits)',
    '        fn consume_node(&mut self)',
    '        fn update(&mut self, bytes: &[u8])',
    '        fn record_directory(',
    '        fn begin_file(',
    '        fn record_symlink(',
    '        fn finish(self) -> SnapshotIdentity',
]:
    if text.count(sig) != 1:
        raise SystemExit(f"snapshot method marker count for {sig!r} = {text.count(sig)}")
    text = text.replace(sig, sig.replace('fn ', 'pub(crate) fn ', 1), 1)
snapshot.write_text(text)

cow = Path("src/cow_diff_apply.rs")
text = cow.read_text()
import_marker = 'use crate::snapshot_identity::{\n    snapshot_sha256, SnapshotIdentity, SnapshotIdentityError, SnapshotIdentityLimits,\n};\n'
if text.count(import_marker) != 1:
    raise SystemExit(f"cow import marker count={text.count(import_marker)}")
text = text.replace(
    import_marker,
    import_marker + '#[cfg(target_os = "linux")]\nuse crate::snapshot_identity::CanonicalHasher;\n',
    1,
)

old_block = '''            let mut directory_modes = BTreeMap::new();
            directory_modes.insert(Vec::new(), (root_stat.st_mode & 0o7777) as u32);
            copy_directory(
                base_fd.raw(),
                staging_fd.raw(),
                &mut budget,
                &mut directory_modes,
                &[],
                0,
            )?;

            let materialized_identity =
                if let Some((expected, identity_limits)) = expected_materialized {
                    // The copy phase intentionally keeps directories launcher-writable.
                    // Restore the canonical base modes before hashing so the second
                    // identity gate observes the same object model as Snapshot 33A.
                    restore_directory_modes(staging_fd.raw(), &directory_modes)?;
                    let staging_path =
                        canonical_parent.join(OsString::from_vec(staging_name.as_bytes().to_vec()));
                    let actual = snapshot_sha256(&staging_path, identity_limits)
                        .map_err(|source| CowDiffApplyError::BaseIdentity { source })?;
                    if actual.sha256 != expected.sha256 {
                        return Err(CowDiffApplyError::BaseIdentityMismatch { expected, actual });
                    }
                    // Replay mutates this private tree. Re-enable owner write/search
                    // authority without changing the canonical modes retained in the
                    // directory-mode map; final modes are restored after replay.
                    make_directories_writable(staging_fd.raw(), &directory_modes)?;
                    Some(actual)
                } else {
                    None
                };
'''
new_block = '''            let root_mode = (root_stat.st_mode & 0o7777) as u32;
            let mut directory_modes = BTreeMap::new();
            directory_modes.insert(Vec::new(), root_mode);
            let mut materialized_hasher = match expected_materialized {
                Some((_, identity_limits)) => {
                    let mut identity = identity_result(CanonicalHasher::new(identity_limits))?;
                    identity_result(identity.consume_node())?;
                    identity_result(identity.record_directory(b"/", root_mode))?;
                    Some(identity)
                }
                None => None,
            };
            copy_directory(
                base_fd.raw(),
                staging_fd.raw(),
                &mut budget,
                &mut directory_modes,
                materialized_hasher.as_mut(),
                &[],
                0,
            )?;

            let materialized_identity = materialized_hasher.map(CanonicalHasher::finish);
            if let (Some((expected, _)), Some(actual)) =
                (expected_materialized, materialized_identity)
            {
                if actual.sha256 != expected.sha256 {
                    return Err(CowDiffApplyError::BaseIdentityMismatch { expected, actual });
                }
            }
'''
if text.count(old_block) != 1:
    raise SystemExit(f"materialized path-hash block count={text.count(old_block)}")
text = text.replace(old_block, new_block, 1)

old_copy_dir = '''    fn copy_directory(
        source_fd: RawFd,
        destination_fd: RawFd,
        budget: &mut Budget,
        directory_modes: &mut BTreeMap<Vec<u8>, u32>,
        relative: &[u8],
        depth: usize,
    ) -> Result<(), CowDiffApplyError> {
        if depth > MAX_TREE_DEPTH {
            return Err(CowDiffApplyError::InvalidInput(
                "base snapshot exceeds the 64-level replay depth ceiling".to_owned(),
            ));
        }
        for name in read_directory_names_bounded(source_fd, Some(budget))? {
            let name_c = CString::new(name.clone()).expect("directory entry has no embedded NUL");
            let child_relative = join_relative(relative, &name);
            let mut stat = unsafe { std::mem::zeroed::<libc::stat>() };
            if unsafe {
                libc::fstatat(
                    source_fd,
                    name_c.as_ptr(),
                    &mut stat,
                    libc::AT_SYMLINK_NOFOLLOW,
                )
            } == -1
            {
                return Err(io_error(
                    "stat base snapshot entry",
                    io::Error::last_os_error(),
                ));
            }
            match stat.st_mode & libc::S_IFMT {
                libc::S_IFDIR => {
                    if unsafe { libc::mkdirat(destination_fd, name_c.as_ptr(), 0o700) } == -1 {
                        return Err(io_error(
                            "create copied base directory",
                            io::Error::last_os_error(),
                        ));
                    }
                    let source_child = open_child_directory(
                        source_fd,
                        name_c.as_c_str(),
                        "open base child directory",
                    )?;
                    let destination_child = open_child_directory(
                        destination_fd,
                        name_c.as_c_str(),
                        "open copied child directory",
                    )?;
                    directory_modes.insert(child_relative.clone(), (stat.st_mode & 0o7777) as u32);
                    copy_directory(
                        source_child.raw(),
                        destination_child.raw(),
                        budget,
                        directory_modes,
                        &child_relative,
                        depth + 1,
                    )?;
                }
                libc::S_IFREG => {
                    copy_regular_file(
                        source_fd,
                        destination_fd,
                        name_c.as_c_str(),
                        (stat.st_mode & 0o7777) as u32,
                        budget,
                    )?;
                }
                libc::S_IFLNK => {
                    copy_symlink(source_fd, destination_fd, name_c.as_c_str(), budget)?;
                }
                _ => {
                    return Err(CowDiffApplyError::InvalidInput(format!(
                        "base snapshot contains unsupported node kind at /{}",
                        String::from_utf8_lossy(&child_relative)
                    )));
                }
            }
        }
        Ok(())
    }
'''
new_copy_dir = '''    fn copy_directory(
        source_fd: RawFd,
        destination_fd: RawFd,
        budget: &mut Budget,
        directory_modes: &mut BTreeMap<Vec<u8>, u32>,
        mut identity: Option<&mut CanonicalHasher>,
        relative: &[u8],
        depth: usize,
    ) -> Result<(), CowDiffApplyError> {
        if depth > MAX_TREE_DEPTH {
            return Err(CowDiffApplyError::InvalidInput(
                "base snapshot exceeds the 64-level replay depth ceiling".to_owned(),
            ));
        }
        for name in read_directory_names_bounded(
            source_fd,
            Some(budget),
            identity.as_deref_mut(),
        )? {
            let name_c = CString::new(name.clone()).expect("directory entry has no embedded NUL");
            let child_relative = join_relative(relative, &name);
            let absolute_path = absolute_snapshot_path(&child_relative);
            let mut stat = unsafe { std::mem::zeroed::<libc::stat>() };
            if unsafe {
                libc::fstatat(
                    source_fd,
                    name_c.as_ptr(),
                    &mut stat,
                    libc::AT_SYMLINK_NOFOLLOW,
                )
            } == -1
            {
                return Err(io_error(
                    "stat base snapshot entry",
                    io::Error::last_os_error(),
                ));
            }
            match stat.st_mode & libc::S_IFMT {
                libc::S_IFDIR => {
                    if unsafe { libc::mkdirat(destination_fd, name_c.as_ptr(), 0o700) } == -1 {
                        return Err(io_error(
                            "create copied base directory",
                            io::Error::last_os_error(),
                        ));
                    }
                    let source_child = open_child_directory(
                        source_fd,
                        name_c.as_c_str(),
                        "open base child directory",
                    )?;
                    let mut current = unsafe { std::mem::zeroed::<libc::stat>() };
                    if unsafe { libc::fstat(source_child.raw(), &mut current) } == -1 {
                        return Err(io_error(
                            "stat opened base child directory",
                            io::Error::last_os_error(),
                        ));
                    }
                    if current.st_mode & libc::S_IFMT != libc::S_IFDIR {
                        return Err(CowDiffApplyError::InvalidInput(
                            "base directory changed type during replay materialization".to_owned(),
                        ));
                    }
                    let mode = (current.st_mode & 0o7777) as u32;
                    if let Some(identity) = identity.as_deref_mut() {
                        identity_result(identity.record_directory(&absolute_path, mode))?;
                    }
                    let destination_child = open_child_directory(
                        destination_fd,
                        name_c.as_c_str(),
                        "open copied child directory",
                    )?;
                    directory_modes.insert(child_relative.clone(), mode);
                    copy_directory(
                        source_child.raw(),
                        destination_child.raw(),
                        budget,
                        directory_modes,
                        identity.as_deref_mut(),
                        &child_relative,
                        depth + 1,
                    )?;
                }
                libc::S_IFREG => {
                    copy_regular_file(
                        source_fd,
                        destination_fd,
                        name_c.as_c_str(),
                        &absolute_path,
                        budget,
                        identity.as_deref_mut(),
                    )?;
                }
                libc::S_IFLNK => {
                    copy_symlink(
                        source_fd,
                        destination_fd,
                        name_c.as_c_str(),
                        &absolute_path,
                        budget,
                        identity.as_deref_mut(),
                    )?;
                }
                _ => {
                    return Err(CowDiffApplyError::InvalidInput(format!(
                        "base snapshot contains unsupported node kind at /{}",
                        String::from_utf8_lossy(&child_relative)
                    )));
                }
            }
        }
        Ok(())
    }
'''
if text.count(old_copy_dir) != 1:
    raise SystemExit(f"copy_directory block count={text.count(old_copy_dir)}")
text = text.replace(old_copy_dir, new_copy_dir, 1)

regular_pattern = re.compile(r'''    fn copy_regular_file\(\n.*?\n    fn copy_symlink\(''', re.S)
regular_replacement = '''    fn copy_regular_file(
        source_parent: RawFd,
        destination_parent: RawFd,
        name: &std::ffi::CStr,
        path: &[u8],
        budget: &mut Budget,
        mut identity: Option<&mut CanonicalHasher>,
    ) -> Result<(), CowDiffApplyError> {
        let source_fd = unsafe {
            libc::openat(
                source_parent,
                name.as_ptr(),
                libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            )
        };
        if source_fd == -1 {
            return Err(io_error(
                "open base regular file",
                io::Error::last_os_error(),
            ));
        }
        let source_fd = Fd(source_fd);
        let mut stat = unsafe { std::mem::zeroed::<libc::stat>() };
        if unsafe { libc::fstat(source_fd.raw(), &mut stat) } == -1 {
            return Err(io_error(
                "stat opened base regular file",
                io::Error::last_os_error(),
            ));
        }
        if stat.st_mode & libc::S_IFMT != libc::S_IFREG || stat.st_size < 0 {
            return Err(CowDiffApplyError::InvalidInput(
                "base regular file changed type or has invalid size during replay materialization"
                    .to_owned(),
            ));
        }
        let mode = (stat.st_mode & 0o7777) as u32;
        let length = stat.st_size as u64;
        if let Some(identity) = identity.as_deref_mut() {
            identity_result(identity.begin_file(path, mode, length))?;
        }

        let destination_fd = unsafe {
            libc::openat(
                destination_parent,
                name.as_ptr(),
                libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_CLOEXEC | libc::O_NOFOLLOW,
                0o600,
            )
        };
        if destination_fd == -1 {
            return Err(io_error(
                "create copied regular file",
                io::Error::last_os_error(),
            ));
        }
        let destination_fd = Fd(destination_fd);
        let mut remaining = length;
        let mut buffer = [0u8; 8192];
        while remaining > 0 {
            let request = std::cmp::min(remaining, buffer.len() as u64) as usize;
            let count = loop {
                let count = unsafe {
                    libc::read(
                        source_fd.raw(),
                        buffer.as_mut_ptr().cast::<libc::c_void>(),
                        request,
                    )
                };
                if count == -1 && io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) {
                    continue;
                }
                break count;
            };
            if count == -1 {
                return Err(io_error(
                    "read base regular file",
                    io::Error::last_os_error(),
                ));
            }
            if count == 0 {
                return Err(CowDiffApplyError::InvalidInput(
                    "base regular file shrank during replay materialization".to_owned(),
                ));
            }
            let bytes = &buffer[..count as usize];
            budget.consume_base_bytes(count as u64)?;
            write_all(destination_fd.raw(), bytes)?;
            if let Some(identity) = identity.as_deref_mut() {
                identity_result(identity.update(bytes))?;
            }
            remaining -= count as u64;
        }

        let mut extra = [0u8; 1];
        let extra_count = loop {
            let count = unsafe {
                libc::read(
                    source_fd.raw(),
                    extra.as_mut_ptr().cast::<libc::c_void>(),
                    extra.len(),
                )
            };
            if count == -1 && io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            break count;
        };
        if extra_count == -1 {
            return Err(io_error(
                "verify base regular file length",
                io::Error::last_os_error(),
            ));
        }
        if extra_count != 0 {
            return Err(CowDiffApplyError::InvalidInput(
                "base regular file grew during replay materialization".to_owned(),
            ));
        }
        if unsafe { libc::fchmod(destination_fd.raw(), mode as libc::mode_t) } == -1 {
            return Err(io_error(
                "restore copied file mode",
                io::Error::last_os_error(),
            ));
        }
        Ok(())
    }

    fn copy_symlink('''
text, count = regular_pattern.subn(regular_replacement, text, count=1)
if count != 1:
    raise SystemExit(f"copy_regular_file replacement count={count}")

old_symlink_sig = '''    fn copy_symlink(
        source_parent: RawFd,
        destination_parent: RawFd,
        name: &std::ffi::CStr,
        budget: &mut Budget,
    ) -> Result<(), CowDiffApplyError> {'''
new_symlink_sig = '''    fn copy_symlink(
        source_parent: RawFd,
        destination_parent: RawFd,
        name: &std::ffi::CStr,
        path: &[u8],
        budget: &mut Budget,
        identity: Option<&mut CanonicalHasher>,
    ) -> Result<(), CowDiffApplyError> {'''
if text.count(old_symlink_sig) != 1:
    raise SystemExit(f"copy_symlink signature count={text.count(old_symlink_sig)}")
text = text.replace(old_symlink_sig, new_symlink_sig, 1)
old_symlink_tail = '''        if unsafe { libc::symlinkat(target.as_ptr(), destination_parent, name.as_ptr()) } == -1 {
            return Err(io_error("copy base symlink", io::Error::last_os_error()));
        }
        Ok(())
    }
'''
new_symlink_tail = '''        if unsafe { libc::symlinkat(target.as_ptr(), destination_parent, name.as_ptr()) } == -1 {
            return Err(io_error("copy base symlink", io::Error::last_os_error()));
        }
        if let Some(identity) = identity {
            identity_result(identity.record_symlink(path, target.as_bytes()))?;
        }
        Ok(())
    }
'''
if text.count(old_symlink_tail) != 1:
    raise SystemExit(f"copy_symlink tail count={text.count(old_symlink_tail)}")
text = text.replace(old_symlink_tail, new_symlink_tail, 1)

make_writable_pattern = re.compile(r'''    fn make_directories_writable\(\n.*?\n    fn restore_directory_modes\(''', re.S)
text, count = make_writable_pattern.subn('    fn restore_directory_modes(', text, count=1)
if count != 1:
    raise SystemExit(f"make_directories_writable removal count={count}")

old_clear = '        for name in read_directory_names_bounded(directory_fd, None)? {'
new_clear = '        for name in read_directory_names_bounded(directory_fd, None, None)? {'
if text.count(old_clear) != 1:
    raise SystemExit(f"clear_directory read marker count={text.count(old_clear)}")
text = text.replace(old_clear, new_clear, 1)

old_read_sig = '''    fn read_directory_names_bounded(
        directory_fd: RawFd,
        mut base_budget: Option<&mut Budget>,
    ) -> Result<Vec<Vec<u8>>, CowDiffApplyError> {'''
new_read_sig = '''    fn read_directory_names_bounded(
        directory_fd: RawFd,
        mut base_budget: Option<&mut Budget>,
        mut identity: Option<&mut CanonicalHasher>,
    ) -> Result<Vec<Vec<u8>>, CowDiffApplyError> {'''
if text.count(old_read_sig) != 1:
    raise SystemExit(f"read_directory_names signature count={text.count(old_read_sig)}")
text = text.replace(old_read_sig, new_read_sig, 1)
old_push = '''                    if let Some(budget) = &mut base_budget {
                        // Reserve the base-tree node before retaining its name.
                        // This makes max_nodes bound directory-enumeration
                        // buffering instead of applying only after collection.
                        budget.consume_base_node()?;
                    }
                    names.push(name.to_vec());'''
new_push = '''                    if let Some(budget) = &mut base_budget {
                        // Reserve the base-tree node before retaining its name.
                        // This makes max_nodes bound directory-enumeration
                        // buffering instead of applying only after collection.
                        budget.consume_base_node()?;
                    }
                    if let Some(identity) = identity.as_deref_mut() {
                        identity_result(identity.consume_node())?;
                    }
                    names.push(name.to_vec());'''
if text.count(old_push) != 1:
    raise SystemExit(f"directory name push marker count={text.count(old_push)}")
text = text.replace(old_push, new_push, 1)

join_marker = '''    fn join_relative(parent: &[u8], name: &[u8]) -> Vec<u8> {
        let mut result =
            Vec::with_capacity(parent.len() + usize::from(!parent.is_empty()) + name.len());
        result.extend_from_slice(parent);
        if !parent.is_empty() {
            result.push(b'/');
        }
        result.extend_from_slice(name);
        result
    }
'''
absolute_helper = join_marker + '''
    fn absolute_snapshot_path(relative: &[u8]) -> Vec<u8> {
        let mut result = Vec::with_capacity(relative.len() + 1);
        result.push(b'/');
        result.extend_from_slice(relative);
        result
    }

    fn identity_result<T>(
        result: Result<T, SnapshotIdentityError>,
    ) -> Result<T, CowDiffApplyError> {
        result.map_err(|source| CowDiffApplyError::BaseIdentity { source })
    }
'''
if text.count(join_marker) != 1:
    raise SystemExit(f"join_relative marker count={text.count(join_marker)}")
text = text.replace(join_marker, absolute_helper, 1)

text = text.replace(
    '    /// Canonical identity revalidated from the materialized base copy immediately\n    /// before diff replay begins.',
    '    /// Canonical identity derived from the exact metadata and bytes copied into\n    /// the private replay staging tree before diff replay begins.',
    1,
)
text = text.replace(
    '/// materialized into the private staging tree. The first gate preserves the 34A\n/// fail-fast ordering: a stale expected identity is rejected before destination\n/// inspection or staging creation. The second gate binds replay to the exact\n/// materialized input tree, so a base mutation after the first scan cannot be\n/// replayed under the earlier identity.\n///\n/// This does not make the source tree a hostile-writer snapshot while it is being\n/// copied: the materialized tree must itself hash to `expected_base` before replay.',
    '/// materialized into the private staging tree. The first gate preserves the 34A\n/// fail-fast ordering: a stale expected identity is rejected before destination\n/// inspection or staging creation. During the copy, the same canonical identity\n/// stream is derived from the opened object modes, symlink targets, and exact regular-file\n/// bytes written into staging. The second gate therefore binds replay to the actual\n/// materialized input rather than reopening staging through pathname permissions.\n///\n/// This does not lock the hostile source tree while it is being copied: replay proceeds\n/// only when the completed materialized stream itself matches `expected_base`.',
    1,
)

cow.write_text(text)
