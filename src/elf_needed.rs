use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fmt;
use std::io;
use std::os::unix::io::RawFd;

const ELF_HEADER_BYTES: usize = 64;
const ELF64_PROGRAM_HEADER_BYTES: usize = 56;
const ELF64_DYNAMIC_BYTES: usize = 16;
const PT_LOAD: u32 = 1;
const PT_DYNAMIC: u32 = 2;
const DT_NULL: i64 = 0;
const DT_NEEDED: i64 = 1;
const DT_STRTAB: i64 = 5;
const DT_STRSZ: i64 = 10;
const DT_RPATH: i64 = 15;
const DT_RUNPATH: i64 = 29;
const PN_XNUM: u16 = 0xffff;
const MAX_DYNAMIC_BYTES: u64 = 1024 * 1024;
const MAX_STRING_TABLE_BYTES: u64 = 1024 * 1024;
const MAX_NEEDED_ENTRIES: usize = 128;

#[derive(Debug)]
pub(crate) struct ElfNeededError(String);

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ElfDynamicLinks {
    pub needed: Vec<Vec<u8>>,
    pub runpath: Option<Vec<u8>>,
    pub rpath: Option<Vec<u8>>,
}

impl ElfDynamicLinks {
    fn empty() -> Self {
        Self {
            needed: Vec::new(),
            runpath: None,
            rpath: None,
        }
    }
}

impl fmt::Display for ElfNeededError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

#[derive(Clone, Copy)]
struct LoadSegment {
    offset: u64,
    vaddr: u64,
    filesz: u64,
}

fn read_u16(bytes: &[u8]) -> u16 {
    u16::from_le_bytes([bytes[0], bytes[1]])
}

fn read_u32(bytes: &[u8]) -> u32 {
    u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
}

fn read_i64(bytes: &[u8]) -> i64 {
    i64::from_le_bytes([
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
    ])
}

fn read_u64(bytes: &[u8]) -> u64 {
    u64::from_le_bytes([
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
    ])
}

fn pread_exact(fd: RawFd, offset: u64, buffer: &mut [u8]) -> Result<(), ElfNeededError> {
    let mut done = 0usize;
    while done < buffer.len() {
        let absolute = offset
            .checked_add(done as u64)
            .ok_or_else(|| ElfNeededError("ELF read offset overflow".to_owned()))?;
        if absolute > libc::off_t::MAX as u64 {
            return Err(ElfNeededError("ELF read offset exceeds off_t".to_owned()));
        }
        let read = unsafe {
            libc::pread(
                fd,
                buffer[done..].as_mut_ptr().cast::<libc::c_void>(),
                buffer.len() - done,
                absolute as libc::off_t,
            )
        };
        if read == -1 {
            let error = io::Error::last_os_error();
            if error.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            return Err(ElfNeededError(format!("ELF pread failed: {error}")));
        }
        if read == 0 {
            return Err(ElfNeededError("ELF file ended unexpectedly".to_owned()));
        }
        done += read as usize;
    }
    Ok(())
}

fn validate_range(
    offset: u64,
    size: u64,
    file_size: u64,
    label: &str,
) -> Result<(), ElfNeededError> {
    let end = offset
        .checked_add(size)
        .ok_or_else(|| ElfNeededError(format!("{label} range overflow")))?;
    if end > file_size {
        return Err(ElfNeededError(format!(
            "{label} extends beyond the ELF image"
        )));
    }
    Ok(())
}

fn display_needed_name(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

fn validate_path_qualified_needed_name(
    parent: Option<&[u8]>,
    name: &[u8],
) -> Result<(), ElfNeededError> {
    if name.first() != Some(&b'/') || name == b"/" || name.contains(&b'$') {
        let parent = parent
            .map(display_needed_name)
            .unwrap_or_else(|| "<main executable>".to_owned());
        return Err(ElfNeededError(format!(
            "{parent} has non-literal path-qualified DT_NEEDED entry {:?}",
            display_needed_name(name)
        )));
    }
    Ok(())
}

pub(crate) fn validate_dependency_graph_roots(
    root_needed: &[Vec<u8>],
    declared: &BTreeSet<Vec<u8>>,
) -> Result<(), ElfNeededError> {
    let mut root_seen = BTreeSet::new();
    for edge in root_needed {
        validate_path_qualified_needed_name(None, edge)?;
        if !root_seen.insert(edge.clone()) {
            return Err(ElfNeededError(format!(
                "main executable contains duplicate DT_NEEDED edge {}",
                display_needed_name(edge)
            )));
        }
        if !declared.contains(edge) {
            return Err(ElfNeededError(format!(
                "main executable DT_NEEDED edge {} is not present in the declared sealed dependency graph",
                display_needed_name(edge)
            )));
        }
    }
    Ok(())
}

pub(crate) fn validate_exact_dependency_graph(
    root_needed: &[Vec<u8>],
    dependency_needed: &BTreeMap<Vec<u8>, Vec<Vec<u8>>>,
) -> Result<(), ElfNeededError> {
    let declared = dependency_needed.keys().cloned().collect::<BTreeSet<_>>();
    validate_dependency_graph_roots(root_needed, &declared)?;

    let mut queue = root_needed.iter().cloned().collect::<VecDeque<_>>();
    let mut reachable = BTreeSet::new();
    while let Some(node) = queue.pop_front() {
        if !reachable.insert(node.clone()) {
            continue;
        }
        let children = dependency_needed
            .get(&node)
            .expect("queued dependency graph node is declared");
        let mut child_seen = BTreeSet::new();
        for edge in children {
            validate_path_qualified_needed_name(Some(&node), edge)?;
            if !child_seen.insert(edge.clone()) {
                return Err(ElfNeededError(format!(
                    "sealed dependency {} contains duplicate DT_NEEDED edge {}",
                    display_needed_name(&node),
                    display_needed_name(edge)
                )));
            }
            if !dependency_needed.contains_key(edge) {
                return Err(ElfNeededError(format!(
                    "sealed dependency {} requires undeclared DT_NEEDED edge {}",
                    display_needed_name(&node),
                    display_needed_name(edge)
                )));
            }
            queue.push_back(edge.clone());
        }
    }

    if reachable.len() != dependency_needed.len() {
        let unreachable = dependency_needed
            .keys()
            .find(|path| !reachable.contains(*path))
            .expect("graph cardinality mismatch has an unreachable node");
        return Err(ElfNeededError(format!(
            "declared sealed dependency {} is unreachable from the main executable",
            display_needed_name(unreachable)
        )));
    }

    Ok(())
}

pub(crate) fn read_elf64_x86_64_dt_needed(fd: RawFd) -> Result<Vec<Vec<u8>>, ElfNeededError> {
    let mut stat = unsafe { std::mem::zeroed::<libc::stat>() };
    if unsafe { libc::fstat(fd, &mut stat) } == -1 {
        return Err(ElfNeededError(format!(
            "cannot stat ELF image: {}",
            io::Error::last_os_error()
        )));
    }
    if stat.st_size < ELF_HEADER_BYTES as i64 {
        return Err(ElfNeededError(
            "ELF image is smaller than its header".to_owned(),
        ));
    }
    let file_size = stat.st_size as u64;

    let mut header = [0u8; ELF_HEADER_BYTES];
    pread_exact(fd, 0, &mut header)?;
    if &header[0..4] != b"\x7fELF"
        || header[4] != 2
        || header[5] != 1
        || header[6] != 1
        || read_u16(&header[18..20]) != 62
        || read_u32(&header[20..24]) != 1
    {
        return Err(ElfNeededError(
            "expected little-endian ELF64 x86_64 image".to_owned(),
        ));
    }

    let phoff = read_u64(&header[32..40]);
    let phentsize = read_u16(&header[54..56]);
    let phnum = read_u16(&header[56..58]);
    if phnum == PN_XNUM {
        return Err(ElfNeededError(
            "extended ELF program-header counts are not supported".to_owned(),
        ));
    }
    if phnum == 0 {
        return Ok(Vec::new());
    }
    if phentsize as usize != ELF64_PROGRAM_HEADER_BYTES {
        return Err(ElfNeededError(format!(
            "unexpected ELF64 program-header size {phentsize}"
        )));
    }
    let ph_table_size = u64::from(phnum)
        .checked_mul(ELF64_PROGRAM_HEADER_BYTES as u64)
        .ok_or_else(|| ElfNeededError("ELF program-header table overflow".to_owned()))?;
    validate_range(phoff, ph_table_size, file_size, "ELF program-header table")?;

    let mut loads = Vec::new();
    let mut dynamic = None;
    for index in 0..u64::from(phnum) {
        let offset = phoff + index * ELF64_PROGRAM_HEADER_BYTES as u64;
        let mut ph = [0u8; ELF64_PROGRAM_HEADER_BYTES];
        pread_exact(fd, offset, &mut ph)?;
        let kind = read_u32(&ph[0..4]);
        let file_offset = read_u64(&ph[8..16]);
        let vaddr = read_u64(&ph[16..24]);
        let filesz = read_u64(&ph[32..40]);
        if kind == PT_LOAD {
            validate_range(file_offset, filesz, file_size, "PT_LOAD")?;
            loads.push(LoadSegment {
                offset: file_offset,
                vaddr,
                filesz,
            });
        } else if kind == PT_DYNAMIC {
            if dynamic.is_some() {
                return Err(ElfNeededError(
                    "ELF image contains more than one PT_DYNAMIC segment".to_owned(),
                ));
            }
            if filesz == 0 || filesz > MAX_DYNAMIC_BYTES || filesz % ELF64_DYNAMIC_BYTES as u64 != 0
            {
                return Err(ElfNeededError(
                    "PT_DYNAMIC has an invalid bounded size".to_owned(),
                ));
            }
            validate_range(file_offset, filesz, file_size, "PT_DYNAMIC")?;
            dynamic = Some((file_offset, filesz));
        }
    }

    let Some((dynamic_offset, dynamic_size)) = dynamic else {
        return Ok(Vec::new());
    };
    let mut needed_offsets = Vec::new();
    let mut strtab_vaddr = None;
    let mut strtab_size = None;
    let mut terminated = false;
    for index in 0..(dynamic_size / ELF64_DYNAMIC_BYTES as u64) {
        let mut entry = [0u8; ELF64_DYNAMIC_BYTES];
        pread_exact(
            fd,
            dynamic_offset + index * ELF64_DYNAMIC_BYTES as u64,
            &mut entry,
        )?;
        let tag = read_i64(&entry[0..8]);
        let value = read_u64(&entry[8..16]);
        match tag {
            DT_NULL => {
                terminated = true;
                break;
            }
            DT_NEEDED => {
                if needed_offsets.len() >= MAX_NEEDED_ENTRIES {
                    return Err(ElfNeededError("too many DT_NEEDED entries".to_owned()));
                }
                needed_offsets.push(value);
            }
            DT_STRTAB => match strtab_vaddr {
                Some(_) => {
                    return Err(ElfNeededError(
                        "ELF image contains multiple DT_STRTAB entries".to_owned(),
                    ));
                }
                None => strtab_vaddr = Some(value),
            },
            DT_STRSZ => match strtab_size {
                Some(_) => {
                    return Err(ElfNeededError(
                        "ELF image contains multiple DT_STRSZ entries".to_owned(),
                    ));
                }
                None => strtab_size = Some(value),
            },
            _ => {}
        }
    }
    if !terminated {
        return Err(ElfNeededError(
            "PT_DYNAMIC has no DT_NULL terminator".to_owned(),
        ));
    }
    if needed_offsets.is_empty() {
        return Ok(Vec::new());
    }

    let strtab_vaddr =
        strtab_vaddr.ok_or_else(|| ElfNeededError("DT_NEEDED requires DT_STRTAB".to_owned()))?;
    let strtab_size =
        strtab_size.ok_or_else(|| ElfNeededError("DT_NEEDED requires DT_STRSZ".to_owned()))?;
    if strtab_size == 0 || strtab_size > MAX_STRING_TABLE_BYTES {
        return Err(ElfNeededError(
            "DT_STRTAB size is outside the bounded range".to_owned(),
        ));
    }

    let mut strtab_offset = None;
    for load in loads {
        let Some(delta) = strtab_vaddr.checked_sub(load.vaddr) else {
            continue;
        };
        if delta <= load.filesz && strtab_size <= load.filesz.saturating_sub(delta) {
            strtab_offset = load.offset.checked_add(delta);
            if strtab_offset.is_none() {
                return Err(ElfNeededError("DT_STRTAB file offset overflow".to_owned()));
            }
            break;
        }
    }
    let strtab_offset = strtab_offset
        .ok_or_else(|| ElfNeededError("DT_STRTAB is not backed by one PT_LOAD".to_owned()))?;
    validate_range(strtab_offset, strtab_size, file_size, "DT_STRTAB")?;

    let mut strings = vec![0u8; strtab_size as usize];
    pread_exact(fd, strtab_offset, &mut strings)?;
    let mut result = Vec::with_capacity(needed_offsets.len());
    for needed in needed_offsets {
        if needed >= strtab_size {
            return Err(ElfNeededError(
                "DT_NEEDED string offset is outside DT_STRTAB".to_owned(),
            ));
        }
        let tail = &strings[needed as usize..];
        let end = tail
            .iter()
            .position(|byte| *byte == 0)
            .ok_or_else(|| ElfNeededError("DT_NEEDED string is not NUL terminated".to_owned()))?;
        if end == 0 {
            return Err(ElfNeededError("DT_NEEDED string is empty".to_owned()));
        }
        result.push(tail[..end].to_vec());
    }
    Ok(result)
}

#[cfg(test)]
mod graph_tests {
    use super::validate_exact_dependency_graph;
    use std::collections::BTreeMap;

    fn bytes(value: &str) -> Vec<u8> {
        value.as_bytes().to_vec()
    }

    #[test]
    fn exact_dependency_graph_accepts_reachable_transitive_nodes_and_cycles() {
        let root = vec![bytes("/a")];
        let mut graph = BTreeMap::new();
        graph.insert(bytes("/a"), vec![bytes("/b")]);
        graph.insert(bytes("/b"), vec![bytes("/a")]);
        validate_exact_dependency_graph(&root, &graph).unwrap();
    }

    #[test]
    fn dependency_graph_roots_reject_missing_direct_edges_before_node_access() {
        let root = vec![bytes("/required")];
        let declared = [bytes("/different")].into_iter().collect();
        let err = super::validate_dependency_graph_roots(&root, &declared).unwrap_err();
        assert!(err
            .to_string()
            .contains("main executable DT_NEEDED edge /required is not present"));
    }

    #[test]
    fn exact_dependency_graph_rejects_undeclared_and_unreachable_nodes() {
        let root = vec![bytes("/a")];
        let mut missing = BTreeMap::new();
        missing.insert(bytes("/a"), vec![bytes("/b")]);
        let err = validate_exact_dependency_graph(&root, &missing).unwrap_err();
        assert!(err
            .to_string()
            .contains("requires undeclared DT_NEEDED edge /b"));

        let mut unreachable = BTreeMap::new();
        unreachable.insert(bytes("/a"), Vec::new());
        unreachable.insert(bytes("/unused"), Vec::new());
        let err = validate_exact_dependency_graph(&root, &unreachable).unwrap_err();
        assert!(err
            .to_string()
            .contains("is unreachable from the main executable"));
    }

    #[test]
    fn exact_dependency_graph_rejects_non_literal_or_duplicate_edges() {
        let mut graph = BTreeMap::new();
        graph.insert(bytes("/a"), Vec::new());

        let err = validate_exact_dependency_graph(&[bytes("liba.so")], &graph).unwrap_err();
        assert!(err
            .to_string()
            .contains("non-literal path-qualified DT_NEEDED"));

        let err = validate_exact_dependency_graph(&[bytes("/a"), bytes("/a")], &graph).unwrap_err();
        assert!(err.to_string().contains("duplicate DT_NEEDED edge /a"));
    }
}
