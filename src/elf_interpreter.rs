use std::fmt;
use std::io;
use std::os::unix::io::RawFd;

const ELF_HEADER_BYTES: usize = 64;
const ELF64_PROGRAM_HEADER_BYTES: usize = 56;
const PT_INTERP: u32 = 3;
const PN_XNUM: u16 = 0xffff;
const MAX_INTERPRETER_BYTES: usize = 4096;

#[derive(Debug)]
pub(crate) struct ElfInterpreterError(String);

impl fmt::Display for ElfInterpreterError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

fn read_u16(bytes: &[u8]) -> u16 {
    u16::from_le_bytes([bytes[0], bytes[1]])
}

fn read_u32(bytes: &[u8]) -> u32 {
    u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
}

fn read_u64(bytes: &[u8]) -> u64 {
    u64::from_le_bytes([
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
    ])
}

fn pread_exact(fd: RawFd, offset: u64, buffer: &mut [u8]) -> Result<(), ElfInterpreterError> {
    let mut done = 0usize;
    while done < buffer.len() {
        let absolute = offset
            .checked_add(done as u64)
            .ok_or_else(|| ElfInterpreterError("ELF read offset overflow".to_owned()))?;
        if absolute > libc::off_t::MAX as u64 {
            return Err(ElfInterpreterError(
                "ELF read offset exceeds off_t".to_owned(),
            ));
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
            return Err(ElfInterpreterError(format!("ELF pread failed: {error}")));
        }
        if read == 0 {
            return Err(ElfInterpreterError(
                "ELF file ended unexpectedly".to_owned(),
            ));
        }
        done += read as usize;
    }
    Ok(())
}

pub(crate) fn read_elf64_x86_64_pt_interp(
    fd: RawFd,
) -> Result<Option<Vec<u8>>, ElfInterpreterError> {
    let mut stat = unsafe { std::mem::zeroed::<libc::stat>() };
    if unsafe { libc::fstat(fd, &mut stat) } == -1 {
        return Err(ElfInterpreterError(format!(
            "cannot stat ELF image: {}",
            io::Error::last_os_error()
        )));
    }
    if stat.st_size < ELF_HEADER_BYTES as i64 {
        return Err(ElfInterpreterError(
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
        return Err(ElfInterpreterError(
            "expected little-endian ELF64 x86_64 executable image".to_owned(),
        ));
    }

    let phoff = read_u64(&header[32..40]);
    let phentsize = read_u16(&header[54..56]);
    let phnum = read_u16(&header[56..58]);
    if phnum == PN_XNUM {
        return Err(ElfInterpreterError(
            "extended ELF program-header counts are not supported".to_owned(),
        ));
    }
    if phnum == 0 {
        return Ok(None);
    }
    if phentsize as usize != ELF64_PROGRAM_HEADER_BYTES {
        return Err(ElfInterpreterError(format!(
            "unexpected ELF64 program-header size {phentsize}"
        )));
    }
    let table_bytes = u64::from(phnum)
        .checked_mul(ELF64_PROGRAM_HEADER_BYTES as u64)
        .and_then(|bytes| phoff.checked_add(bytes))
        .ok_or_else(|| ElfInterpreterError("ELF program-header table overflow".to_owned()))?;
    if table_bytes > file_size {
        return Err(ElfInterpreterError(
            "ELF program-header table extends beyond the file".to_owned(),
        ));
    }

    let mut found = None;
    for index in 0..u64::from(phnum) {
        let offset = phoff + index * ELF64_PROGRAM_HEADER_BYTES as u64;
        let mut ph = [0u8; ELF64_PROGRAM_HEADER_BYTES];
        pread_exact(fd, offset, &mut ph)?;
        if read_u32(&ph[0..4]) != PT_INTERP {
            continue;
        }
        if found.is_some() {
            return Err(ElfInterpreterError(
                "ELF image contains more than one PT_INTERP segment".to_owned(),
            ));
        }
        let interp_offset = read_u64(&ph[8..16]);
        let interp_size = read_u64(&ph[32..40]);
        if interp_size < 2 || interp_size > MAX_INTERPRETER_BYTES as u64 {
            return Err(ElfInterpreterError(format!(
                "PT_INTERP size {interp_size} is outside 2..={MAX_INTERPRETER_BYTES}"
            )));
        }
        let interp_end = interp_offset
            .checked_add(interp_size)
            .ok_or_else(|| ElfInterpreterError("PT_INTERP range overflow".to_owned()))?;
        if interp_end > file_size {
            return Err(ElfInterpreterError(
                "PT_INTERP extends beyond the ELF image".to_owned(),
            ));
        }
        let mut bytes = vec![0u8; interp_size as usize];
        pread_exact(fd, interp_offset, &mut bytes)?;
        if bytes.last().copied() != Some(0) {
            return Err(ElfInterpreterError(
                "PT_INTERP is not NUL terminated".to_owned(),
            ));
        }
        bytes.pop();
        if bytes.is_empty() || bytes[0] != b'/' || bytes.contains(&0) {
            return Err(ElfInterpreterError(
                "PT_INTERP must be one absolute NUL-free path".to_owned(),
            ));
        }
        found = Some(bytes);
    }
    Ok(found)
}
