from pathlib import Path


def replace_one(path: str, old: str, new: str, label: str) -> None:
    p = Path(path)
    text = p.read_text()
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{label}: expected exactly one match, got {count}")
    p.write_text(text.replace(old, new, 1))


# Policy: explicit opt-in for activating only the loopback device in the
# already-isolated network namespace. Absence remains disabled.
replace_one(
    "src/policy.rs",
    '''    /// Absolute path interpreted inside `root_dir`.
    pub working_dir: PathBuf,
    /// Optional trusted host directory exposed read-only at exactly one''',
    '''    /// Absolute path interpreted inside `root_dir`.
    pub working_dir: PathBuf,
    /// Whether the launcher activates `lo` inside the isolated network namespace.
    /// This does not attach the namespace to any host or external network.
    pub loopback_enabled: bool,
    /// Optional trusted host directory exposed read-only at exactly one''',
    "policy field",
)
replace_one(
    "src/policy.rs",
    '''        let mut environment = BTreeMap::new();
        let mut working_dir = None;
        let mut readonly_volume_source = None;''',
    '''        let mut environment = BTreeMap::new();
        let mut working_dir = None;
        let mut loopback_enabled = None;
        let mut readonly_volume_source = None;''',
    "parser state",
)
replace_one(
    "src/policy.rs",
    '''                "filesystem.root" => set_once(&mut root_dir, value.to_owned(), line_no, key)?,
                "identity.hostname" => set_once(&mut hostname, value.to_owned(), line_no, key)?,
                "volume.readonly_source" => {''',
    '''                "filesystem.root" => set_once(&mut root_dir, value.to_owned(), line_no, key)?,
                "identity.hostname" => set_once(&mut hostname, value.to_owned(), line_no, key)?,
                "network.loopback" => set_once(
                    &mut loopback_enabled,
                    parse_enabled_disabled(value, line_no, key)?,
                    line_no,
                    key,
                )?,
                "volume.readonly_source" => {''',
    "parser key",
)
replace_one(
    "src/policy.rs",
    '''            environment,
            working_dir: PathBuf::from(required(working_dir, "working_dir")?),
            readonly_volume_source: readonly_volume_source.map(PathBuf::from),''',
    '''            environment,
            working_dir: PathBuf::from(required(working_dir, "working_dir")?),
            loopback_enabled: loopback_enabled.unwrap_or(false),
            readonly_volume_source: readonly_volume_source.map(PathBuf::from),''',
    "policy construction",
)
replace_one(
    "src/policy.rs",
    '''fn parse_stdio_mode(value: &str, line: usize, key: &str) -> Result<StdioMode, PolicyError> {
    match value {''',
    '''fn parse_enabled_disabled(value: &str, line: usize, key: &str) -> Result<bool, PolicyError> {
    match value {
        "enabled" => Ok(true),
        "disabled" => Ok(false),
        _ => Err(PolicyError::at(
            line,
            format!("{key} must be enabled or disabled"),
        )),
    }
}

fn parse_stdio_mode(value: &str, line: usize, key: &str) -> Result<StdioMode, PolicyError> {
    match value {''',
    "network parser helper",
)
replace_one(
    "src/policy.rs",
    '''        assert_eq!(policy.hostname, "security-lab");
        assert_eq!(policy.readonly_volume_source, None);''',
    '''        assert_eq!(policy.hostname, "security-lab");
        assert!(!policy.loopback_enabled);
        assert_eq!(policy.readonly_volume_source, None);''',
    "default disabled assertion",
)
replace_one(
    "src/policy.rs",
    '''    #[test]
    fn parses_readonly_volume_pair() {''',
    '''    #[test]
    fn parses_loopback_networking_mode() {
        let enabled: SandboxPolicy = format!("{VALID}\\nnetwork.loopback = enabled").parse().unwrap();
        assert!(enabled.loopback_enabled);

        let disabled: SandboxPolicy = format!("{VALID}\\nnetwork.loopback = disabled").parse().unwrap();
        assert!(!disabled.loopback_enabled);
    }

    #[test]
    fn rejects_invalid_or_duplicate_loopback_networking_mode() {
        let invalid = format!("{VALID}\\nnetwork.loopback = host");
        let error = invalid.parse::<SandboxPolicy>().unwrap_err();
        assert!(error.to_string().contains("must be enabled or disabled"));

        let duplicate = format!(
            "{VALID}\\nnetwork.loopback = enabled\\nnetwork.loopback = disabled"
        );
        assert!(duplicate.parse::<SandboxPolicy>().is_err());
    }

    #[test]
    fn parses_readonly_volume_pair() {''',
    "policy tests",
)

# Runtime: activate lo using the classic network-device flag ioctl while the
# post-unshare launcher still owns CAP_NET_ADMIN in the user namespace that
# owns the new network namespace. The target never receives this management
# capability or an implicit ioctl syscall grant.
replace_one(
    "src/platform/linux.rs",
    '''    const PHASE_VOLUME_ATTACH: u32 = 46;

    #[repr(C)]
    struct OpenHow {''',
    '''    const PHASE_VOLUME_ATTACH: u32 = 46;
    const PHASE_NETWORK_LOOPBACK: u32 = 47;

    const SIOCGIFFLAGS: libc::c_ulong = 0x8913;
    const SIOCSIFFLAGS: libc::c_ulong = 0x8914;
    const IFF_UP: libc::c_short = 0x1;
    const IFNAMSIZ: usize = 16;

    #[repr(C)]
    struct OpenHow {''',
    "network constants",
)
replace_one(
    "src/platform/linux.rs",
    '''    #[repr(C)]
    struct CapabilityHeader {''',
    '''    #[repr(C, align(8))]
    struct IfreqFlags {
        name: [libc::c_char; IFNAMSIZ],
        flags: libc::c_short,
        _padding: [u8; 22],
    }

    #[repr(C)]
    struct CapabilityHeader {''',
    "ifreq layout",
)
replace_one(
    "src/platform/linux.rs",
    '''        gid_map: Vec<u8>,
        hostname: Vec<u8>,
    }''',
    '''        gid_map: Vec<u8>,
        hostname: Vec<u8>,
        loopback_enabled: bool,
    }''',
    "prepared launch field",
)
replace_one(
    "src/platform/linux.rs",
    '''                gid_map,
                hostname,
            })''',
    '''                gid_map,
                hostname,
                loopback_enabled: policy.loopback_enabled,
            })''',
    "prepared launch construction",
)
replace_one(
    "src/platform/linux.rs",
    '''        if libc::syscall(
            libc::SYS_sethostname,
            prepared.hostname.as_ptr(),
            prepared.hostname.len(),
        ) == -1
        {
            child_fail(launch_error, PHASE_HOSTNAME, seccomp.error_exit_syscall);
        }

        if libc::syscall(
            libc::SYS_mount,''',
    '''        if libc::syscall(
            libc::SYS_sethostname,
            prepared.hostname.as_ptr(),
            prepared.hostname.len(),
        ) == -1
        {
            child_fail(launch_error, PHASE_HOSTNAME, seccomp.error_exit_syscall);
        }

        if prepared.loopback_enabled {
            enable_loopback_or_fail(launch_error, seccomp.error_exit_syscall);
        }

        if libc::syscall(
            libc::SYS_mount,''',
    "loopback setup call",
)
replace_one(
    "src/platform/linux.rs",
    '''    unsafe fn write_proc_file_or_fail(
        path: &'static [u8],''',
    '''    unsafe fn enable_loopback_or_fail(
        launch_error: *mut LaunchErrorRecord,
        error_exit_syscall: libc::c_long,
    ) {
        let socket_fd = libc::syscall(
            libc::SYS_socket,
            libc::AF_INET,
            libc::SOCK_DGRAM | libc::SOCK_CLOEXEC,
            0,
        );
        if socket_fd == -1 {
            child_fail(launch_error, PHASE_NETWORK_LOOPBACK, error_exit_syscall);
        }
        let socket_fd = socket_fd as RawFd;

        let mut request = IfreqFlags {
            name: [0; IFNAMSIZ],
            flags: 0,
            _padding: [0; 22],
        };
        request.name[0] = b'l' as libc::c_char;
        request.name[1] = b'o' as libc::c_char;

        if libc::syscall(
            libc::SYS_ioctl,
            socket_fd,
            SIOCGIFFLAGS,
            &mut request as *mut IfreqFlags,
        ) == -1
        {
            let errno = *libc::__errno_location();
            libc::syscall(libc::SYS_close, socket_fd);
            child_fail_errno(
                launch_error,
                PHASE_NETWORK_LOOPBACK,
                errno,
                error_exit_syscall,
            );
        }
        request.flags |= IFF_UP;
        if libc::syscall(
            libc::SYS_ioctl,
            socket_fd,
            SIOCSIFFLAGS,
            &request as *const IfreqFlags,
        ) == -1
        {
            let errno = *libc::__errno_location();
            libc::syscall(libc::SYS_close, socket_fd);
            child_fail_errno(
                launch_error,
                PHASE_NETWORK_LOOPBACK,
                errno,
                error_exit_syscall,
            );
        }
        if libc::syscall(libc::SYS_close, socket_fd) == -1 {
            child_fail(launch_error, PHASE_NETWORK_LOOPBACK, error_exit_syscall);
        }
    }

    unsafe fn write_proc_file_or_fail(
        path: &'static [u8],''',
    "loopback helper",
)
replace_one(
    "src/platform/linux.rs",
    '''        if namespace_unavailable || mount_boundary_unavailable {
            Err(SandboxError::UnsupportedPlatform(format!(
                "required namespace/mount isolation is unavailable: {message}"
            )))
        } else {
            Err(SandboxError::SetupFailed(message))
        }''',
    '''        let loopback_unavailable = record.phase == PHASE_NETWORK_LOOPBACK
            && matches!(
                record.errno,
                libc::EPERM | libc::EACCES | libc::ENOSYS | libc::ENODEV | libc::EOPNOTSUPP
            );
        if namespace_unavailable || mount_boundary_unavailable {
            Err(SandboxError::UnsupportedPlatform(format!(
                "required namespace/mount isolation is unavailable: {message}"
            )))
        } else if loopback_unavailable {
            Err(SandboxError::UnsupportedPlatform(format!(
                "policy-owned loopback networking is unavailable: {message}"
            )))
        } else {
            Err(SandboxError::SetupFailed(message))
        }''',
    "loopback unsupported classification",
)
replace_one(
    "src/platform/linux.rs",
    '''            PHASE_VOLUME_ATTACH => "persistent volume mount attachment",
            _ => "unknown launch phase",''',
    '''            PHASE_VOLUME_ATTACH => "persistent volume mount attachment",
            PHASE_NETWORK_LOOPBACK => "policy-owned loopback activation",
            _ => "unknown launch phase",''',
    "loopback phase label",
)
replace_one(
    "src/platform/linux.rs",
    '''            "socket" => libc::SYS_socket,
            "connect" => libc::SYS_connect,
            "msgget" => libc::SYS_msgget,''',
    '''            "socket" => libc::SYS_socket,
            "connect" => libc::SYS_connect,
            "accept" => libc::SYS_accept,
            "bind" => libc::SYS_bind,
            "listen" => libc::SYS_listen,
            "msgget" => libc::SYS_msgget,''',
    "network syscall mapping",
)

# Integration policy construction defaults to no positive network topology.
replace_one(
    "tests/sandbox.rs",
    '''        working_dir: PathBuf::from("/work"),
        readonly_volume_source: None,''',
    '''        working_dir: PathBuf::from("/work"),
        loopback_enabled: false,
        readonly_volume_source: None,''',
    "integration policy default",
)

# Existing host-loopback isolation oracle is made stronger: the sandbox's own
# lo is up, yet host 127.0.0.1 is still a different network namespace.
replace_one(
    "tests/sandbox.rs",
    '''    let isolated = policy(
        "K",
        &[port.as_str()],
        &["execveat", "socket", "connect", "close", "exit"],
    );
    assert_eq!(run(&isolated).unwrap(), ChildOutcome::Exited(0));''',
    '''    let mut isolated = policy(
        "K",
        &[port.as_str()],
        &["execveat", "socket", "connect", "close", "exit"],
    );
    isolated.loopback_enabled = true;
    assert_eq!(run(&isolated).unwrap(), ChildOutcome::Exited(0));''',
    "host isolation with loopback enabled",
)
replace_one(
    "tests/sandbox.rs",
    '''#[test]
fn ipc_namespace_cannot_observe_host_sysv_message_queue() {''',
    '''#[test]
fn enabled_loopback_supports_intra_sandbox_tcp() {
    let mut local = policy(
        "n",
        &[],
        &[
            "execveat", "socket", "bind", "listen", "fork", "connect", "accept", "read",
            "write", "close", "exit",
        ],
    );
    local.loopback_enabled = true;
    local.wall_clock_milliseconds = Some(2000);
    assert_eq!(run(&local).unwrap(), ChildOutcome::Exited(0));
}

#[test]
fn ipc_namespace_cannot_observe_host_sysv_message_queue() {''',
    "positive loopback integration test",
)

# Raw target: fixed high port is safe because every run has a fresh isolated
# network namespace. A child connects to its direct-target parent's listener
# and transfers an exact marker. A two-second launcher deadline in the Rust
# test turns any broken accept/connect path into a deterministic failure.
replace_one(
    "tests/fixtures/probe.S",
    '''#   w write through a declared persistent volume while root and host source paths stay confined
#   F forbidden getpid; exits 77 only when seccomp returns -EPERM''',
    '''#   w write through a declared persistent volume while root and host source paths stay confined
#   n prove policy-owned loopback supports positive intra-sandbox TCP
#   F forbidden getpid; exits 77 only when seccomp returns -EPERM''',
    "fixture mode comment",
)
replace_one(
    "tests/fixtures/probe.S",
    '''    cmp $119, %al
    je .writable_volume
    cmp $70, %al''',
    '''    cmp $119, %al
    je .writable_volume
    cmp $110, %al
    je .loopback_networking
    cmp $70, %al''',
    "fixture dispatch",
)
replace_one(
    "tests/fixtures/probe.S",
    '''    xor %edi, %edi
    jmp .exit

.forbidden:
    mov $39, %eax''',
    '''    xor %edi, %edi
    jmp .exit

.loopback_networking:
    movw $2, network_addr(%rip)
    movw $0xb8a5, network_addr+2(%rip)
    movl $0x0100007f, network_addr+4(%rip)

    mov $41, %eax
    mov $2, %edi
    mov $1, %esi
    xor %edx, %edx
    syscall
    test %rax, %rax
    js .fail34
    mov %rax, %r12

    mov $49, %eax
    mov %r12, %rdi
    lea network_addr(%rip), %rsi
    mov $16, %edx
    syscall
    test %rax, %rax
    js .fail34

    mov $50, %eax
    mov %r12, %rdi
    mov $1, %esi
    syscall
    test %rax, %rax
    js .fail34

    mov $57, %eax
    syscall
    test %rax, %rax
    js .fail34
    jz .loopback_client

    mov $43, %eax
    mov %r12, %rdi
    xor %esi, %esi
    xor %edx, %edx
    syscall
    test %rax, %rax
    js .fail34
    mov %rax, %r13

    xor %eax, %eax
    mov %r13, %rdi
    lea network_buffer(%rip), %rsi
    mov $loopback_message_len, %edx
    syscall
    cmp $loopback_message_len, %rax
    jne .fail34

    lea network_buffer(%rip), %rdi
    lea loopback_message(%rip), %rsi
    mov $loopback_message_len, %ecx
    repe cmpsb
    jne .fail34

    mov $3, %eax
    mov %r13, %rdi
    syscall
    test %rax, %rax
    js .fail34
    mov $3, %eax
    mov %r12, %rdi
    syscall
    test %rax, %rax
    js .fail34
    xor %edi, %edi
    jmp .exit

.loopback_client:
    mov $41, %eax
    mov $2, %edi
    mov $1, %esi
    xor %edx, %edx
    syscall
    test %rax, %rax
    js .fail34
    mov %rax, %r13

    mov $42, %eax
    mov %r13, %rdi
    lea network_addr(%rip), %rsi
    mov $16, %edx
    syscall
    test %rax, %rax
    js .fail34

    mov $1, %eax
    mov %r13, %rdi
    lea loopback_message(%rip), %rsi
    mov $loopback_message_len, %edx
    syscall
    cmp $loopback_message_len, %rax
    jne .fail34

    mov $3, %eax
    mov %r13, %rdi
    syscall
    test %rax, %rax
    js .fail34
    xor %edi, %edi
    jmp .exit

.forbidden:
    mov $39, %eax''',
    "loopback raw oracle",
)
replace_one(
    "tests/fixtures/probe.S",
    '''.fail33:
    mov $33, %edi

.exit:''',
    '''.fail33:
    mov $33, %edi
    jmp .exit
.fail34:
    mov $34, %edi

.exit:''',
    "fixture fail code",
)
replace_one(
    "tests/fixtures/probe.S",
    '''writable_volume_message:
    .ascii "persistent-write\\n"
.set writable_volume_message_len, . - writable_volume_message
deadline_message:''',
    '''writable_volume_message:
    .ascii "persistent-write\\n"
.set writable_volume_message_len, . - writable_volume_message
loopback_message:
    .ascii "loopback-ok"
.set loopback_message_len, . - loopback_message
deadline_message:''',
    "loopback marker",
)
replace_one(
    "tests/fixtures/probe.S",
    '''network_addr:
    .skip 16

.section .note.GNU-stack,''',
    '''network_addr:
    .skip 16
network_buffer:
    .skip 32

.section .note.GNU-stack,''',
    "loopback buffer",
)
