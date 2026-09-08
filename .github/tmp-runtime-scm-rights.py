from pathlib import Path


def replace_one(path: str, old: str, new: str, label: str) -> None:
    p = Path(path)
    text = p.read_text()
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{label}: expected exactly one match, got {count}")
    p.write_text(text.replace(old, new, 1))


# Target seccomp must explicitly name recvmsg before a post-launch descriptor
# transfer can be consumed. Do not add sendmsg: this slice is receive-only.
replace_one(
    "src/platform/linux.rs",
    '            "listen" => libc::SYS_listen,\n            "msgget" => libc::SYS_msgget,',
    '            "listen" => libc::SYS_listen,\n            "recvmsg" => libc::SYS_recvmsg,\n            "msgget" => libc::SYS_msgget,',
    "recvmsg syscall mapping",
)

# Reserve digit 0 as a new raw fixture mode because all alphabetic mode bytes
# are already occupied. The mode proves the transfer happens only after exec.
replace_one(
    "tests/fixtures/probe.S",
    "#   b exchange bytes over a brokered host pathname AF_UNIX stream; direct host path stays hidden\n",
    "#   b exchange bytes over a brokered host pathname AF_UNIX stream; direct host path stays hidden\n#   0 receive one post-launch SCM_RIGHTS fd over that broker and prove its host pathname stays hidden\n",
    "fixture mode documentation",
)
replace_one(
    "tests/fixtures/probe.S",
    "    cmp $98, %al\n    je .brokered_host_unix\n",
    "    cmp $98, %al\n    je .brokered_host_unix\n    cmp $48, %al\n    je .brokered_host_unix_scm_rights\n",
    "fixture dispatch",
)

scm_rights_routine = r'''.brokered_host_unix_scm_rights:
    # argv[2] is the original trusted host pathname for the transferred file.
    # Preserve it across the stack frame so we can prove chroot keeps it hidden.
    mov 24(%rsp), %r13
    test %r13, %r13
    je .fail29
    sub $160, %rsp
    mov $-1, %r12

    # Publish a one-byte readiness handshake from executed target code. The host
    # peer waits for this byte before sendmsg(SCM_RIGHTS), making the capability
    # transfer observably post-launch rather than preloaded in the socket buffer.
    movb $82, 143(%rsp)
    mov $1, %eax
    mov $10, %edi
    lea 143(%rsp), %rsi
    mov $1, %edx
    syscall
    cmp $1, %rax
    jne .brokered_host_unix_scm_rights_fail

    # Build one iovec plus a 24-byte ancillary buffer for exactly one descriptor.
    # Linux x86_64 msghdr layout is 56 bytes; cmsghdr is 16 bytes and one int
    # produces CMSG_LEN=20 / CMSG_SPACE=24.
    xor %eax, %eax
    mov %rax, 0(%rsp)
    mov %rax, 8(%rsp)
    lea 64(%rsp), %rax
    mov %rax, 16(%rsp)
    movq $1, 24(%rsp)
    lea 80(%rsp), %rax
    mov %rax, 32(%rsp)
    movq $24, 40(%rsp)
    movq $0, 48(%rsp)

    lea 144(%rsp), %rax
    mov %rax, 64(%rsp)
    movq $1, 72(%rsp)
    movq $0, 80(%rsp)
    movq $0, 88(%rsp)
    movq $0, 96(%rsp)

    # MSG_CMSG_CLOEXEC ensures the received capability cannot survive a later
    # exec unless the target deliberately clears FD_CLOEXEC.
    mov $47, %eax
    mov $10, %edi
    mov %rsp, %rsi
    mov $0x40000000, %edx
    syscall
    cmp $1, %rax
    jne .brokered_host_unix_scm_rights_fail
    cmpb $70, 144(%rsp)
    jne .brokered_host_unix_scm_rights_fail
    testl $8, 48(%rsp)
    jne .brokered_host_unix_scm_rights_fail
    cmpq $20, 80(%rsp)
    jne .brokered_host_unix_scm_rights_fail
    cmpl $1, 88(%rsp)
    jne .brokered_host_unix_scm_rights_fail
    cmpl $1, 92(%rsp)
    jne .brokered_host_unix_scm_rights_fail
    mov 96(%rsp), %r12d
    test %r12d, %r12d
    js .brokered_host_unix_scm_rights_fail

    # The handed-off descriptor must carry the exact file object capability.
    mov $0, %eax
    mov %r12d, %edi
    lea 112(%rsp), %rsi
    mov $runtime_fd_handoff_marker_len, %edx
    syscall
    cmp $runtime_fd_handoff_marker_len, %rax
    jne .brokered_host_unix_scm_rights_fail
    lea 112(%rsp), %rsi
    lea runtime_fd_handoff_marker(%rip), %rdi
    mov $runtime_fd_handoff_marker_len, %ecx
    repe cmpsb
    jne .brokered_host_unix_scm_rights_fail

    mov $3, %eax
    mov %r12d, %edi
    syscall
    test %rax, %rax
    js .brokered_host_unix_scm_rights_fail
    mov $-1, %r12

    # The descriptor grant must not make the original host pathname reachable.
    mov $257, %eax
    mov $-100, %edi
    mov %r13, %rsi
    xor %edx, %edx
    xor %r10d, %r10d
    syscall
    cmp $-2, %rax
    je .brokered_host_unix_scm_rights_close_broker
    test %rax, %rax
    js .brokered_host_unix_scm_rights_fail
    mov %rax, %r14
    mov $3, %eax
    mov %r14, %rdi
    syscall
    jmp .brokered_host_unix_scm_rights_fail

.brokered_host_unix_scm_rights_close_broker:
    mov $3, %eax
    mov $10, %edi
    syscall
    test %rax, %rax
    js .brokered_host_unix_scm_rights_fail
    add $160, %rsp
    xor %edi, %edi
    jmp .exit

.brokered_host_unix_scm_rights_fail:
    test %r12d, %r12d
    js .brokered_host_unix_scm_rights_fail_restore
    mov $3, %eax
    mov %r12d, %edi
    syscall
.brokered_host_unix_scm_rights_fail_restore:
    add $160, %rsp
    jmp .fail29

'''
replace_one(
    "tests/fixtures/probe.S",
    ".brokered_host_unix:\n",
    scm_rights_routine + ".brokered_host_unix:\n",
    "SCM_RIGHTS raw fixture routine",
)
replace_one(
    "tests/fixtures/probe.S",
    'brokered_host_unix_message:\n    .ascii "brokered-host-unix-ok"\n.set brokered_host_unix_message_len, . - brokered_host_unix_message\n',
    'brokered_host_unix_message:\n    .ascii "brokered-host-unix-ok"\n.set brokered_host_unix_message_len, . - brokered_host_unix_message\nruntime_fd_handoff_marker:\n    .ascii "runtime-fd-handoff-ok\\n"\n.set runtime_fd_handoff_marker_len, . - runtime_fd_handoff_marker\n',
    "SCM_RIGHTS expected marker",
)

send_helper = r'''#[repr(C, align(8))]
struct OneFdControl([u8; 24]);

fn send_one_fd(socket_fd: RawFd, source_fd: RawFd) {
    let mut payload = *b"F";
    let mut iovec = libc::iovec {
        iov_base: payload.as_mut_ptr().cast::<libc::c_void>(),
        iov_len: payload.len(),
    };
    let mut control = OneFdControl([0; 24]);
    let header = control.0.as_mut_ptr().cast::<libc::cmsghdr>();
    unsafe {
        (*header).cmsg_len = std::mem::size_of::<libc::cmsghdr>() + std::mem::size_of::<RawFd>();
        (*header).cmsg_level = libc::SOL_SOCKET;
        (*header).cmsg_type = libc::SCM_RIGHTS;
        control
            .0
            .as_mut_ptr()
            .add(std::mem::size_of::<libc::cmsghdr>())
            .cast::<RawFd>()
            .write(source_fd);
    }

    let mut message = unsafe { std::mem::zeroed::<libc::msghdr>() };
    message.msg_iov = &mut iovec;
    message.msg_iovlen = 1;
    message.msg_control = control.0.as_mut_ptr().cast::<libc::c_void>();
    message.msg_controllen = control.0.len();

    loop {
        let sent = unsafe { libc::sendmsg(socket_fd, &message, 0) };
        if sent == 1 {
            return;
        }
        if sent == -1 {
            let error = std::io::Error::last_os_error();
            if error.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            panic!("SCM_RIGHTS sendmsg failed: {error}");
        }
        panic!("SCM_RIGHTS sendmsg wrote unexpected payload length {sent}");
    }
}

'''
replace_one(
    "tests/sandbox.rs",
    "fn write_all_fd(fd: RawFd, buffer: &[u8]) {\n",
    send_helper + "fn write_all_fd(fd: RawFd, buffer: &[u8]) {\n",
    "SCM_RIGHTS test sender helper",
)

integration_test = r'''#[test]
fn brokered_host_unix_stream_transfers_one_post_launch_fd_via_scm_rights() {
    let socket_path = std::env::temp_dir().join(format!(
        "security-lab-runtime-rights-{}.sock",
        process::id()
    ));
    let marker_path = std::env::temp_dir().join(format!(
        "security-lab-runtime-rights-marker-{}",
        process::id()
    ));
    let _ = std::fs::remove_file(&socket_path);
    let _ = std::fs::remove_file(&marker_path);
    std::fs::write(&marker_path, b"runtime-fd-handoff-ok\n")
        .expect("seed runtime descriptor handoff marker");

    let listener = UnixListener::bind(&socket_path).expect("bind runtime SCM_RIGHTS endpoint");
    let marker_for_server = marker_path.clone();
    let server = thread::spawn(move || {
        let (stream, _) = listener
            .accept()
            .expect("accept runtime SCM_RIGHTS broker connection");
        let mut ready = [0u8; 1];
        read_exact_fd(stream.as_raw_fd(), &mut ready);
        assert_eq!(&ready, b"R", "target must execute before the FD is sent");
        let marker = std::fs::File::open(marker_for_server)
            .expect("open runtime descriptor handoff marker");
        send_one_fd(stream.as_raw_fd(), marker.as_raw_fd());
    });

    let marker_argument = marker_path.to_string_lossy().into_owned();
    let mut brokered = policy(
        "0",
        &[marker_argument.as_str()],
        &[
            "execveat", "write", "recvmsg", "read", "close", "openat", "exit",
        ],
    );
    brokered.host_unix_stream_path = Some(socket_path.clone());
    brokered.host_unix_stream_target_fd = Some(10);
    brokered.host_unix_stream_peer_uid = Some(unsafe { libc::geteuid() });
    brokered.host_unix_stream_peer_gid = Some(unsafe { libc::getegid() });
    brokered.wall_clock_milliseconds = Some(2000);

    let result = run(&brokered);
    server.join().expect("runtime SCM_RIGHTS server failed");
    let _ = std::fs::remove_file(&socket_path);
    let _ = std::fs::remove_file(&marker_path);
    assert_eq!(result.unwrap(), ChildOutcome::Exited(0));
}

'''
replace_one(
    "tests/sandbox.rs",
    "#[test]\nfn network_namespace_cannot_reach_host_loopback_listener() {\n",
    integration_test + "#[test]\nfn network_namespace_cannot_reach_host_loopback_listener() {\n",
    "SCM_RIGHTS integration test",
)
