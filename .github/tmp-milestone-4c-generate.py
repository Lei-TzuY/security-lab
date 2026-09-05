from pathlib import Path


def replace_one(path: str, old: str, new: str, label: str) -> None:
    p = Path(path)
    text = p.read_text()
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{label}: expected exactly one match, got {count}")
    p.write_text(text.replace(old, new, 1))


replace_one(
    "src/platform/linux.rs",
    "            libc::CLONE_NEWUSER | libc::CLONE_NEWNS | libc::CLONE_NEWPID | libc::CLONE_NEWNET,\n",
    "            libc::CLONE_NEWUSER\n                | libc::CLONE_NEWNS\n                | libc::CLONE_NEWPID\n                | libc::CLONE_NEWNET\n                | libc::CLONE_NEWIPC,\n",
    "IPC namespace unshare",
)
replace_one(
    "src/platform/linux.rs",
    '            PHASE_NAMESPACE => "user/mount/PID/network namespace creation",\n',
    '            PHASE_NAMESPACE => "user/mount/PID/network/IPC namespace creation",\n',
    "namespace failure label",
)
replace_one(
    "src/platform/linux.rs",
    '            "connect" => libc::SYS_connect,\n',
    '            "connect" => libc::SYS_connect,\n            "msgget" => libc::SYS_msgget,\n',
    "msgget syscall mapping",
)

replace_one(
    "tests/fixtures/probe.S",
    "#   K assert host loopback listener is unreachable from the target network namespace\n",
    "#   K assert host loopback listener is unreachable from the target network namespace\n#   L assert host SysV message queue key is invisible in the target IPC namespace\n",
    "IPC fixture mode comment",
)
replace_one(
    "tests/fixtures/probe.S",
    "    cmp $75, %al\n    je .network_isolation\n    jmp .fail2\n",
    "    cmp $75, %al\n    je .network_isolation\n    cmp $76, %al\n    je .ipc_isolation\n    jmp .fail2\n",
    "IPC fixture dispatch",
)
replace_one(
    "tests/fixtures/probe.S",
    "    xor %edi, %edi\n    jmp .exit\n\n.str_eq:\n",
    "    xor %edi, %edi\n    jmp .exit\n\n.ipc_isolation:\n    mov 24(%rsp), %rdi\n    test %rdi, %rdi\n    je .fail2\n    xor %r12d, %r12d\n.ipc_key_parse_loop:\n    movzbl (%rdi), %eax\n    test %al, %al\n    je .ipc_key_parsed\n    sub $48, %eax\n    cmp $9, %eax\n    ja .fail2\n    imul $10, %r12d, %r12d\n    add %eax, %r12d\n    inc %rdi\n    jmp .ipc_key_parse_loop\n.ipc_key_parsed:\n    test %r12d, %r12d\n    je .fail2\n    mov $68, %eax\n    mov %r12d, %edi\n    xor %esi, %esi\n    syscall\n    cmp $-2, %rax\n    jne .fail27\n    xor %edi, %edi\n    jmp .exit\n\n.str_eq:\n",
    "IPC raw fixture",
)
replace_one(
    "tests/fixtures/probe.S",
    ".fail26:\n    mov $26, %edi\n\n.exit:\n",
    ".fail26:\n    mov $26, %edi\n    jmp .exit\n.fail27:\n    mov $27, %edi\n\n.exit:\n",
    "IPC fixture failure label",
)

network_test = '''#[test]\nfn network_namespace_cannot_reach_host_loopback_listener() {\n    let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind host loopback listener");\n    let address = listener.local_addr().expect("read host listener address");\n\n    // Prove the host-side endpoint is genuinely reachable before using it\n    // as the cross-namespace isolation oracle.\n    let host_client =\n        TcpStream::connect(address).expect("host loopback listener must be reachable");\n    let (host_peer, _) = listener.accept().expect("accept host reachability probe");\n    drop(host_peer);\n    drop(host_client);\n\n    let port = address.port().to_string();\n    let mut isolated = policy(\n        "K",\n        &[port.as_str()],\n        &["execveat", "socket", "connect", "close", "exit"],\n    );\n    isolated.wall_clock_milliseconds = Some(2000);\n\n    assert_eq!(run(&isolated).unwrap(), ChildOutcome::Exited(0));\n}\n'''
ipc_test = network_test + '''\n#[test]\nfn ipc_namespace_cannot_observe_host_sysv_message_queue() {\n    let base_key = 0x534c_0000_i32.wrapping_add(((process::id() & 0x0fff) as i32) << 4);\n    let mut created = None;\n    for offset in 0..16_i32 {\n        let key = base_key.wrapping_add(offset) as libc::key_t;\n        let queue_id = unsafe {\n            libc::msgget(\n                key,\n                libc::IPC_CREAT | libc::IPC_EXCL | 0o600,\n            )\n        };\n        if queue_id >= 0 {\n            created = Some((key, queue_id));\n            break;\n        }\n        let error = std::io::Error::last_os_error();\n        assert_eq!(\n            error.raw_os_error(),\n            Some(libc::EEXIST),\n            "host msgget failed before finding a free key: {error}"\n        );\n    }\n\n    let (key, queue_id) = created.expect("create host SysV message queue");\n    let host_lookup = unsafe { libc::msgget(key, 0) };\n    assert_eq!(\n        host_lookup, queue_id,\n        "host must observe the queue before it is used as an IPC namespace oracle"\n    );\n\n    let key_text = (key as i64).to_string();\n    let result = run(&policy(\n        "L",\n        &[key_text.as_str()],\n        &["execveat", "msgget", "exit"],\n    ));\n\n    let removed = unsafe { libc::msgctl(queue_id, libc::IPC_RMID, std::ptr::null_mut()) };\n    assert_eq!(removed, 0, "remove host SysV message queue");\n    assert_eq!(result.unwrap(), ChildOutcome::Exited(0));\n}\n'''
replace_one(
    "tests/sandbox.rs",
    network_test,
    ipc_test,
    "IPC integration test",
)
