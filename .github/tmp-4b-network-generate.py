from pathlib import Path


def replace_once(text: str, old: str, new: str, label: str) -> str:
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{label}: expected one match, got {count}")
    return text.replace(old, new, 1)

# Linux backend: create a network namespace together with the existing
# user/mount/PID namespaces, and expose only the syscall names needed by the
# raw integration probe. Launcher operations remain outside target seccomp.
path = Path("src/platform/linux.rs")
text = path.read_text()
text = replace_once(
    text,
    "            libc::CLONE_NEWUSER | libc::CLONE_NEWNS | libc::CLONE_NEWPID,\n",
    "            libc::CLONE_NEWUSER\n"
    "                | libc::CLONE_NEWNS\n"
    "                | libc::CLONE_NEWPID\n"
    "                | libc::CLONE_NEWNET,\n",
    "network namespace unshare",
)
text = replace_once(
    text,
    '            PHASE_NAMESPACE => "user/mount namespace creation",\n',
    '            PHASE_NAMESPACE => "user/mount/PID/network namespace creation",\n',
    "namespace phase label",
)
text = replace_once(
    text,
    '            "ioctl" => libc::SYS_ioctl,\n',
    '            "ioctl" => libc::SYS_ioctl,\n'
    '            "socket" => libc::SYS_socket,\n'
    '            "connect" => libc::SYS_connect,\n',
    "network syscall names",
)
path.write_text(text)

# Integration test: prove the host listener is reachable from the host first,
# then prove an explicitly socket/connect-enabled target cannot reach the same
# loopback listener from the new network namespace.
path = Path("tests/sandbox.rs")
text = path.read_text()
text = replace_once(
    text,
    "use std::collections::{BTreeMap, BTreeSet};\n",
    "use std::collections::{BTreeMap, BTreeSet};\n"
    "use std::net::{TcpListener, TcpStream};\n",
    "network test imports",
)
text = replace_once(
    text,
    "#[test]\nfn allowed_operation_succeeds() {\n",
    "#[test]\n"
    "fn network_namespace_cannot_reach_host_loopback_listener() {\n"
    "    let listener = TcpListener::bind((\"127.0.0.1\", 0)).expect(\"bind host loopback listener\");\n"
    "    let address = listener.local_addr().expect(\"read host listener address\");\n\n"
    "    // Prove the host-side endpoint is genuinely reachable before using it\n"
    "    // as the cross-namespace isolation oracle.\n"
    "    let host_client = TcpStream::connect(address).expect(\"host loopback listener must be reachable\");\n"
    "    let (host_peer, _) = listener.accept().expect(\"accept host reachability probe\");\n"
    "    drop(host_peer);\n"
    "    drop(host_client);\n\n"
    "    let port = address.port().to_string();\n"
    "    let mut isolated = policy(\n"
    "        \"K\",\n"
    "        &[port.as_str()],\n"
    "        &[\"execveat\", \"socket\", \"connect\", \"close\", \"exit\"],\n"
    "    );\n"
    "    isolated.wall_clock_milliseconds = Some(2000);\n\n"
    "    assert_eq!(run(&isolated).unwrap(), ChildOutcome::Exited(0));\n"
    "}\n\n"
    "#[test]\n"
    "fn allowed_operation_succeeds() {\n",
    "network integration test",
)
path.write_text(text)

# Raw x86_64 fixture mode K: connect to 127.0.0.1:argv[2]. socket/connect are
# explicitly allowed. Success is a failure because the host listener must be
# unreachable from the isolated network stack. EPERM is also a failure so
# seccomp denial cannot masquerade as network isolation.
path = Path("tests/fixtures/probe.S")
text = path.read_text()
text = replace_once(
    text,
    "#   Q emit a marker, fork a descendant, then remain live past the policy deadline\n",
    "#   Q emit a marker, fork a descendant, then remain live past the policy deadline\n"
    "#   K assert host loopback listener is unreachable from the target network namespace\n",
    "network probe comment",
)
text = replace_once(
    text,
    "    cmp $81, %al\n    je .deadline_tree\n    jmp .fail2\n",
    "    cmp $81, %al\n"
    "    je .deadline_tree\n"
    "    cmp $75, %al\n"
    "    je .network_isolation\n"
    "    jmp .fail2\n",
    "network probe dispatch",
)
anchor = ".str_eq:\n"
if text.count(anchor) != 1:
    raise SystemExit(f"network behavior anchor: expected one match, got {text.count(anchor)}")
network_block = r'''.network_isolation:
    mov 24(%rsp), %rdi
    test %rdi, %rdi
    je .fail2
    xor %r12d, %r12d
.network_port_parse_loop:
    movzbl (%rdi), %eax
    test %al, %al
    je .network_port_parsed
    sub $48, %eax
    cmp $9, %eax
    ja .fail2
    imul $10, %r12d, %r12d
    add %eax, %r12d
    cmp $65535, %r12d
    ja .fail2
    inc %rdi
    jmp .network_port_parse_loop
.network_port_parsed:
    test %r12d, %r12d
    je .fail2
    movw $2, network_addr(%rip)
    rolw $8, %r12w
    movw %r12w, network_addr+2(%rip)
    movl $0x0100007f, network_addr+4(%rip)

    mov $41, %eax
    mov $2, %edi
    mov $1, %esi
    xor %edx, %edx
    syscall
    test %rax, %rax
    js .fail26
    mov %rax, %r13

    mov $42, %eax
    mov %r13, %rdi
    lea network_addr(%rip), %rsi
    mov $16, %edx
    syscall
    test %rax, %rax
    jns .network_unexpected_reachability
    cmp $-111, %rax
    je .network_isolated
    cmp $-101, %rax
    je .network_isolated
    cmp $-113, %rax
    je .network_isolated
    jmp .fail26

.network_unexpected_reachability:
    mov $3, %eax
    mov %r13, %rdi
    syscall
    jmp .fail26

.network_isolated:
    mov $3, %eax
    mov %r13, %rdi
    syscall
    test %rax, %rax
    js .fail26
    xor %edi, %edi
    jmp .exit

'''
text = text.replace(anchor, network_block + anchor, 1)
text = replace_once(
    text,
    ".fail25:\n    mov $25, %edi\n\n.exit:\n",
    ".fail25:\n"
    "    mov $25, %edi\n"
    "    jmp .exit\n"
    ".fail26:\n"
    "    mov $26, %edi\n\n"
    ".exit:\n",
    "network failure code",
)
text = replace_once(
    text,
    "redirect_buffer:\n    .skip 1\n",
    "redirect_buffer:\n"
    "    .skip 1\n"
    ".balign 16\n"
    "network_addr:\n"
    "    .skip 16\n",
    "network sockaddr storage",
)
path.write_text(text)
