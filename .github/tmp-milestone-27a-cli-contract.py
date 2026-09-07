from pathlib import Path

path = Path("tests/cli.rs")
text = path.read_text()
old = "{\\\"base_namespaces\\\":true,\\\"time_namespace_offsets\\\":false,\\\"hostname\\\":true,\\\"private_mount_propagation\\\":true,\\\"readonly_root\\\":true,\\\"chroot\\\":true,\\\"fd_sanitization\\\":true,\\\"private_procfs\\\":false,\\\"rlimits\\\":true,\\\"capabilities_reduced\\\":true,\\\"no_new_privs\\\":true,\\\"landlock\\\":false,\\\"seccomp\\\":true}}\\n"
new = "{\\\"base_namespaces\\\":true,\\\"time_namespace_offsets\\\":false,\\\"hostname\\\":true,\\\"private_mount_propagation\\\":true,\\\"readonly_root\\\":true,\\\"copy_on_write_root\\\":false,\\\"chroot\\\":true,\\\"fd_sanitization\\\":true,\\\"private_procfs\\\":false,\\\"rlimits\\\":true,\\\"capabilities_reduced\\\":true,\\\"no_new_privs\\\":true,\\\"landlock\\\":false,\\\"seccomp\\\":true}}\\n"
if text.count(old) != 1:
    raise SystemExit(f"CLI receipt contract: expected one match, got {text.count(old)}")
path.write_text(text.replace(old, new, 1))
