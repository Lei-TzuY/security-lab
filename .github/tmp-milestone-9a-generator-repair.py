from pathlib import Path

path = Path('.github/tmp-milestone-9a-loopback-networking.py')
text = path.read_text()
old = '''replace_one(
    "tests/sandbox.rs",
    \'\'\'    let isolated = policy(
        "K",
        &[port.as_str()],
        &["execveat", "socket", "connect", "close", "exit"],
    );
    assert_eq!(run(&isolated).unwrap(), ChildOutcome::Exited(0));\'\'\',
    \'\'\'    let mut isolated = policy(
        "K",
        &[port.as_str()],
        &["execveat", "socket", "connect", "close", "exit"],
    );
    isolated.loopback_enabled = true;
    assert_eq!(run(&isolated).unwrap(), ChildOutcome::Exited(0));\'\'\',
    "host isolation with loopback enabled",
)'''
new = '''replace_one(
    "tests/sandbox.rs",
    \'\'\'    let mut isolated = policy(
        "K",
        &[port.as_str()],
        &["execveat", "socket", "connect", "close", "exit"],
    );
    isolated.wall_clock_milliseconds = Some(2000);

    assert_eq!(run(&isolated).unwrap(), ChildOutcome::Exited(0));\'\'\',
    \'\'\'    let mut isolated = policy(
        "K",
        &[port.as_str()],
        &["execveat", "socket", "connect", "close", "exit"],
    );
    isolated.loopback_enabled = true;
    isolated.wall_clock_milliseconds = Some(2000);

    assert_eq!(run(&isolated).unwrap(), ChildOutcome::Exited(0));\'\'\',
    "host isolation with loopback enabled",
)'''
count = text.count(old)
if count != 1:
    raise SystemExit(f'host-isolation generator repair: expected one block, got {count}')
path.write_text(text.replace(old, new, 1))
