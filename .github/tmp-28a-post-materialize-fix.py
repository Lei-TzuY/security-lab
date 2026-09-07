from pathlib import Path
import re

path = Path("src/policy.rs")
text = path.read_text()


def replace_test(name: str, next_name: str, replacement: str) -> None:
    global text
    pattern = (
        rf"    #\[test\]\n    fn {re.escape(name)}\(\) \{{.*?"
        rf"(?=    #\[test\]\n    fn {re.escape(next_name)}\(\))"
    )
    text, count = re.subn(pattern, replacement, text, count=1, flags=re.S)
    if count != 1:
        raise SystemExit(f"{name}: expected exactly one generated test, got {count}")


replace_test(
    "parses_bounded_named_persistent_volume_graph",
    "rejects_incomplete_overlapping_or_oversized_named_volume_graph",
    r'''    #[test]
    fn parses_bounded_named_persistent_volume_graph() {
        let base = volume_valid();
        let text = format!(
            "{base}\nvolume.mount.assets.source = /srv/assets\nvolume.mount.assets.target = /assets\nvolume.mount.assets.access = read-only\nvolume.mount.state.source = /srv/state\nvolume.mount.state.target = /state\nvolume.mount.state.access = writable"
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

''',
)

replace_test(
    "rejects_incomplete_overlapping_or_oversized_named_volume_graph",
    "parses_stdout_redirect_inside_scratch",
    r'''    #[test]
    fn rejects_incomplete_overlapping_or_oversized_named_volume_graph() {
        let base = volume_valid();
        let incomplete = format!(
            "{base}\nvolume.mount.assets.source = /srv/assets\nvolume.mount.assets.target = /assets"
        );
        assert!(incomplete.parse::<SandboxPolicy>().is_err());

        let overlapping_targets = format!(
            "{base}\nvolume.mount.a.source = /srv/a\nvolume.mount.a.target = /data\nvolume.mount.a.access = read-only\nvolume.mount.b.source = /srv/b\nvolume.mount.b.target = /data/nested\nvolume.mount.b.access = writable"
        );
        let error = overlapping_targets.parse::<SandboxPolicy>().unwrap_err();
        assert!(error.to_string().contains("target paths must not overlap"));

        let mut oversized = base;
        for index in 0..9 {
            oversized.push_str(&format!(
                "volume.mount.v{index}.source = /srv/v{index}\nvolume.mount.v{index}.target = /v{index}\nvolume.mount.v{index}.access = read-only\n"
            ));
        }
        let error = oversized.parse::<SandboxPolicy>().unwrap_err();
        assert!(error.to_string().contains("too many persistent volumes"));
    }

''',
)

old = "landlock.file_mutate must be within filesystem.scratch or a writable persistent volume target"
new = "landlock.file_mutate must be within filesystem.scratch or volume.writable_target (including named writable persistent volume targets)"
if text.count(old) != 1:
    raise SystemExit(f"Landlock compatibility message: expected exactly one match, got {text.count(old)}")
text = text.replace(old, new, 1)

path.write_text(text)
