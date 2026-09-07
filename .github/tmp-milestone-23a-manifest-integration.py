from pathlib import Path


def replace_one(path: str, old: str, new: str, label: str) -> None:
    p = Path(path)
    text = p.read_text()
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{label}: expected exactly one match, got {count}")
    p.write_text(text.replace(old, new, 1))


# Regression first: the static authority manifest must expose the time-namespace grant.
replace_one(
    "tests/authority_manifest_cli.rs",
    "working_dir = /work\nstdio.stdin = closed",
    "working_dir = /work\ntime.monotonic_offset_seconds = 3600\ntime.boottime_offset_seconds = 7200\nstdio.stdin = closed",
    "manifest fixture time namespace",
)
replace_one(
    "tests/authority_manifest_cli.rs",
    "    assert!(stdout.contains(\"\\\"stdout_capture_bytes\\\":1024,\\\"stdout_total_bytes\\\":4096\"));\n",
    "    assert!(stdout.contains(\"\\\"stdout_capture_bytes\\\":1024,\\\"stdout_total_bytes\\\":4096,\\\"time_namespace\\\":{\\\"monotonic_offset_seconds\\\":3600,\\\"boottime_offset_seconds\\\":7200}\"));\n",
    "manifest JSON time namespace assertion",
)
replace_one(
    "tests/authority_manifest_cli.rs",
    "    assert!(stdout.contains(\"seccomp: allow=5 masked=1 ranges=1\\n\"));\n",
    "    assert!(stdout.contains(\"seccomp: allow=5 masked=1 ranges=1\\n\"));\n    assert!(stdout.contains(\"time-namespace: monotonic-offset-seconds=3600 boottime-offset-seconds=7200\\n\"));\n",
    "manifest human time namespace assertion",
)

# Production: represent the grant explicitly without implying runtime preflight.
replace_one(
    "src/authority_manifest.rs",
    "    output.push_str(\",\\\"stdout_total_bytes\\\":\");\n    push_optional_u64(&mut output, policy.stdout_total_bytes);\n    output.push('}');\n",
    "    output.push_str(\",\\\"stdout_total_bytes\\\":\");\n    push_optional_u64(&mut output, policy.stdout_total_bytes);\n    output.push_str(\",\\\"time_namespace\\\":\");\n    match (\n        policy.time_monotonic_offset_seconds,\n        policy.time_boottime_offset_seconds,\n    ) {\n        (Some(monotonic), Some(boottime)) => {\n            output.push_str(\"{\\\"monotonic_offset_seconds\\\":\");\n            write!(&mut output, \"{monotonic}\").expect(\"write to String cannot fail\");\n            output.push_str(\",\\\"boottime_offset_seconds\\\":\");\n            write!(&mut output, \"{boottime}\").expect(\"write to String cannot fail\");\n            output.push('}');\n        }\n        _ => output.push_str(\"null\"),\n    }\n    output.push('}');\n",
    "manifest JSON time namespace",
)
replace_one(
    "src/authority_manifest.rs",
    "    writeln!(\n        &mut output,\n        \"seccomp: allow={} masked={} ranges={}\",\n",
    "    match (\n        policy.time_monotonic_offset_seconds,\n        policy.time_boottime_offset_seconds,\n    ) {\n        (Some(monotonic), Some(boottime)) => writeln!(\n            &mut output,\n            \"time-namespace: monotonic-offset-seconds={monotonic} boottime-offset-seconds={boottime}\"\n        )\n        .expect(\"write to String cannot fail\"),\n        _ => writeln!(&mut output, \"time-namespace: none\")\n            .expect(\"write to String cannot fail\"),\n    }\n    writeln!(\n        &mut output,\n        \"seccomp: allow={} masked={} ranges={}\",\n",
    "manifest human time namespace",
)
