from pathlib import Path

source_path = Path('.github/tmp-22b-stdout-output-budget.py')
source = source_path.read_text()
first_label = source.index('"lifecycle poll error phase"')
start = source.rfind('replace_one(', 0, first_label)
second_label = source.index('"lifecycle invalid poll phase"')
end = source.index('replace_one(', second_label)
replacement = r'''phase_old = "            let phase = if cancellation_fd >= 0 {\n                phases.cancellation_poll\n            } else {\n                phases.poll\n            };"
phase_new = "            let phase = if output_limit_fd >= 0 {\n                phases.output_limit_poll\n            } else if cancellation_fd >= 0 {\n                phases.cancellation_poll\n            } else {\n                phases.poll\n            };"
phase_path = Path("src/platform/linux_pid_lifecycle.rs")
phase_text = phase_path.read_text()
phase_count = phase_text.count(phase_old)
if phase_count != 2:
    raise SystemExit(f"lifecycle poll phase blocks: expected exactly two matches, got {phase_count}")
phase_path.write_text(phase_text.replace(phase_old, phase_new))
'''
source = source[:start] + replacement + source[end:]
exec(compile(source, str(source_path), 'exec'))
