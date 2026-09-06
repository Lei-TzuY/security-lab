from pathlib import Path


def replace_one(path: str, old: str, new: str, label: str) -> None:
    p = Path(path)
    text = p.read_text()
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{label}: expected exactly one match, got {count}")
    p.write_text(text.replace(old, new, 1))


# README: synchronize the executable 6A/7A status and control-plane semantics.
replace_one(
    "README.md",
    "The current Milestone 6A candidate adds **explicit selected non-stdio handle passing**: the launcher may pin an already-open non-directory object before fork and expose it only at one declared target descriptor while undeclared descriptors remain sanitized.",
    "Milestone 6A added **explicit selected non-stdio handle passing** without reopening ambient descriptor inheritance. The current Milestone 7A candidate adds **caller-owned external cancellation**: a cloneable one-way token can ask launcher-owned PID 1 to terminate and reap the sandbox process tree while the token itself remains outside target authority.",
    "README status summary",
)
replace_one(
    "README.md",
    "7. **Optional deadline supervision** after forking the target, PID 1 closes inherited setup descriptors, opens a pidfd for the direct target, creates and arms a `CLOCK_MONOTONIC` timerfd, and polls pidfd + timerfd. The timer starts at this supervision point; it is not a claim about total host-side launch latency before the target fork.\n8. **Deterministic deadline race** whenever supervision wakes, PID 1 first performs one `wait4(target, WNOHANG)`. If the direct target is already waitable, natural termination wins. Otherwise, when the timer is readable, deadline ownership begins; PID 1 sends `SIGKILL` to the direct target and the result is reported as `ChildOutcome::TimedOut`, not as an ordinary target signal.",
    "7. **Optional deadline/cancellation supervision** after forking the target, PID 1 closes inherited setup descriptors, opens a pidfd whenever deadline or external cancellation supervision is active, optionally creates and arms a `CLOCK_MONOTONIC` timerfd, and optionally retains the launcher-pinned cancellation eventfd. The direct target closes the cancellation control descriptor before stdio/rlimit/capability/seccomp/exec setup, so the token is not a target capability.\n8. **Deterministic supervision race** whenever supervision wakes, PID 1 first performs one `wait4(target, WNOHANG)`. If the direct target is already waitable, natural termination wins. Otherwise a readable cancellation eventfd wins before a simultaneously readable deadline timer; PID 1 terminates the direct target and reports `ChildOutcome::Cancelled` or `ChildOutcome::TimedOut` according to the winning control path.",
    "README supervision pipeline",
)
replace_one(
    "README.md",
    "10. **Owned process-tree teardown** after natural target termination or deadline termination, PID 1 repeatedly sends `SIGKILL` to remaining namespace processes and reaps children with `wait4` until `ECHILD`. It then publishes raw target wait status, timeout ownership, and the number of additional descendants reaped.\n11. **Bounded stdout capture** the host parent drains capture before waiting for bootstrap completion, retains only the declared byte ceiling, and discards excess bytes. A deadline can still fire while that host drain is blocking because deadline enforcement lives in PID 1; killing/reaping the target tree closes remaining capture writers and lets EOF converge.\n12. **Reporting** `run_report()` returns `Exited(code)`, `Signaled(signal)`, or `TimedOut`, plus captured stdout and `reaped_descendants`. The compatibility `run()` path returns the same `ChildOutcome`. The CLI maps `TimedOut` to exit status 124.",
    "10. **Owned process-tree teardown** after natural target termination, deadline termination, or external cancellation, PID 1 repeatedly sends `SIGKILL` to remaining namespace processes and reaps children with `wait4` until `ECHILD`. It then publishes raw target wait status, timeout/cancellation ownership, and the number of additional descendants reaped.\n11. **Bounded stdout capture** the host parent drains capture before waiting for bootstrap completion, retains only the declared byte ceiling, and discards excess bytes. Deadline or external cancellation can still fire while that host drain is blocking because supervision lives in PID 1; terminating/reaping the target tree closes remaining capture writers and lets EOF converge.\n12. **Reporting** `run_report()` / `run_report_with_cancel()` return `Exited(code)`, `Signaled(signal)`, `TimedOut`, or `Cancelled`, plus captured stdout and `reaped_descendants`. The compatibility status-only APIs return the same `ChildOutcome`. The CLI maps `TimedOut` to exit status 124 and `Cancelled` to 130.",
    "README teardown and reporting",
)
replace_one(
    "README.md",
    "- `TimedOut` is distinct from `Signaled(SIGKILL)`, even though `SIGKILL` is the kernel mechanism used after deadline ownership is established.\n- After either natural or timeout termination, PID 1 kills/reaps remaining descendants before lifecycle readiness is published.",
    "- `TimedOut` and `Cancelled` are distinct from `Signaled(SIGKILL)`, even though `SIGKILL` is the kernel mechanism used after either launcher control path wins.\n- `CancellationToken` is cloneable and one-way: once any clone calls `cancel()`, its eventfd remains readable and later cancellable runs using that token observe the already-cancelled state. The launcher pins a duplicate before fork, bootstrap drops it, PID 1 alone retains it for supervision, and the direct target closes it before untrusted execution.\n- Supervision arbitration is natural exit > explicit cancellation > deadline when readiness is observed in one poll cycle.\n- After natural, timeout, or cancelled termination, PID 1 kills/reaps remaining descendants before lifecycle readiness is published.",
    "README cancellation invariants",
)
replace_one(
    "README.md",
    "Library callers can distinguish deadline termination directly:\n\n```rust\nlet report = security_lab::run_report(&policy)?;\nmatch report.outcome {\n    security_lab::ChildOutcome::TimedOut => {\n        // The launcher-owned monotonic deadline won the termination race.\n    }\n    security_lab::ChildOutcome::Exited(code) => println!(\"exit {code}\"),\n    security_lab::ChildOutcome::Signaled(signal) => println!(\"signal {signal}\"),\n}\n```",
    "Library callers can distinguish natural exit, deadline termination, and caller-requested cancellation. Existing `run` / `run_report` APIs remain unchanged; cancellable runs use `run_with_cancel` / `run_report_with_cancel`:\n\n```rust\nlet cancellation = security_lab::CancellationToken::new()?;\nlet worker_token = cancellation.clone();\n// Another thread may call `cancellation.cancel()` after an application-defined readiness event.\nlet report = security_lab::run_report_with_cancel(&policy, &worker_token)?;\nmatch report.outcome {\n    security_lab::ChildOutcome::TimedOut => println!(\"deadline\"),\n    security_lab::ChildOutcome::Cancelled => println!(\"cancelled\"),\n    security_lab::ChildOutcome::Exited(code) => println!(\"exit {code}\"),\n    security_lab::ChildOutcome::Signaled(signal) => println!(\"signal {signal}\"),\n}\n```",
    "README cancellation API example",
)
replace_one(
    "README.md",
    "- a fast raw target under a **5,000 ms** deadline still reports its natural `Exited(42)` outcome.",
    "- a fast raw target under a **5,000 ms** deadline still reports its natural `Exited(42)` outcome;\n- external-cancellation evidence uses an exact readiness pipe rather than a sleep: the raw target forks one descendant, writes `cancellation-target-ready\\n` through selected fd 9, and pauses. Only after the parent reads the full marker does it call `CancellationToken::cancel()`. PID 1 reports `Cancelled`, reaps exactly one descendant, and an uncancelled token separately preserves a fast target's natural `Exited(42)` result.",
    "README cancellation evidence",
)
replace_one(
    "README.md",
    "When a wall-clock deadline is declared, `pidfd_open`, `timerfd_create`/`timerfd_settime`, `CLOCK_MONOTONIC`, and `poll` are additionally required.",
    "When a wall-clock deadline is declared, `pidfd_open`, `timerfd_create`/`timerfd_settime`, `CLOCK_MONOTONIC`, and `poll` are additionally required. External cancellation additionally requires `eventfd`; cancellable supervision also uses `pidfd_open` and `poll`.",
    "README platform cancellation support",
)
replace_one(
    "README.md",
    "- `limit.wall_clock_milliseconds` is a launcher-owned deadline, **not** an externally-triggerable asynchronous cancellation handle or API;",
    "- external cancellation is a one-way launcher control primitive, not a resettable/rearmable token, arbitrary signal-forwarding API, general control RPC, or guarantee on end-to-end cancellation latency from API entry;",
    "README cancellation limitation",
)

# Threat model: synchronize claimed boundary, lifecycle arbitration, and non-goals.
replace_one(
    "THREAT_MODEL.md",
    "# Milestones 1–6A threat model",
    "# Milestones 1–7A threat model",
    "threat model title",
)
replace_one(
    "THREAT_MODEL.md",
    "and Milestone 5A added masked numeric syscall-argument constraints. The current Milestone 6A candidate adds explicit launch-time selected non-stdio object capabilities without reopening ambient descriptor inheritance.",
    "Milestone 5A added masked numeric syscall-argument constraints; and Milestone 6A added explicit launch-time selected non-stdio object capabilities without reopening ambient descriptor inheritance. The current Milestone 7A candidate adds a caller-owned external cancellation control plane whose launcher-owned PID 1 supervision terminates and reaps the sandbox process tree.",
    "threat model purpose status",
)
replace_one(
    "THREAT_MODEL.md",
    "and—when declared—a wall-clock execution deadline while preserving fail-closed launch/lifecycle reporting.",
    "a wall-clock execution deadline when declared, and caller-requested external cancellation when the cancellable API is used, while preserving fail-closed launch/lifecycle reporting.",
    "threat model protected boundary",
)
replace_one(
    "THREAT_MODEL.md",
    "- **Owned PID-tree lifecycle:** namespace PID 1 supervises the direct target and reaps descendants. After the direct target becomes terminal—naturally or by deadline—PID 1 repeatedly kills remaining namespace processes and reaps until `ECHILD`, then publishes readiness.\n- **Optional bounded deadline:** `limit.wall_clock_milliseconds` is either absent or 1–86,400,000 ms. When present, the launcher preflights pidfd/timerfd support and PID 1 arms a one-shot `CLOCK_MONOTONIC` timer after it forks the direct target and closes inherited setup descriptors.\n- **Deterministic timeout race:** each PID1 supervision wake performs `wait4(target, WNOHANG)` first. If target status is already available, natural termination wins. If the timer is readable and the target is not yet waitable, deadline ownership wins from that point forward.\n- **Distinct timeout result:** once deadline ownership wins, PID 1 uses `SIGKILL` to terminate the direct target, but shared lifecycle state marks the event and the host reports `ChildOutcome::TimedOut`.",
    "- **Owned PID-tree lifecycle:** namespace PID 1 supervises the direct target and reaps descendants. After the direct target becomes terminal—naturally, by deadline, or by external cancellation—PID 1 repeatedly kills remaining namespace processes and reaps until `ECHILD`, then publishes readiness.\n- **Optional bounded deadline:** `limit.wall_clock_milliseconds` is either absent or 1–86,400,000 ms. When present, the launcher preflights pidfd/timerfd support and PID 1 arms a one-shot `CLOCK_MONOTONIC` timer after it forks the direct target and closes inherited setup descriptors.\n- **Optional external cancellation:** `CancellationToken` is a cloneable Linux eventfd-backed one-way control token. The launcher pins a duplicate before fork; only PID 1 retains that duplicate while the target runs, and the direct target closes its copy before untrusted execution.\n- **Deterministic supervision race:** each PID1 supervision wake performs `wait4(target, WNOHANG)` first. If target status is already available, natural termination wins. Otherwise cancellation readiness is checked before deadline readiness, yielding natural exit > explicit cancellation > deadline when multiple conditions are simultaneously observable.\n- **Distinct control results:** deadline ownership reports `ChildOutcome::TimedOut`; cancellation ownership reports `ChildOutcome::Cancelled`. Both may use `SIGKILL` after ownership is established, but neither is reported as an ordinary target signal.",
    "threat model cancellation properties",
)
replace_one(
    "THREAT_MODEL.md",
    "## Deadline and lifecycle orchestration",
    "## Deadline, cancellation, and lifecycle orchestration",
    "threat model supervision heading",
)
replace_one(
    "THREAT_MODEL.md",
    "If no deadline is declared, PID 1 uses the existing blocking direct-target wait. If a deadline is declared, PID 1 opens a pidfd for the already-forked target, creates a `TFD_CLOEXEC` timerfd using `CLOCK_MONOTONIC`, arms it for the validated interval, and polls the pidfd and timerfd. These descriptors are created after target fork and are never inherited by the target.",
    "If neither a deadline nor external cancellation is active, PID 1 uses the existing blocking direct-target wait. Otherwise PID 1 opens a pidfd for the already-forked target. A declared deadline adds a `TFD_CLOEXEC` timerfd using `CLOCK_MONOTONIC`; a cancellable run adds the pre-fork pinned eventfd duplicate. PID 1 polls the active supervision descriptors. The direct target closes the cancellation fd before target setup, and pidfd/timerfd are created after target fork, so none of these control descriptors become untrusted target capabilities.",
    "threat model supervision descriptors",
)
replace_one(
    "THREAT_MODEL.md",
    "When poll wakes, PID 1 performs one nonblocking target reap check as the race arbiter. An already-waitable target keeps its natural raw wait status. Otherwise a readable timer transfers ownership to the deadline path; PID 1 sends `SIGKILL`, waits specifically for the direct target, then runs the existing kill/reap loop for every remaining descendant. Shared lifecycle state records raw target status, `timed_out`, descendant reap count, and publishes `ready` last.",
    "When poll wakes, PID 1 performs one nonblocking target reap check as the race arbiter. An already-waitable target keeps its natural raw wait status. Otherwise a readable cancellation eventfd wins before a simultaneously readable timer; failing that, a readable timer transfers ownership to the deadline path. The winning launcher control path sends `SIGKILL`, waits specifically for the direct target, then runs the existing kill/reap loop for every remaining descendant. Shared lifecycle state records raw target status, mutually exclusive `timed_out` / `cancelled` flags, descendant reap count, and publishes `ready` last.",
    "threat model arbitration",
)
replace_one(
    "THREAT_MODEL.md",
    "- an externally-triggered cancellation handle/API. Milestone 3B implements policy-owned deadline expiration only;",
    "- reset/rearm semantics for external cancellation, arbitrary signal forwarding, a general bidirectional control RPC, or an end-to-end cancellation latency guarantee. Milestone 7A is deliberately one-way cancellation only;",
    "threat model cancellation non-goal",
)
replace_one(
    "THREAT_MODEL.md",
    "- A declared deadline intentionally authorizes launcher PID 1 to terminate the direct target and descendants when the timer wins the documented race.",
    "- A declared deadline intentionally authorizes launcher PID 1 to terminate the direct target and descendants when the timer wins the documented race.\n- Supplying a `CancellationToken` to a cancellable run and signalling it intentionally authorizes launcher PID 1 to terminate the direct target and descendants when cancellation wins the documented race. The token is one-way and remains cancelled after it is signalled.",
    "threat model cancellation trust",
)
replace_one(
    "THREAT_MODEL.md",
    "- a raw deadline target that writes an exact stdout marker, forks a descendant that remains in `pause()`, and is preempted by a 1,000 ms policy deadline while a fast target under 5,000 ms still preserves `Exited(42)`.",
    "- a raw deadline target that writes an exact stdout marker, forks a descendant that remains in `pause()`, and is preempted by a 1,000 ms policy deadline while a fast target under 5,000 ms still preserves `Exited(42)`;\n- an external-cancellation target that forks one paused descendant and writes an exact readiness marker through selected fd 9. The parent waits for the full marker before signalling the token, then verifies `Cancelled` plus one reaped descendant; a separate uncancelled-token run preserves natural `Exited(42)`.",
    "threat model cancellation evidence",
)
replace_one(
    "THREAT_MODEL.md",
    "Invalid policy is rejected before launch. Namespace creation, UTS hostname installation, selected-source pin/inspection, selected-target remapping, deadline support preflight, pidfd creation, timer creation/arming, supervision poll, namespace/bootstrap/init forks, descriptor cleanup, capture reads, mount/capability/seccomp setup, process-tree kill/reap, lifecycle publication, and target exec failures are terminal.",
    "Invalid policy is rejected before launch. Namespace creation, UTS hostname installation, selected-source pin/inspection, selected-target remapping, deadline/cancellation supervision preflight, cancellation eventfd pinning/signalling, pidfd creation, timer creation/arming, supervision poll, namespace/bootstrap/init forks, descriptor cleanup, capture reads, mount/capability/seccomp setup, process-tree kill/reap, lifecycle publication, and target exec failures are terminal.",
    "threat model cancellation failure semantics",
)

# Roadmap: seal 6A, describe 7A evidence, and promote beyond cancellation variants.
replace_one(
    "ROADMAP.md",
    "**Current verified candidate.** Add an explicit launch-time object-capability surface without reopening ambient descriptor inheritance.",
    "**Status: complete on `main`.** Adds an explicit launch-time object-capability surface without reopening ambient descriptor inheritance.",
    "roadmap 6A status",
)
replace_one(
    "ROADMAP.md",
    "After 6A integrates, do not farm more descriptor numbers or object types merely to repeat the same remap path. Promote to a different executable boundary such as an external cancellation/control-plane primitive, evidence-backed persistent-volume policy, or controlled networking.\n\n## Later frontiers\n\nExternal asynchronous cancellation, supplementary-group isolation with a viable mapping architecture, broader persistent-volume policy, and controlled networking remain separate evidence-backed frontiers. Do not add configuration-only names without executable kernel behavior and integration evidence.",
    "Milestone 6A is sealed on `main`; do not farm more descriptor numbers or object types merely to repeat the same remap path.\n\n## Milestone 7 — external control plane\n\n### Slice 7A — external cancellation\n\n**Current verified candidate.** Add a caller-owned one-way cancellation primitive that integrates with launcher-owned PID 1 process-tree supervision without exposing the control descriptor to the target.\n\nAcceptance evidence is executable:\n\n- `CancellationToken` is cloneable and backed by `eventfd(EFD_CLOEXEC | EFD_NONBLOCK)` on Linux; signalling is one-way and readiness remains persistent because the launcher never drains the eventfd;\n- `run_report_with_cancel` / `run_with_cancel` add cancellable execution without changing existing `run_report` / `run` behavior;\n- the launcher pins a cancellation duplicate before fork, bootstrap closes it, namespace PID 1 alone retains it for supervision, and the direct target closes its copy before stdio/rlimit/capability/seccomp/exec setup;\n- PID 1 polls target pidfd, optional deadline timerfd, and optional cancellation eventfd with one deterministic arbitration rule: natural target exit > explicit cancellation > deadline;\n- cancellation ownership reports `ChildOutcome::Cancelled`, remains distinct from `TimedOut` and ordinary target signals, then reuses the owned process-tree kill/reap path before lifecycle readiness;\n- a raw target forks one paused descendant, publishes `cancellation-target-ready\\n` through selected fd 9, and pauses. The parent reads the exact marker before signalling cancellation, then observes `Cancelled` and exactly one reaped descendant;\n- a separate uncancelled-token run preserves the fast target's natural `Exited(42)` outcome;\n- stable format/Clippy/full tests and the full Rust 1.74 suite remain green.\n\nBoundary: 7A is one-way cancellation only. It does not provide token reset/rearm, arbitrary signal forwarding, a bidirectional control protocol, or a bound on total latency from public API entry to termination.\n\n### Milestone 7 promotion rule\n\nAfter 7A integrates, do not farm cancellation aliases, signal numbers, or alternate wake primitives that repeat the same ownership path. Promote to a materially different executable boundary such as evidence-backed persistent-volume policy or controlled networking. Milestone 4A remains blocked on real unprivileged cgroup-v2 delegation, and supplementary-group isolation still requires a different user-namespace mapping architecture.\n\n## Later frontiers\n\nSupplementary-group isolation with a viable mapping architecture, broader persistent-volume policy, and controlled networking remain separate evidence-backed frontiers. Do not add configuration-only names without executable kernel behavior and integration evidence.",
    "roadmap 7A promotion",
)
