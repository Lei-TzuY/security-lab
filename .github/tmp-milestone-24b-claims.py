from pathlib import Path


def replace_one(path: str, old: str, new: str, label: str) -> None:
    p = Path(path)
    text = p.read_text()
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{label}: expected exactly one match, got {count}")
    p.write_text(text.replace(old, new, 1))


# README: synchronize the already-integrated time-namespace phase and make the
# observability evidence layers explicit.  Do not describe partial preflight as
# proof that the full launch pipeline can succeed.
replace_one(
    "README.md",
    "Milestone 24A added deterministic human and JSON **static policy-authority manifests** that validate policy without launching or probing runtime support. The current Milestone 23A verified candidate adds an optional **policy-owned Linux time namespace for descendants**, with bounded `CLOCK_MONOTONIC` and `CLOCK_BOOTTIME` offsets installed before namespace PID 1 and the target are created.",
    "Milestone 23A added an optional **policy-owned Linux time namespace for descendants**, with bounded `CLOCK_MONOTONIC` and `CLOCK_BOOTTIME` offsets installed before namespace PID 1 and the target are created. Milestone 24A added deterministic human and JSON **static policy-authority manifests** that validate policy without launching or probing runtime support. The current Milestone 24B verified candidate adds a **conservative policy-specific host preflight**: it reports safely observed optional runtime capabilities, but keeps the overall verdict `indeterminate` while mandatory launch prerequisites remain unprobed rather than falsely claiming launch compatibility.",
    "README milestone summary",
)

observability = r'''## Policy observability commands

The CLI intentionally separates four evidence levels rather than treating them as interchangeable:

- `check` / `check-json` perform static policy validation only. They do not probe the host or launch the sandbox.
- `manifest` / `manifest-json` emit the deterministic declared-authority manifest from Milestone 24A. They remain static (`runtime_preflight=false`) and do not prove kernel support.
- `host` / `host-json` report a coarse host capability snapshot independent of any policy. Milestone 24B additionally exposes `eventfd` because the observed stdout-total budget depends on it.
- `preflight` / `preflight-json` match one validated policy against the safely probed host subset without launching or mutating sandbox runtime state. Known unavailable represented requirements produce `incompatible` and exit status 3. Unknown mandatory launch-core prerequisites, or another requested mechanism without a complete safe probe, produce `indeterminate` and exit status 4. The report states `launch_attempted=false` and `launch_preflight_complete=false`. The current implementation deliberately cannot emit `satisfied` from the real probe path because the mandatory namespace/filesystem/FD launch core is not independently proven.
- `run` / `run-json` remain the executable runtime evidence: only an actual successful launch demonstrates that all mandatory setup and enforcement mechanisms worked for that invocation.

A future `satisfied` preflight verdict is reserved for a design that can positively establish every mandatory prerequisite without weakening host policy or converting preflight into a destructive/privileged launch simulation.

'''
replace_one(
    "README.md",
    "## Current sandbox pipeline\n",
    observability + "## Current sandbox pipeline\n",
    "README observability section",
)

# Roadmap: seal the already-integrated 23A state and record 24B as the exact
# conservative executable/tooling candidate that fixes issue #41.
replace_one(
    "ROADMAP.md",
    "**Current verified candidate.** Adds one optional Linux time namespace for subsequently created sandbox descendants without changing host clocks or the launcher's own clock view.",
    "**Status: complete on `main`.** Adds one optional Linux time namespace for subsequently created sandbox descendants without changing host clocks or the launcher's own clock view.",
    "roadmap 23A status",
)

slice_24b = r'''Boundary: this is static observability, not runtime capability preflight or proof of effective kernel state.

### Slice 24B — conservative policy-specific host preflight

**Current verified candidate.** Adds non-destructive policy/host capability matching without claiming that partial probing proves the full sandbox launch path.

Acceptance evidence is executable:

- `preflight` / `preflight-json` validate the policy first, derive requested Landlock ABI plus deadline/stdout-budget/time-namespace requirements, and compare them with the existing host capability snapshot; `eventfd` is now also probed and surfaced because stdout-total enforcement depends on it;
- preflight never launches the target, creates sandbox namespaces, materializes the configured root, or mutates runtime filesystem state; machine and human reports explicitly carry `launch_attempted=false` and `launch_preflight_complete=false`;
- the mandatory launch core is first-class evidence state. The real probe path currently marks it `unprobed` with reason `mandatory_runtime_prerequisites_not_probed`, so green optional probes cannot produce a false-positive `satisfied` verdict;
- known unavailable represented prerequisites produce `incompatible` with exit status 3; any unprobed mandatory prerequisite produces `indeterminate` with exit status 4. Exit status 0 / `satisfied` is reserved for evaluator state where complete mandatory-core evidence is explicitly present, and is unreachable from the current production probe path;
- deterministic evaluator regressions prove Linux/x86_64 plus available Landlock/pidfd/timerfd/eventfd still remains indeterminate when the mandatory core is unknown, while an explicitly unavailable mandatory core is incompatible;
- CLI regressions use a deliberately nonexistent filesystem root and prove `preflight` leaves it absent while reporting the mandatory-core gap, preserving the distinction between static manifest, partial host preflight, and actual `run` evidence;
- stable rustfmt/Clippy/full tests and the full Rust 1.74 suite are green on the exact implementation head.

Boundary: 24B is a conservative partial preflight, not a dry-run, launch simulator, or complete kernel compatibility oracle. It does not independently establish unprivileged user/mount/PID/network/IPC/UTS/time namespace creation, `openat2`/mount API behavior, descriptor sanitization, final filesystem identity, or target enforcement. Those mechanisms remain authoritative only when the real launch path executes successfully.

### Milestone 24 promotion rule

After 24B integrates, seal the current policy-observability layer. Do not farm output aliases or relabel partial probes as conformance. A later preflight slice must add genuinely safe positive evidence for previously unprobed mandatory mechanisms; otherwise promote to a materially different executable authority/enforcement frontier.
'''
replace_one(
    "ROADMAP.md",
    "Boundary: this is static observability, not runtime capability preflight or proof of effective kernel state.\n",
    slice_24b,
    "roadmap 24B section",
)

# Threat model: distinguish static declared authority, partial host capability
# evidence, and actual launch/enforcement evidence.
replace_one(
    "THREAT_MODEL.md",
    "# Milestones 1–22B + 23A candidate threat model",
    "# Milestones 1–23A + Milestone 24B candidate threat model",
    "threat title",
)
replace_one(
    "THREAT_MODEL.md",
    "The current Milestone 23A verified candidate adds a policy-owned child time namespace with bounded monotonic/boottime offsets while leaving the trusted bootstrap and host clocks unchanged. Every claimed property must correspond to a kernel mechanism and executable evidence.",
    "Milestone 23A adds a policy-owned child time namespace with bounded monotonic/boottime offsets while leaving the trusted bootstrap and host clocks unchanged. Milestone 24A adds a static declared-authority manifest, and the current Milestone 24B verified candidate adds conservative policy-specific host preflight that remains explicitly incomplete until mandatory launch prerequisites are positively established. Every claimed property must correspond to a kernel mechanism and executable evidence.",
    "threat purpose observability",
)

preflight_property = r'''- **Conservative policy-specific host preflight:** `preflight` / `preflight-json` validate policy and compare only independently safe host observations such as target build support, Landlock ABI, pidfd, timerfd, and eventfd against requested features. They do not launch or materialize sandbox state. The report explicitly marks the mandatory namespace/filesystem/descriptor launch core `unprobed`; therefore current production preflight can report known incompatibility or indeterminate evidence but cannot claim full satisfaction. Static `manifest` output, partial preflight, and actual runtime enforcement are separate evidence classes.
'''
replace_one(
    "THREAT_MODEL.md",
    "- **Optional policy-owned descendant time namespace:** when the paired offsets are declared, the bootstrap adds `CLONE_NEWTIME`, writes `monotonic` and `boottime` offsets to `/proc/self/timens_offsets` after user-namespace mapping and before the first descendant is created, then forks PID 1/target into that prepared child time namespace. Policy bounds each nonnegative offset to 365 days and rejects an all-zero pair.\n",
    "- **Optional policy-owned descendant time namespace:** when the paired offsets are declared, the bootstrap adds `CLONE_NEWTIME`, writes `monotonic` and `boottime` offsets to `/proc/self/timens_offsets` after user-namespace mapping and before the first descendant is created, then forks PID 1/target into that prepared child time namespace. Policy bounds each nonnegative offset to 365 days and rejects an all-zero pair.\n" + preflight_property,
    "threat preflight property",
)
replace_one(
    "THREAT_MODEL.md",
    "Milestones through 22B are complete on `main`; the bounded persistent-volume, namespace/network brokers, Landlock pathname/network/IPC/device envelopes, richer seccomp predicates, supplementary-group closure, resource observability, and observed-output enforcement phases are sealed. Milestone 24A static authority-manifest tooling is also complete on `main` and remains explicitly distinct from runtime preflight. The current Milestone 23A verified candidate adds one bounded descendant time-namespace model. After 23A integrates, seal this clock-offset slice rather than farming more clock IDs or offset spellings. Milestone 4A cgroup-v2 aggregate process accounting remains blocked by missing unprivileged delegation; future promotion must target a materially different executable authority, enforcement, runtime-preflight, or observability frontier.",
    "Milestones through 23A are complete on `main`; the bounded persistent-volume, namespace/network brokers, Landlock pathname/network/IPC/device envelopes, richer seccomp predicates, supplementary-group closure, resource observability, observed-output enforcement, and bounded descendant time-namespace phases are sealed. Milestone 24A static authority-manifest tooling is also complete on `main`. The current Milestone 24B verified candidate adds conservative partial runtime-capability preflight while explicitly refusing to claim full launch compatibility from unprobed mandatory mechanisms. After 24B integrates, seal this observability layer rather than farming command/output aliases. Milestone 4A cgroup-v2 aggregate process accounting remains blocked by missing unprivileged delegation; future promotion must target a materially different executable authority/enforcement frontier or add genuinely safe positive evidence for a previously unprobed mandatory runtime prerequisite.",
    "threat phase promotion",
)
