from pathlib import Path

def replace_one(path: str, old: str, new: str, label: str) -> None:
    p = Path(path)
    text = p.read_text()
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{label}: expected exactly one match, got {count}")
    p.write_text(text.replace(old, new, 1))

# README: seal 56B and describe only the verified broker/controller multi-round capability.
replace_one(
    "README.md",
    "Milestone 56A added a **bounded one-shot runtime request/response channel**: one private `AF_UNIX/SOCK_SEQPACKET` endpoint is transferred after readiness, preserving one target request packet and one trusted-controller response packet under independent byte ceilings. The current Milestone 56B verified candidate adds a **launcher-owned bounded request wait**: the trusted controller can bound only the wait for that first request with a monotonic timer without widening target syscall authority.",
    "Milestone 56A added a **bounded one-shot runtime request/response channel**: one private `AF_UNIX/SOCK_SEQPACKET` endpoint is transferred after readiness, preserving one target request packet and one trusted-controller response packet under independent byte ceilings. Milestone 56B added a **launcher-owned bounded request wait**: the trusted controller can bound the wait for an awaiting request with a monotonic timer without widening target syscall authority. The current Milestone 58A verified candidate adds a **bounded multi-round runtime message controller** over that same granted endpoint: 2–32 strictly ordered request/response rounds remain individually byte-bounded, and any ambiguous protocol/I/O/timeout failure closes the whole controller.",
    "README milestone summary",
)

replace_one(
    "README.md",
    "This is still one bounded round trip with kernel-preserved message boundaries; the request-wait bound is not an endpoint-grant-to-request deadline, target process wall-clock deadline, response deadline, general RPC loop, streaming protocol, authentication layer, or replay protocol.",
    "This one-shot API remains one bounded round trip with kernel-preserved message boundaries; the request-wait bound is not an endpoint-grant-to-request deadline, target process wall-clock deadline, response deadline, streaming protocol, authentication layer, or replay protocol. `prepare_runtime_multi_message_exchange(max_request_bytes, max_response_bytes, max_rounds)` is the separate 58A lifecycle extension: `max_rounds` is restricted to 2–32, each request/response retains the existing 1-byte–64-KiB ceiling and optional per-receive monotonic deadline, and the controller reopens `AwaitingRequest` only after a successful response while rounds remain. The same readiness-gated `PreparedRuntimeMessageChannel`/SCM_RIGHTS grant path is reused unchanged. Local broker integration evidence transfers the real endpoint and completes two exact ordered rounds; second-round oversize or timeout failures poison the session. This is bounded sequential multi-round messaging, not multiplexing, concurrent in-flight requests, request IDs, out-of-order responses, authentication, replay protection, an endpoint-grant deadline, or a response deadline.",
    "README runtime protocol details",
)

# Threat model: update modeled runtime authority and add the new bounded lifecycle claim.
replace_one(
    "THREAT_MODEL.md",
    "one bounded one-shot request/response message endpoint with an optional bounded controller-side first-request wait",
    "one bounded one-shot or 2–32-round request/response message endpoint with an optional bounded controller-side request wait",
    "threat protected boundary",
)

replace_one(
    "THREAT_MODEL.md",
    "- **Bounded one-shot runtime request/response:** a trusted caller may prepare one private `AF_UNIX/SOCK_SEQPACKET` pair with independent 1-byte–64-KiB request and response ceilings. The existing readiness-gated broker transfers only the target endpoint. The trusted controller accepts one non-empty packet, rejects truncation/over-budget input, then permits one non-empty budget-checked response packet. Invalid protocol state or I/O failure is terminal, and one successful response completes the only round. `receive_request_with_deadline()` may additionally bound only the controller's blocking first-request wait from 1 ms through 24 hours using `CLOCK_MONOTONIC` timerfd plus `poll`; `EINTR` does not restart the timer, request/peer readiness wins over simultaneous timer readiness, and expiration returns typed `RuntimeRequestTimedOut` while terminally closing the controller. The timer begins at method invocation, not endpoint grant. Kernel packet boundaries are preserved, but no endpoint-grant-to-request bound, response deadline, authentication, replay identity, multiplexing, or multi-round session is claimed. Target `recvmsg`/`sendmsg` authority remains explicit in seccomp policy.",
    "- **Bounded one-shot runtime request/response:** a trusted caller may prepare one private `AF_UNIX/SOCK_SEQPACKET` pair with independent 1-byte–64-KiB request and response ceilings. The existing readiness-gated broker transfers only the target endpoint. The trusted controller accepts one non-empty packet, rejects truncation/over-budget input, then permits one non-empty budget-checked response packet. Invalid protocol state or I/O failure is terminal, and one successful response completes the only round. `receive_request_with_deadline()` may additionally bound the controller's blocking wait for the currently awaited request from 1 ms through 24 hours using `CLOCK_MONOTONIC` timerfd plus `poll`; `EINTR` does not restart the timer, request/peer readiness wins over simultaneous timer readiness, and expiration returns typed `RuntimeRequestTimedOut` while terminally closing the controller. The timer begins at method invocation, not endpoint grant.\n- **Bounded multi-round runtime request/response:** a separate controller reuses the same private SOCK_SEQPACKET endpoint and readiness-gated grant but requires an explicit 2–32 round ceiling. Every round preserves the existing independent 1-byte–64-KiB request/response bounds and strict request-before-response state; only a successful response advances the completed-round count and reopens the next request state. The final successful response completes the controller. Truncation, empty/oversized input, invalid response, I/O failure, or a bounded request-wait timeout is terminal for the entire session. This statically bounds payload opportunity by the configured per-message ceilings and round count while preserving packet boundaries. It does not provide multiplexing, concurrent in-flight requests, request identifiers, out-of-order completion, endpoint-grant or response deadlines, authentication, replay protection, or a general unbounded RPC transport. Target syscall authority remains explicit.",
    "threat runtime properties",
)

replace_one(
    "THREAT_MODEL.md",
    "Milestone 56A adds exactly one bounded request packet followed by one bounded response packet, and Milestone 56B bounds only the trusted controller's wait after `receive_request_with_deadline()` is called; neither provides an endpoint-grant-to-request deadline, response deadline, or multi-round RPC;",
    "Milestones 56A–56B retain the one-round API, while 58A adds only a bounded 2–32-round sequential controller over the same endpoint; these surfaces still provide no endpoint-grant-to-request deadline, response deadline, multiplexing, concurrent in-flight requests, authentication, replay protection, or unbounded/general RPC;",
    "threat runtime non-goal",
)

# Roadmap: seal 56B on main and promote the materially different multi-round lifecycle.
replace_one(
    "ROADMAP.md",
    "**Current verified candidate.** Adds a lifecycle bound to the 56A controller without changing target syscall authority or turning the one-round exchange into a general RPC protocol.",
    "**Status: complete on `main`.** Adds a lifecycle bound to the 56A controller without changing target syscall authority or turning the one-round exchange into a general RPC protocol.",
    "roadmap 56B status",
)

replace_one(
    "ROADMAP.md",
    "### Milestone 56 promotion rule\n\nAfter 56B integrates, seal this bounded one-round message-protocol phase. Do not farm deadline units, timeout values, packet sizes, message tags, or equivalent one-round wrappers. Further runtime-protocol work must add a materially different capability lifecycle or authority property with executable evidence; otherwise promote to another architectural frontier.\n\n## Later frontiers\n",
    """### Milestone 56 promotion rule

56A–56B are sealed on `main`. Do not farm deadline units, timeout values, packet sizes, message tags, or equivalent one-round wrappers. Further runtime-protocol work must add a materially different capability lifecycle or authority property with executable evidence; otherwise promote to another architectural frontier.

## Milestone 58 — bounded multi-round runtime message lifecycle

### Slice 58A — bounded sequential multi-round exchange

**Current verified candidate.** Promotes the one-round request/response mechanism into a bounded sequential session without changing the existing target endpoint-grant authority.

Acceptance evidence is executable:

- `prepare_runtime_multi_message_exchange(max_request_bytes, max_response_bytes, max_rounds)` reuses the existing private `AF_UNIX/SOCK_SEQPACKET|SOCK_CLOEXEC` endpoint and requires `max_rounds` from 2 through 32; each request and response independently retains the existing 1-byte–64-KiB ceiling;
- the new controller wraps the proven one-round receive/timer/send primitives rather than duplicating packet parsing. A successful response increments `completed_rounds`; only when more configured rounds remain does it transition back to `AwaitingRequest`, while the final response leaves the underlying controller complete;
- `receive_request_with_deadline()` remains available on every awaiting round with the existing 1–86,400,000 ms `CLOCK_MONOTONIC` timerfd semantics and request/peer-readiness-before-timer arbitration;
- any empty/truncated/oversized request, invalid/oversized response, I/O ambiguity, or request-wait timeout leaves the underlying controller terminally failed. The wrapper never resets a failed controller into a later round;
- broker-level integration evidence performs the real readiness handshake and `SCM_RIGHTS` transfer of the prepared endpoint, then completes two exact ordered request/response packets and rejects any third round at the configured limit;
- deterministic regressions reject round counts outside 2–32, prove a second-round oversized request poisons the whole session after one completed round, and prove a second-round timeout is likewise terminal;
- exact candidate stable format/Clippy/full tests and the complete Rust 1.74 suite are green.

Boundary: 58A is a bounded **sequential** message lifecycle over one already-granted endpoint. It does not add a new sandbox grant path, multiplexing, concurrent in-flight requests, request IDs, out-of-order responses, authentication, replay protection, an endpoint-grant-to-request deadline, a response deadline, or an unbounded/general RPC transport. The executable multi-round evidence is at the broker/controller integration layer; existing full sandbox regressions remain green, but this slice does not claim a new dedicated multi-round raw-target oracle.

### Milestone 58 promotion rule

After 58A integrates, seal simple sequential round-count expansion. Do not farm larger round caps, per-round aliases, message tags, or timeout wrappers. A further runtime-protocol phase must add a materially different property such as explicit correlation/multiplexing, end-to-end session lifetime ownership, authenticated peer/application semantics, or another independent authority frontier with executable evidence.

## Later frontiers
""",
    "roadmap 58 section",
)
