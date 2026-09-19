from pathlib import Path

def replace_one(path: str, old: str, new: str, label: str) -> None:
    p = Path(path)
    text = p.read_text()
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{label}: expected exactly one match, got {count}")
    p.write_text(text.replace(old, new, 1))

# README: seal 58A and describe only the verified response-publication bound.
replace_one(
    "README.md",
    "Milestone 56B added a **launcher-owned bounded request wait**: the trusted controller can bound the wait for an awaiting request with a monotonic timer without widening target syscall authority. The current Milestone 58A verified candidate adds a **bounded multi-round runtime message controller** over that same granted endpoint: 2–32 strictly ordered request/response rounds remain individually byte-bounded, and any ambiguous protocol/I/O/timeout failure closes the whole controller.",
    "Milestone 56B added a **launcher-owned bounded request wait**: the trusted controller can bound the wait for an awaiting request with a monotonic timer without widening target syscall authority. Milestone 58A added a **bounded multi-round runtime message controller** over that same granted endpoint: 2–32 strictly ordered request/response rounds remain individually byte-bounded, and any ambiguous protocol/I/O/timeout failure closes the whole controller. The current Milestone 59A verified candidate adds a **launcher-owned bounded response-publication wait** so a trusted controller cannot block forever when the peer stops draining the SOCK_SEQPACKET receive queue.",
    "README milestone summary",
)

replace_one(
    "README.md",
    "This is bounded sequential multi-round messaging, not multiplexing, concurrent in-flight requests, request IDs, out-of-order responses, authentication, replay protection, an endpoint-grant deadline, or a response deadline.",
    "This is bounded sequential multi-round messaging, not multiplexing, concurrent in-flight requests, request IDs, out-of-order responses, authentication, replay protection, or an endpoint-grant deadline. `send_response_with_deadline(bytes, wait_milliseconds)` is the separate 59A liveness bound: it accepts 1–86,400,000 ms, arms launcher/controller-owned `CLOCK_MONOTONIC` timerfd state, polls the private response socket for writability, and uses atomic `MSG_DONTWAIT|MSG_NOSIGNAL` send as the final readiness-race arbiter. Socket writability is tried before a simultaneously readable timer; `EAGAIN` is not accepted as publication and the deadline remains live. Expiration returns typed `RuntimeResponseTimedOut` and terminally closes the exchange. The multi-round wrapper advances the completed-round count only after successful publication. This bound ends when the whole response packet is accepted into the peer socket's kernel receive queue; it does **not** prove that the target read, processed, acknowledged, or acted on that response, and it is not a whole-session deadline.",
    "README response publication semantics",
)

# Threat model: synchronize current phase and exact publication semantics.
replace_one(
    "THREAT_MODEL.md",
    "Milestone 56A added one bounded one-shot bidirectional runtime message exchange over a private `SOCK_SEQPACKET` pair, with independent request/response ceilings and terminal protocol state. The current Milestone 56B verified candidate additionally lets the trusted controller bound only its wait for the first request with launcher-owned monotonic timer state.",
    "Milestone 56A added one bounded one-shot bidirectional runtime message exchange over a private `SOCK_SEQPACKET` pair, with independent request/response ceilings and terminal protocol state. Milestone 56B added launcher-owned monotonic request-wait bounds, and Milestone 58A added an explicitly bounded 2–32-round sequential controller over the same granted endpoint. The current Milestone 59A verified candidate additionally bounds trusted-controller response publication under real socket backpressure without claiming peer consumption or acknowledgment.",
    "threat purpose runtime summary",
)

replace_one(
    "THREAT_MODEL.md",
    "one bounded one-shot or 2–32-round request/response message endpoint with an optional bounded controller-side request wait",
    "one bounded one-shot or 2–32-round request/response message endpoint with optional bounded controller-side request and response-publication waits",
    "threat protected boundary",
)

replace_one(
    "THREAT_MODEL.md",
    "- **Bounded multi-round runtime request/response:** a separate controller reuses the same private SOCK_SEQPACKET endpoint and readiness-gated grant but requires an explicit 2–32 round ceiling. Every round preserves the existing independent 1-byte–64-KiB request/response bounds and strict request-before-response state; only a successful response advances the completed-round count and reopens the next request state. The final successful response completes the controller. Truncation, empty/oversized input, invalid response, I/O failure, or a bounded request-wait timeout is terminal for the entire session. This statically bounds payload opportunity by the configured per-message ceilings and round count while preserving packet boundaries. It does not provide multiplexing, concurrent in-flight requests, request identifiers, out-of-order completion, endpoint-grant or response deadlines, authentication, replay protection, or a general unbounded RPC transport. Target syscall authority remains explicit.",
    "- **Bounded multi-round runtime request/response:** a separate controller reuses the same private SOCK_SEQPACKET endpoint and readiness-gated grant but requires an explicit 2–32 round ceiling. Every round preserves the existing independent 1-byte–64-KiB request/response bounds and strict request-before-response state; only a successful response advances the completed-round count and reopens the next request state. The final successful response completes the controller. Truncation, empty/oversized input, invalid response, I/O failure, or a bounded request-wait timeout is terminal for the entire session. This statically bounds payload opportunity by the configured per-message ceilings and round count while preserving packet boundaries.\n- **Bounded response publication:** after a valid request, `send_response_with_deadline()` may bound only the trusted controller's wait for the complete response packet to be accepted into the peer SOCK_SEQPACKET kernel receive queue from 1 ms through 24 hours. The controller uses `CLOCK_MONOTONIC` timerfd plus `poll`, attempts socket writability before a simultaneously readable timer, and uses `MSG_DONTWAIT|MSG_NOSIGNAL` send as the final atomic readiness-race arbiter. `EAGAIN` does not count as success. Expiration returns typed `RuntimeResponseTimedOut` and makes the exchange terminal; a multi-round wrapper advances only after successful publication. This does not attest that the target read, processed, acknowledged, or acted on the response and does not create an endpoint-grant, application-response, or whole-session deadline. Target syscall authority remains unchanged.",
    "threat response publication property",
)

replace_one(
    "THREAT_MODEL.md",
    "Milestones 56A–56B retain the one-round API, while 58A adds only a bounded 2–32-round sequential controller over the same endpoint; these surfaces still provide no endpoint-grant-to-request deadline, response deadline, multiplexing, concurrent in-flight requests, authentication, replay protection, or unbounded/general RPC;",
    "Milestones 56A–56B retain the one-round API, while 58A adds only a bounded 2–32-round sequential controller over the same endpoint and 59A bounds only kernel-queue response publication; these surfaces still provide no endpoint-grant-to-request deadline, proof of target response consumption/processing/acknowledgment, whole-session deadline, multiplexing, concurrent in-flight requests, authentication, replay protection, or unbounded/general RPC;",
    "threat runtime non-goal",
)

# Roadmap: seal 58A and promote the distinct response-backpressure liveness property.
replace_one(
    "ROADMAP.md",
    "**Current verified candidate.** Promotes the one-round request/response mechanism into a bounded sequential session without changing the existing target endpoint-grant authority.",
    "**Status: complete on `main`.** Promotes the one-round request/response mechanism into a bounded sequential session without changing the existing target endpoint-grant authority.",
    "roadmap 58A status",
)

replace_one(
    "ROADMAP.md",
    "After 58A integrates, seal simple sequential round-count expansion. Do not farm larger round caps, per-round aliases, message tags, or timeout wrappers. A further runtime-protocol phase must add a materially different property such as explicit correlation/multiplexing, end-to-end session lifetime ownership, authenticated peer/application semantics, or another independent authority frontier with executable evidence.\n\n## Later frontiers\n",
    """58A is sealed on `main`. Do not farm larger round caps, per-round aliases, message tags, or request-timeout wrappers. Further runtime work must close a distinct lifecycle/authority gap with executable evidence rather than repackage the same state machine.

## Milestone 59 — bounded response publication liveness

### Slice 59A — launcher-owned bounded response-publication wait

**Current verified candidate.** Closes the trusted controller's distinct blocking-send liveness gap under real peer receive-queue backpressure without changing target syscall authority or claiming target consumption.

Acceptance evidence is executable:

- `send_response_with_deadline(bytes, wait_milliseconds)` is separate from the existing blocking `send_response()`; valid waits are 1–86,400,000 ms, while invalid bounds return `InvalidConfiguration` without consuming the already-received request state;
- each bounded send creates launcher/controller-owned `timerfd(CLOCK_MONOTONIC, TFD_CLOEXEC|TFD_NONBLOCK)` state and polls the private response socket plus timer, so `EINTR` does not restart the deadline;
- socket readiness is attempted before a simultaneously readable timer, but the final arbiter is an atomic `send(..., MSG_NOSIGNAL|MSG_DONTWAIT)`; `EAGAIN` is never treated as publication success and the loop retains the original timer state;
- exact full-packet send completes the one-round controller; expiration returns typed `RuntimeResponseTimedOut { wait_milliseconds }`, and timer/poll/send ambiguity fails closed;
- the multi-round wrapper exposes the same bounded publication operation and increments `completed_rounds` / reopens `AwaitingRequest` only after successful publication, so timeout cannot revive the session into another round;
- deterministic broker integration performs the real readiness handshake and SCM_RIGHTS endpoint transfer, repeatedly sends one-byte requests while deliberately never draining maximum-size responses, and observes actual SOCK_SEQPACKET backpressure produce the typed publication timeout before the 32-round ceiling; the poisoned controller rejects later use;
- a separate regression proves zero and above-maximum response wait bounds leave a valid received request usable, after which a 1,000 ms bounded publication succeeds and the peer reads exact response bytes;
- exact candidate stable format/Clippy/full tests and the complete Rust 1.74 suite are green.

Boundary: 59A bounds only the trusted controller's wait until the complete response packet is accepted into the peer socket's kernel receive queue. It does not prove target read, processing, acknowledgment, or application progress; it does not add an endpoint-grant-to-request deadline, target-side response deadline, whole-session lifetime bound, multiplexing, authentication, replay protection, or general RPC semantics.

### Milestone 59 promotion rule

After 59A integrates, simple per-operation request/response wait bounds are sealed. Do not farm timeout values, deadline units, or duplicate send wrappers. Promote only to a materially different property such as one monotonic whole-session lifetime budget spanning multiple rounds, explicit correlation/multiplexing, authenticated application semantics, or another independent authority frontier.

## Later frontiers
""",
    "roadmap 59 section",
)
