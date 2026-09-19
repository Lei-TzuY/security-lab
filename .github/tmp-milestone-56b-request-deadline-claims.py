from pathlib import Path

def replace_one(path: str, old: str, new: str, label: str) -> None:
    p = Path(path)
    text = p.read_text()
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{label}: expected exactly one match, got {count}")
    p.write_text(text.replace(old, new, 1))

# README: mark integrated 56A and describe only the verified controller-side request wait.
replace_one(
    "README.md",
    "The current Milestone 56A verified candidate adds a **bounded one-shot runtime request/response channel**: one private `AF_UNIX/SOCK_SEQPACKET` endpoint is transferred after readiness, preserving one target request packet and one trusted-controller response packet under independent byte ceilings.",
    "Milestone 56A added a **bounded one-shot runtime request/response channel**: one private `AF_UNIX/SOCK_SEQPACKET` endpoint is transferred after readiness, preserving one target request packet and one trusted-controller response packet under independent byte ceilings. The current Milestone 56B verified candidate adds a **launcher-owned bounded request wait**: the trusted controller can bound only the wait for that first request with a monotonic timer without widening target syscall authority.",
    "README milestone summary",
)
replace_one(
    "README.md",
    "This is one bounded round trip with kernel-preserved message boundaries, not a general RPC loop, streaming protocol, authentication layer, replay protocol, or deadline facility.",
    "`receive_request_with_deadline(wait_milliseconds)` optionally bounds the trusted controller's wait for that one request from 1 ms through 24 hours. The timer starts when that method is called, uses launcher-side `CLOCK_MONOTONIC` timerfd state across `EINTR`, and treats request/peer readiness as winning over a simultaneously readable timer before `recvmsg` decides packet-versus-peer-shutdown semantics. Expiration returns typed `RuntimeRequestTimedOut` and terminally closes the controller. Invalid deadline bounds are rejected without consuming an otherwise-awaiting exchange. This is still one bounded round trip with kernel-preserved message boundaries; the request-wait bound is not an endpoint-grant-to-request deadline, target process wall-clock deadline, response deadline, general RPC loop, streaming protocol, authentication layer, or replay protocol.",
    "README deadline semantics",
)

# Threat model: synchronize the same bounded claim and preserve non-goals.
replace_one(
    "THREAT_MODEL.md",
    "The current Milestone 56A verified candidate adds one bounded one-shot bidirectional runtime message exchange over a private `SOCK_SEQPACKET` pair, with independent request/response ceilings and terminal protocol state.",
    "Milestone 56A added one bounded one-shot bidirectional runtime message exchange over a private `SOCK_SEQPACKET` pair, with independent request/response ceilings and terminal protocol state. The current Milestone 56B verified candidate additionally lets the trusted controller bound only its wait for the first request with launcher-owned monotonic timer state.",
    "threat purpose",
)
replace_one(
    "THREAT_MODEL.md",
    "one bounded receive-only revocable byte-stream endpoint, or one bounded one-shot request/response message endpoint over that stream,",
    "one bounded receive-only revocable byte-stream endpoint, or one bounded one-shot request/response message endpoint with an optional bounded controller-side first-request wait,",
    "threat protected boundary",
)
replace_one(
    "THREAT_MODEL.md",
    "- **Bounded one-shot runtime request/response:** a trusted caller may prepare one private `AF_UNIX/SOCK_SEQPACKET` pair with independent 1-byte–64-KiB request and response ceilings. The existing readiness-gated broker transfers only the target endpoint. The trusted controller accepts one non-empty packet, rejects truncation/over-budget input, then permits one non-empty budget-checked response packet. Invalid protocol state or I/O failure is terminal, and one successful response completes the only round. Kernel packet boundaries are preserved, but no authentication, replay identity, multiplexing, or multi-round session is claimed. Target `recvmsg`/`sendmsg` authority remains explicit in seccomp policy.",
    "- **Bounded one-shot runtime request/response:** a trusted caller may prepare one private `AF_UNIX/SOCK_SEQPACKET` pair with independent 1-byte–64-KiB request and response ceilings. The existing readiness-gated broker transfers only the target endpoint. The trusted controller accepts one non-empty packet, rejects truncation/over-budget input, then permits one non-empty budget-checked response packet. Invalid protocol state or I/O failure is terminal, and one successful response completes the only round. `receive_request_with_deadline()` may additionally bound only the controller's blocking first-request wait from 1 ms through 24 hours using `CLOCK_MONOTONIC` timerfd plus `poll`; `EINTR` does not restart the timer, request/peer readiness wins over simultaneous timer readiness, and expiration returns typed `RuntimeRequestTimedOut` while terminally closing the controller. The timer begins at method invocation, not endpoint grant. Kernel packet boundaries are preserved, but no endpoint-grant-to-request bound, response deadline, authentication, replay identity, multiplexing, or multi-round session is claimed. Target `recvmsg`/`sendmsg` authority remains explicit in seccomp policy.",
    "threat request wait property",
)
replace_one(
    "THREAT_MODEL.md",
    "Milestone 56A adds exactly one bounded request packet followed by one bounded response packet and does not generalize that into multi-round RPC;",
    "Milestone 56A adds exactly one bounded request packet followed by one bounded response packet, and Milestone 56B bounds only the trusted controller's wait after `receive_request_with_deadline()` is called; neither provides an endpoint-grant-to-request deadline, response deadline, or multi-round RPC;",
    "threat request wait non-goal",
)

# Roadmap: seal 56A and promote the independently executable 56B lifecycle property.
replace_one(
    "ROADMAP.md",
    "**Current verified candidate.** Adds a materially different message-oriented runtime protocol property rather than extending the 55A byte stream.",
    "**Status: complete on `main`.** Adds a materially different message-oriented runtime protocol property rather than extending the 55A byte stream.",
    "roadmap 56A status",
)
replace_one(
    "ROADMAP.md",
    "Boundary: 56A is one bounded target-to-host request followed by one bounded host-to-target response. It does not provide multiple rounds, multiplexing, streaming, message authentication, replay/ordering identifiers beyond the single kernel packet boundary, request cancellation, per-exchange deadlines, peer attestation, or a general long-lived RPC/control protocol.\n\n### Milestone 56 promotion rule\n\nAfter 56A integrates, do not farm packet sizes, extra message tags, or equivalent one-round wrappers. Promote only to a distinct runtime-capability lifecycle/protocol property with new executable evidence, or move to a different architectural frontier.",
    "Boundary: 56A is one bounded target-to-host request followed by one bounded host-to-target response. It does not provide multiple rounds, multiplexing, streaming, message authentication, replay/ordering identifiers beyond the single kernel packet boundary, request cancellation, request-wait deadlines, peer attestation, or a general long-lived RPC/control protocol.\n\n### Slice 56B — launcher-owned bounded request wait\n\n**Current verified candidate.** Adds a lifecycle bound to the 56A controller without changing target syscall authority or turning the one-round exchange into a general RPC protocol.\n\nAcceptance evidence is executable:\n\n- `RuntimeMessageExchangeController::receive_request_with_deadline(wait_milliseconds)` accepts an explicit 1–86,400,000 ms bound while the existing `receive_request()` blocking semantics remain unchanged; zero or larger values fail as `InvalidConfiguration` without consuming an otherwise-awaiting exchange;\n- each bounded call creates and arms a launcher-owned `timerfd(CLOCK_MONOTONIC, TFD_CLOEXEC|TFD_NONBLOCK)`; the deadline therefore continues across interrupted `poll` calls instead of restarting after `EINTR`;\n- the controller polls only its private request socket and timer. When request/peer readiness and timer readiness are observed in the same poll cycle, socket readiness is handled first and the existing bounded `recvmsg` path remains the packet-versus-peer-shutdown arbiter;\n- an expired wait returns typed `RuntimeRequestTimedOut { wait_milliseconds }`, transitions the controller terminally to failed state, and later request/response attempts are rejected rather than reviving an ambiguous exchange; mandatory timer creation/arming/poll failure also fails closed, with `ENOSYS` reported as unsupported rather than falling back to an unbounded requested wait;\n- deterministic local regressions prove a 1 ms no-request timeout is terminal, invalid wait bounds do not consume protocol state, and a request already queued before a 1 ms bounded receive wins the documented request-first arbitration and completes normally;\n- the real raw-syscall sandbox request/response oracle now receives `runtime-request\\n` through the 1,000 ms bounded API and returns the exact response while retaining the existing explicit target `recvmsg`/`sendmsg` policy;\n- exact candidate stable format/Clippy/full tests and the full Rust 1.74 suite are green.\n\nBoundary: 56B bounds only the trusted controller's blocking wait beginning when `receive_request_with_deadline()` is invoked. It is not an endpoint-grant-to-request or end-to-end API deadline, does not terminate the sandbox process tree, does not bound response computation/delivery, and does not add multiple rounds, multiplexing, authentication, cancellation, or peer attestation.\n\n### Milestone 56 promotion rule\n\nAfter 56B integrates, seal this bounded one-round message-protocol phase. Do not farm deadline units, timeout values, packet sizes, message tags, or equivalent one-round wrappers. Further runtime-protocol work must add a materially different capability lifecycle or authority property with executable evidence; otherwise promote to another architectural frontier.",
    "roadmap 56B section",
)
