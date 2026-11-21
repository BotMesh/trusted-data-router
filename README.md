# trusted-data-router

An application-independent data plane for ClawUp, Film and Fleet apps. This PR
contains Rust interfaces only. It has no runnable router, tunnel or authorization
implementation. Review these boundaries before adding adapters.

## Ownership and dependencies

```text
ClawUp / Film clients -> data router -> reverse tunnel -> local service
                                        ^
                         connector dials outward from the node

Fleet -> local Ray / fleet-node -> trusted-shim -> runtime + connector
Central gateway -> policy versions, access grants and cumulative authorization
```

Business payloads do not pass through ClawUp backend, OpenShell gateway or Fleet
heartbeats. Native upstream control connections remain control traffic. Fleet
owns scheduling; shim owns local execution; this project owns service access.

The small `trusted-contracts` crate hosts shared execution, policy and service
identities without a network or rule-engine dependency. It lives here to avoid a
fourth repository and circular dependencies:

```text
trusted-contracts <- router
trusted-contracts <- rail
router + rail + trusted-contracts <- shim
```

Router depends on the `Authorizer` interface, not on a particular rule engine or
ClawUp. The application's composition layer can supply a rail-backed authorizer.
All records are proposed v0.1 interfaces, not a frozen public wire protocol.

## Interfaces under review

- `ExecutionIdentity`: namespace, workload, allocation, lease, generation, node.
  Generations must come from durable authoritative state; Fleet ordinary app
  deployments still need this binding. An access expiry does not release resources.
- `ServiceSpec`: logical service plus an opaque endpoint resolved by a runtime
  adapter. ClawUp maps bots to workloads; Film maps model servers and workers.
- `Authorizer`: independently verifies service registration and user access.
- `RouteDirectory`: publication, exact-instance affinity, generation fencing and
  compare-before-withdraw. Removing a route must not erase its generation fence.
- `Connector`: node-initiated publication and revocation, including active streams.

Permit records are returned only by trusted implementations. Public Rust structs
do not authenticate themselves. Signature algorithms, canonical encodings, key
rotation, time limits and wire version negotiation are follow-up implementation.

## Reuse and integration plan

Prefer [Pingora](https://github.com/cloudflare/pingora) for HTTP proxying. Evaluate
[rathole](https://github.com/rathole-org/rathole) as a Rust tunnel adapter; retain
[frp](https://github.com/fatedier/frp) as an alternative. Do not implement a new
multiplexing, reconnect or cryptographic protocol for language uniformity.

Rathole 0.5.0's TCP data path spawns established forwarding tasks separately from
the listener shutdown path. Config removal alone must therefore NOT be assumed to
close active streams. Adapter selection requires an explicit revocation test;
process isolation or another supported transport may be necessary. No upstream
fork is proposed here.

Extend existing ClawUp `bot_runtimes.json` and Fleet app specs. Backend-specific
transport configuration may be generated as private runtime state, not maintained
as a second user-authored runtime catalog.

First acceptance slice: ClawUp chat and Film Qwen/vLLM over the same data plane,
using outbound-only edge connections. Test HTTP streaming and WebSocket, tenant
isolation, grant expiry, active revocation, reconnect and stale-instance rejection.
These tests have not run: this PR supplies no concrete transport. Next, ComfyUI
needs instance affinity. Film's staged files and shared-directory Blender queue
need separate artifact/worker adapters; a tunnel does not migrate storage.

TEE endpoint identity and end-to-end confidentiality are separate requirements.
TLS terminating at the relay does not hide plaintext from that relay. QUIC is an
optional future optimization; the baseline must work without outbound UDP.

## Checks

```sh
cargo fmt --all -- --check
cargo clippy --locked --workspace --all-targets -- -D warnings
cargo test --locked --workspace
```

Further implementation is intentionally deferred until framework review.
