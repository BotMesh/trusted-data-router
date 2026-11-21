# trusted-data-router

An application-independent Rust data plane for ClawUp, Film and Fleet apps.
The runnable relay and edge connector reuse Tungstenite/rustls for WebSocket/TLS,
Yamux for multiplexing and backpressure, Hyper for streaming HTTP and upgrades,
jsonwebtoken/ring for Ed25519 capabilities, and SQLite for durable revocation.

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

## Interfaces

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
do not authenticate themselves. The concrete v1 transport uses purpose-separated
Ed25519 JWTs with exact execution, service, policy, issuer, audience and validity.
Only the central application gateway owns the signing key. A node gets a
registration capability, and an authorized client gets an access capability.
Neither capability can revoke a route or mint another capability. Credentials
never appear in routing URLs, process arguments or application headers.

## Running the data plane

Build with `cargo build --locked --release -p trusted-router-transport`. Run the relay
with a private, persistent state directory:

```sh
trusted-data-router relay 127.0.0.1:7800 /private/router/routes.db /keys/gateway-public.pem gateway-issuer
```

Put a **dedicated TLS reverse proxy** in front of this loopback listener, on TCP
443. Forward `/v1/` without buffering, allow WebSocket upgrades and sufficiently
long read timeouts. TLS must cover both clients and nodes; the relay intentionally
refuses a non-loopback plaintext listener. No changes to the backend or Fleet's
heartbeat proxy are needed. Relay and TLS proxy see plaintext application data;
this is not TEE end-to-end confidentiality. This version serves one relay with a
durable local database; an HA route directory and signing-key overlap are future
work. Never run concurrent relay processes against the same database.

The application's authenticated control gateway uses `grants::sign` after checking
the principal's ownership and the current Fleet allocation. It must issue the
**complete** `ExecutionIdentity`, a matching `ServiceId`, approved `PolicyRef`,
`iss`, `aud: trusted-data-router/v1`, `sub`, `nbf`, `exp` and a purpose of `register`,
`access` or `revoke`. Maximum lifetime is one hour. `route_id()` addresses the
exact execution; clients never silently fail over to another lease/replica.
The CLI's `sign PRIVATE_KEY_PEM` reads this bounded JSON from stdin and writes a
JWT to stdout for deployment tooling. Signing is a control-plane operation, not
a public unauthenticated token endpoint.

The node's trusted runtime adapter resolves the service to a **numeric loopback**
address. Its connector dials outward only:

```sh
trusted-data-router connect wss://relay.example/v1/connect/ROUTE_ID 127.0.0.1:18789 /private/registration.jwt
```

Grant files must be private regular files (0600). Replace the registration file
atomically before expiry; reconnect rereads it. Connection loss closes in-flight
streams; reconnect uses bounded exponential backoff and never replays a request.
The caller must supervise the connector for the allocation's lifetime. Stop it
and revoke its route before releasing/reusing the runtime's local endpoint.

HTTP/SSE/WebSocket clients can use `/v1/http/ROUTE_ID/<original-path>` and send
`X-Trusted-Access: ACCESS_JWT`; the relay strips that header and preserves the
application's own Authorization header. Native clients that cannot set this
header can use the local forwarder, which preserves all application bytes:

```sh
trusted-data-router forward wss://relay.example/v1/tunnel/ROUTE_ID 127.0.0.1:17889 /private/access.jwt
```

The local forwarder's single access token is fixed for its lifetime; supervise it
with a fresh token when expired. The relay closes established streams at access
expiry, registration expiry, connector disconnect and revocation. HTTP/1 and WS
upgrades are supported by the HTTP endpoint. The raw tunnel can carry other TCP
protocols, including HTTP/2; it does not open arbitrary destinations on the node.
No inbound port is required on the edge node. Plain `ws://` is accepted only for
numeric loopback integration tests.

To revoke, `DELETE /v1/revoke/ROUTE_ID` with a purpose=`revoke` bearer capability.
Revocation is permanent for that exact execution and survives restart. Generation
fences also survive restart and removal; a newer node-local allocation generation
closes its predecessor. Cross-node replacement must revoke the old exact route
explicitly: node-local generations are not a global scheduling authority.
Access requires the same policy revision as the live registration. A routing
capability proves authorization by its issuer, **not** policy evaluation or TEE
attestation; those proofs and OpenShell enforcement belong in rail/shim.

## Reuse and integration plan

The transport directly composes established Rust protocols/libraries. It defines
no custom multiplexing or cryptographic protocol. The initial framework also
evaluated [rathole](https://github.com/rathole-org/rathole) and Pingora.

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
The real-socket test covers HTTP, SSE, raw-tunnel and direct HTTP WebSocket upgrades,
tenant/lease isolation, purpose separation, access expiry, active revocation,
reconnect and persisted revocation. Next, ComfyUI
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

The local test creates ephemeral Ed25519 keys with `openssl`; no production
credentials, remote cluster or local prover is used.

The optional [central connection gateway](crates/transport/CONTROL.md) embeds in an application's backend and issues grants only after checking Fleet's live runtime discovery and caller scope. It uses the same transport crate; no second runtime catalog is introduced.

Before dispatching a one-shot HTTP mutation, clients can check
`GET /v1/ready/{route_id}` with `Authorization: Bearer <access token>`.
The relay returns 204 only while the exact route is connected. This check sends
no application bytes and does not consume a request-bound grant. Fleet health
and relay registration can become ready at different times after a restart.
`Gateway::ready` exposes this check to embedding applications. Availability can
still change after the check; never automatically replay an ambiguous mutation.
