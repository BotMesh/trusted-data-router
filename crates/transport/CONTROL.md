# Central connection gateway

## Fleet control synchronization

Fleet owns the relay's revocation stream. Set all three variables on the relay
to enable managed mode (existing static deployments remain opt-in):

```sh
export TRUSTED_ROUTER_FLEET_URL=https://fleet.example/
export TRUSTED_ROUTER_ID=relay-a
export TRUSTED_ROUTER_TOKEN_FILE=/private/router-sync.token
```

The token file must be absolute, private (0600), bounded and regular. Issue a
namespace token with the **exclusive** `router_sync` permission, no tag or app
grants; enroll its token ID and the relay's existing JWT issuer with an
administrator request to `PUT /routers/relay-a`:

```json
{"issuer":"gateway-issuer","token_id":"<Fleet token ID>"}
```

This credential cannot read apps, create workloads, mint grants or change router
state. Only the enrolled token ID can poll this router. Rotate it by enrolling a
replacement token in the same namespace, then atomically replacing its file;
the epoch and all revocations survive rotation. Never place an administrator or
cluster token on the relay.

The relay initiates `POST /routers/relay-a/sync` every five seconds. HTTPS is
required except for numeric loopback test endpoints. Redirects are refused;
requests time out after ten seconds and responses are bounded to 512 KiB.
The initial request has `epoch:null`, `after_revision:0`, `applied_revision:null`.
Fleet returns the epoch, full revocation snapshot, revision and a 30-second
control lease. Subsequent requests carry the persisted epoch and cursor; Fleet
returns only the contiguous suffix. These protobuf-owned wire records live in
`zkm-fleet/crates/fleet-proto/proto/fleet/model/v1/model.proto`.

The relay commits tombstones and cursor together in SQLite, then cancels affected
sessions before advertising that revision as applied in the next request. This
acknowledges local enforcement; it is not a cryptographic policy proof or a
guarantee that previously delivered application bytes can be retracted.
`GET /routers/relay-a` (administrator only) reports `delivered_revision`,
`applied_revision` and `applied_ms`; a submitted revocation is not an applied one.

An administrator revokes an exact execution/service route with
`DELETE /routers/relay-a/routes/<route_id>`. This operation is idempotent and
permanent. Healthy convergence is normally within one poll interval plus network
latency. A disconnected relay closes active HTTP, SSE, WebSocket and TCP sessions
at lease expiry (100 ms watchdog cadence) and rejects new connections. The lease
uses monotonic time measured from request start. A restart needs a fresh sync;
removing the environment variables cannot downgrade a persisted managed relay.
Wrong epochs, backwards/gapped revisions and mismatched authority are rejected.
An explicit HTTP 401/403/404/409 suspends access immediately.

Keep Fleet's PostgreSQL database and the relay's SQLite state durable. A restored
control database behind a relay's cursor or a changed epoch causes fail-closed
behavior and needs operator reconciliation; the relay never resets itself to an
older snapshot. One active relay process owns each router ID and SQLite database.
The initial implementation caps permanent tombstones at 4096 per router and
returns 507 on further new revocations; it never discards existing tombstones.
Until compaction/pagination is implemented, operators must provision a new router
identity with a new grant issuer/key before capacity is reached, withdraw the old
router and reissue grants, or revoke the sync token to suspend the whole router.
Never reset state while reusing the old issuer: that would revive old grants.
Tokens, epochs, issuer and control endpoint are not silently reset.

This first stream synchronizes exact-route revocations and freshness. Policy
versions, grant signing-key rotation, end-user/session revocation and automatic
app lifecycle-to-route revocation are not yet synchronized. A route revocation
affects every client of that execution/service; business backends still check
user/project ownership before issuing access. This is not complete end-user
tenant isolation.

Run the actual cross-repository acceptance after building both binaries:

```sh
python3 tools/test_fleet_control.py \
  --fleet-binary /absolute/path/fleet-scheduler \
  --router-binary /absolute/path/trusted-data-router
```

It starts an isolated Fleet scheduler, relay, outbound edge connector and SSE
service, checks revocation/ACK/restart/control outage, and cleans up its private
temporary state. It never starts a prover or contacts a configured production
Fleet. Fleet's PostgreSQL tests separately cover migration, concurrent writes
and restart durability.

## Grant issuance

`Gateway::router()` embeds in the application backend; `trusted-data-router gateway 127.0.0.1:8098` provides the same control API behind a TLS proxy. The relay is independently deployed. Neither this API nor Fleet carries application bytes.

Use existing process environment:

- `TRUSTED_GATEWAY_FLEET_URL`: HTTPS Fleet scheduler root.
- `TRUSTED_GATEWAY_RELAY_URL`: HTTPS independent relay root.
- `TRUSTED_GATEWAY_ISSUER`: deployment-specific issuer shared with relay and shim.
- `TRUSTED_GATEWAY_SIGNING_KEY_FILE`, `TRUSTED_GATEWAY_PUBLIC_KEY_FILE`: Ed25519 PEM keys; private key absolute and mode 0600.
- `TRUSTED_GATEWAY_FLEET_TOKEN_FILE`: absolute, private, read-only Fleet credential covering the enrolled runtime namespaces, used only for node registration validation.

The Fleet server must expose `runtime_instances` (ProjectZKM/zkm-fleet #98). Every issuance queries Fleet afresh and fails closed if Fleet is unavailable. Registration requires a separate node bootstrap JWT. Application access uses the caller's Fleet token, so Fleet enforces namespace/tag/app grants. Backend applications can call `Gateway::connections` with their own Fleet credential **after checking user ownership of the selected workload**.

POST `/v1/runtime/connections` with `Authorization: Bearer <Fleet token>`:

```json
{"service":{"namespace":"<namespace-id>","workload":"comfy","service":"http"}}
```

Returns one descriptor per current ready execution: execution identity, service, opaque `route_id`, HTTPS `base_url`, access `token`, and `expires_at`. Use `X-Trusted-Access: <token>` on the relay. Preserve the application's native Authorization header. Tokens expire after 15 minutes; refresh before a new request. Refresh with the same `execution` or `route_id` to preserve stateful affinity. An expired/removed instance returns 503; it is never redirected to a replacement. An active stream ends at grant expiry; do not replay state-changing requests automatically.

POST `/v1/runtime/registration` accepts the shim's execution and service declaration. The node JWT must match that exact node and namespace, and Fleet must still report that exact execution/service as ready. A route grant cannot be used as a node credential. Node bootstrap JWTs have audience `trusted-runtime-node/v1`, issuer matching the gateway, `sub` equal to the Fleet node identity, an explicit `namespaces` list, `nbf` and `exp` (maximum 30 days). Enroll with `trusted-data-router enroll-node PRIVATE_KEY` and the claims on stdin; store stdout atomically in a node-only mode-0600 file. Operators verify the node through their existing Fleet onboarding process. This enrollment does not assert TEE attestation. Rotate bootstrap credentials before expiry.

Set `TRUSTED_ROUTER_ORIGINS=https://studio.example,https://clawup.example` on the relay to permit browser fetch/SSE. Only configured origins receive CORS headers. No cookies, wildcard origins or query-string tokens are used. Native WebSocket clients can supply the access header or use a loopback forwarder; browser WebSocket authentication needs a separate connection-ticket flow and is not provided by this API.

The `fleet-service-access/v1` policy reference identifies the route ACL. It is **not** an action-policy proof. OpenShell enforcement, trusted-rail policy receipts, remote TEE attestation, and their activation gates remain separate concerns. Existing tokens are bounded bearer capabilities: Fleet scope revocation prevents renewal, while runtime deletion closes connectors immediately; otherwise existing grants can remain valid until expiry (15 minutes). Use the relay revoke operation for immediate revocation of a known execution.

The reserved service name `control` is restricted to Fleet administrator credentials (checked with `/access` on every issuance). An ordinary namespace reader cannot receive its grant. Shim ingress/management services additionally verify the exact signed execution on the node. The relay overwrites `X-Trusted-Route` with the capability it has validated; it never forwards a client-supplied value as authority. A configured shim ingress can inject a native application's credential locally and expose only declared methods and paths.


An application can bind an access grant to one HTTP invocation using
`http_request: {id, method, path, body_sha256}` in its connection request. `id`
is 32 random bytes encoded as lowercase hex; the digest covers the exact body
bytes sent by the client. The relay rejects other methods, paths, query strings,
WebSocket upgrades and raw TCP tunnels for these grants. A manifest-selected shim
HTTP ingress must verify the body digest and durably consume the invocation ID
before dispatch; this transport claim alone does not provide replay protection
on an arbitrary raw app endpoint. Roll out compatible relay and shim binaries
before issuing bound grants. This capability is not a policy-evaluation proof.
