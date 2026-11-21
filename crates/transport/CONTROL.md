# Central connection gateway

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
