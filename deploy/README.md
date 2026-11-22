# Independent relay deployment

Run this Compose project on a dedicated public relay host, independently of Fleet,
ClawUp, Film and OpenShell. Only this host needs inbound TCP/443. Runtime nodes
connect outward using WSS; Fleet synchronization uses a separate outbound HTTPS
connection. One active relay owns each router ID and SQLite database.

The image workflow builds on pull requests and publishes
`ghcr.io/attestx/trusted-data-router:sha-<full-commit>` on main/manual runs, plus
version tags on `v*` tags. Select a published digest for deployment. The image
includes all CLI modes; this Compose runs only `relay`.

1. Copy `.env.example` to a private file outside the repository. Set the image,
   Fleet HTTPS origin, enrolled router ID, grant issuer and absolute directories.
2. Create the config/state/TLS directories, owned by the configured UID/GID
   (default `10001:10001`), mode `0700`. Place `grant-public.pem` (mode `0644`, never group/world-writable) and a `0600`
   `router-sync.token` in the config directory. The token must have only
   `router_sync`; enroll it as described in the
   [control protocol](../crates/transport/CONTROL.md#fleet-control-synchronization).
   For a private Fleet CA, add `fleet-ca.pem` and set the documented CA path.
3. Put the public relay certificate chain in `fullchain.pem` and its private key
   in `key.pem` under the TLS directory. Both must be readable by the configured
   UID; the key must be `0600`. Grant-signing private keys stay in the application
   gateway. Do not place them on the relay.
4. Validate and start from this repository:

```sh
docker compose --env-file /private/router.env -f deploy/docker-compose.yml config --quiet
docker compose --env-file /private/router.env -f deploy/docker-compose.yml up -d --wait
curl --fail https://router.example/healthz
```

`/healthz` reports process liveness only. Confirm a fresh Fleet control lease and
applied policy revisions with Fleet's router status, then test an authorized
service route before migrating traffic. Managed routes reject access until sync
succeeds, and fail closed when the control lease expires. Application API keys and
ownership checks remain in ClawUp/Film. No proving runs on this host.

TLS proxy buffering is disabled for HTTP/SSE; WebSocket upgrades and tunnel
traffic share the same TLS endpoint. Configure exact browser origins when needed.
The plaintext relay port is neither published nor bound to a non-loopback address.
The two containers run without capabilities or a Docker socket, with read-only
root filesystems. Only the relay can write its state directory.

For upgrades, update the pinned image and run `up -d --wait` for the **whole
project**, so Compose recreates the proxy when the relay network namespace changes.
Existing streams disconnect and clients reconnect; requests are never replayed.
Renew TLS files atomically and run `docker compose ... exec tls nginx -s reload`.
Back up SQLite using its backup API, or stop the project before copying the entire
state directory. Preserve router identity, cursor, revocations and Fleet's database
together; never reset relay state to revive older grants. See the control protocol
for rollback/epoch reconciliation. This deployment does not provide relay HA.
