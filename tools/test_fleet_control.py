#!/usr/bin/env python3
"""Real Fleet + relay + outbound connector acceptance, without a prover.

Build both repositories first. All generated state/credentials live in a private
temporary directory, and every child process is stopped on success or failure.
"""
import argparse
import copy
import hashlib
import http.client
import http.server
import json
from pathlib import Path
import secrets
import socket
import subprocess
import tempfile
import threading
import time
import urllib.error
import urllib.request
import os


def port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def request(url, token=None, method="GET", body=None, headers=None):
    headers = dict(headers or {})
    if token:
        headers["Authorization"] = "Bearer " + token
    if body is not None:
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=None if body is None else json.dumps(body).encode(), headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=4) as response:
            raw = response.read()
            try:
                body = json.loads(raw) if raw else None
            except json.JSONDecodeError:
                body = raw.decode()
            return response.status, body
    except urllib.error.HTTPError as error:
        return error.code, None


def eventually(check, seconds=12):
    until = time.monotonic() + seconds
    while time.monotonic() < until:
        try:
            if check():
                return
        except (OSError, urllib.error.URLError):
            pass
        time.sleep(0.1)
    raise AssertionError("acceptance condition timed out")


class App(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.end_headers()
        try:
            while True:
                self.wfile.write(b"data: test\n\n")
                self.wfile.flush()
                time.sleep(0.05)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def log_message(self, *_):
        pass


def acceptance(fleet_binary, router_binary, root):
    children, logs = [], []
    app = http.server.ThreadingHTTPServer(("127.0.0.1", 0), App)
    threading.Thread(target=app.serve_forever, daemon=True).start()

    def write(name, value):
        path = root / name
        path.write_text(value)
        path.chmod(0o600)
        return path

    def launch(name, args, env=None):
        log = (root / (name + ".log")).open("ab")
        logs.append(log)
        process = subprocess.Popen(args, env=env, stdout=log, stderr=subprocess.STDOUT)
        children.append(process)
        return process

    def stop(process):
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()

    try:
        ports = set()
        while len(ports) < 3:
            ports.add(port())
        fp, cp, rp = ports
        fleet = f"http://127.0.0.1:{fp}"
        relay = f"http://127.0.0.1:{rp}"
        cluster = write("cluster.token", secrets.token_hex(48))
        config = write("fleet.yaml", f"control_addr: 127.0.0.1:{cp}\nhttp_addr: 127.0.0.1:{fp}\ndata_dir: {root}/fleet\ncluster_token_file: {cluster}\n")
        fleet_process = launch("fleet", [fleet_binary, "--config", str(config)])
        eventually(lambda: (root / "fleet/admin.token").exists() and request(fleet + "/healthz")[0] == 200)
        admin = (root / "fleet/admin.token").read_text().strip()
        status, namespace = request(fleet + "/namespaces", admin, "POST", {"name": "router-test"})
        assert status == 201
        namespace = namespace["id"]
        token = secrets.token_hex(48)
        token_id = secrets.token_hex(16)
        assert request(fleet + "/tokens", admin, "POST", {"id": token_id, "address": secrets.token_hex(20),
            "namespace": "router-test", "permissions": ["router_sync"], "token_hash": hashlib.sha256(token.encode()).hexdigest()})[0] == 201
        assert request(fleet + "/routers/relay-a", admin, "PUT", {"issuer": "gateway", "token_id": token_id})[0] == 201
        token_file = write("router.token", token)
        private, public = root / "key.pem", root / "public.pem"
        subprocess.run(["openssl", "genpkey", "-algorithm", "ED25519", "-out", str(private)], check=True, capture_output=True)
        private.chmod(0o600)
        subprocess.run(["openssl", "pkey", "-in", str(private), "-pubout", "-out", str(public)], check=True, capture_output=True)
        public.chmod(0o644)
        env = os.environ.copy()
        env.update(TRUSTED_ROUTER_FLEET_URL=fleet, TRUSTED_ROUTER_ID="relay-a", TRUSTED_ROUTER_TOKEN_FILE=str(token_file))
        relay_args = [router_binary, "relay", f"127.0.0.1:{rp}", str(root / "routes.db"), str(public), "gateway"]
        relay_process = launch("relay", relay_args, env)
        eventually(lambda: request(fleet + "/routers/relay-a", admin)[1]["applied_revision"] == 0)

        grant = {"iss": "gateway", "aud": "trusted-data-router/v1", "sub": "test", "nbf": int(time.time()), "exp": int(time.time()) + 180,
            "purpose": "register", "http_request": None,
            "execution": {"namespace": namespace, "workload": "app", "allocation_id": "one", "lease_id": "first", "generation": 1, "node_id": "nat-node"},
            "service": {"namespace": namespace, "workload": "app", "service": "http"},
            "policy": {"issuer": "gateway", "policy_id": "network", "version": 1, "sha256": "ab" * 32}}

        def signed(claims, purpose):
            claims = dict(claims, purpose=purpose)
            if purpose == "register":
                claims.pop("access", None)
            return subprocess.run([router_binary, "sign", str(private)], input=json.dumps(claims), text=True, capture_output=True, check=True).stdout.strip()

        def events(route, access):
            req = urllib.request.Request(relay + "/v1/http/" + route + "/events", headers={"X-Trusted-Access": access})
            stream = urllib.request.urlopen(req, timeout=40)
            assert stream.readline().startswith(b"data:")
            return stream

        def connect(claims):
            route = hashlib.sha256(json.dumps([claims["iss"], claims["execution"], claims["service"]], separators=(",", ":")).encode()).hexdigest()
            registration = write("register-" + str(claims["execution"]["generation"]), signed(claims, "register"))
            access = signed(claims, "access")
            launch("edge", [router_binary, "connect", f"ws://127.0.0.1:{rp}/v1/connect/{route}", f"127.0.0.1:{app.server_port}", str(registration)])
            eventually(lambda: request(relay + "/v1/ready/" + route, access)[0] == 204)
            return route, access, events(route, access)

        route, access, stream = connect(grant)
        assert request(fleet + f"/routers/relay-a/routes/{route}", admin, "DELETE")[0] == 200
        eventually(lambda: request(fleet + "/routers/relay-a", admin)[1]["applied_revision"] == 1)

        def closed(stream, seconds):
            until = time.monotonic() + seconds
            try:
                while time.monotonic() < until:
                    if not stream.readline():
                        return
            except (http.client.IncompleteRead, ConnectionResetError):
                return
            finally:
                stream.close()
            raise AssertionError("stream remained open after revocation/lease expiry")

        closed(stream, 2)
        stop(relay_process)
        # Restart with persisted cursor/tombstones; a missing config must fail,
        # not silently downgrade to static grants.
        legacy_env = {k: v for k, v in os.environ.items() if not k.startswith("TRUSTED_ROUTER_")}
        accidental = launch("missing-control", relay_args, legacy_env)
        assert accidental.wait(timeout=3) != 0
        launch("relay", relay_args, env)
        next_grant = copy.deepcopy(grant)
        next_grant["execution"].update(generation=2, lease_id="second")
        backend = secrets.token_hex(48)
        assert request(fleet + "/tokens", admin, "POST", {"id": secrets.token_hex(16), "address": secrets.token_hex(20),
            "namespace": namespace, "permissions": ["read", "router_delegate"], "token_hash": hashlib.sha256(backend.encode()).hexdigest()})[0] == 201
        policy = dict(namespace=namespace, workload="app", service="http", version=1, sha256="ab" * 32, enabled=True)
        assert request(fleet + "/routers/relay-a/access-policy", admin, "PUT", policy)[0] == 200
        identity = dict(namespace=namespace, workload="app", service="http", principal="11" * 32, session="aa" * 32)
        status, binding = request(fleet + "/routers/relay-a/authorize", backend, "POST", identity)
        assert status == 200
        next_grant.update(sub=binding["principal"], access=binding)
        next_route, _, stream = connect(next_grant)
        assert request(relay + "/v1/ready/" + route, access)[0] != 204
        second = copy.deepcopy(next_grant)
        second["access"]["session"] = "bb" * 32
        second_stream = events(next_route, signed(second, "access"))
        assert request(fleet + "/routers/relay-a/revoke-subject", backend, "POST",
            {"namespace": namespace, "principal": identity["principal"], "session": identity["session"]})[0] == 200
        eventually(lambda: request(fleet + "/routers/relay-a", admin)[1]["applied_authorization_revision"] == 2)
        closed(stream, 2)
        assert second_stream.readline()  # another session on the same connector continues
        third = copy.deepcopy(second)
        third["sub"] = third["access"]["principal"] = "22" * 32
        third_stream = events(next_route, signed(third, "access"))
        status, compacted = request(fleet + "/routers/relay-a/revoke-subject", backend, "POST",
            {"namespace": namespace, "principal": identity["principal"], "session": None})
        assert status == 200 and len(compacted["revoked_subjects"]) == 1
        eventually(lambda: request(fleet + "/routers/relay-a", admin)[1]["applied_authorization_revision"] == 3)
        closed(second_stream, 2)
        assert third_stream.readline()  # another principal retains access
        for denied in (next_grant, second):
            assert request(relay + "/v1/ready/" + next_route, signed(denied, "access"))[0] == 403
        policy.update(version=2, sha256="cd" * 32)
        assert request(fleet + "/routers/relay-a/access-policy", admin, "PUT", policy)[0] == 200
        eventually(lambda: request(fleet + "/routers/relay-a", admin)[1]["applied_authorization_revision"] == 4)
        closed(third_stream, 2)
        third["access"].update(policy_version=2, policy_sha256=policy["sha256"])
        stream = events(next_route, signed(third, "access"))  # same runtime/connector, new approved policy
        stop(fleet_process)
        closed(stream, 33)
        print("PASS: real Fleet sync, applied ACK, route/session revocation and safe compaction, policy upgrade without runtime replacement, durable restart, downgrade refusal, control outage expiry")
    finally:
        for process in reversed(children):
            stop(process)
        app.shutdown()
        app.server_close()
        for log in logs:
            log.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fleet-binary", required=True)
    parser.add_argument("--router-binary", required=True)
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="router-fleet-test-") as directory:
        acceptance(str(Path(args.fleet_binary).resolve()), str(Path(args.router_binary).resolve()), Path(directory))
