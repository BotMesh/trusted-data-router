#!/usr/bin/env python3
"""Exercise the real gateway and relay against an isolated private-CA Fleet fixture."""
import argparse
import http.server
import json
import os
from pathlib import Path
import socket
import ssl
import subprocess
import tempfile
import threading
import time
import urllib.error
import urllib.request


def port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def eventually(check):
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        try:
            if check():
                return
        except (OSError, urllib.error.URLError):
            pass
        time.sleep(.1)
    raise AssertionError("private CA acceptance timed out")


def acceptance(binary, root):
    children, logs, acknowledgments, requests = [], [], [], []
    execution = dict(namespace="film", workload="comfy", allocation_id="a", lease_id="l", generation=1, node_id="edge")

    class Fleet(http.server.BaseHTTPRequestHandler):
        def respond(self, body):
            data = json.dumps(body).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def do_GET(self):
            requests.append(self.path)
            if self.path != "/apps/comfy?namespace=film" or self.headers.get("Authorization") != "Bearer delegate":
                self.send_error(403)
                return
            self.respond(dict(name="comfy", namespace="film", disabled=False,
                runtime_instances=[dict(execution=execution, ready=True, services=["http"])]))

        def do_POST(self):
            if self.path != "/routers/relay/sync" or self.headers.get("Authorization") != "Bearer sync":
                self.send_error(403)
                return
            request = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            acknowledgments.append(request.get("applied_revision"))
            self.respond(dict(router_id="relay", issuer="test", epoch="ab" * 16,
                from_revision=0, revision=0, revoked_routes=[], lease_seconds=30))

        def log_message(self, *_):
            pass

    def write(name, contents):
        path = root / name
        path.write_text(contents)
        path.chmod(0o600)
        return path

    def openssl(*args):
        subprocess.run(["openssl", *map(str, args)], check=True, capture_output=True)

    ca, ca_key, cert, key = [root / name for name in ("ca.pem", "ca.key", "server.pem", "server.key")]
    openssl("req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1", "-subj", "/CN=Test CA",
        "-addext", "basicConstraints=critical,CA:TRUE", "-keyout", ca_key, "-out", ca)
    openssl("req", "-new", "-newkey", "rsa:2048", "-nodes", "-subj", "/CN=127.0.0.1",
        "-keyout", key, "-out", root / "server.csr")
    extensions = write("extensions", "subjectAltName=IP:127.0.0.1\nbasicConstraints=CA:FALSE\nextendedKeyUsage=serverAuth\n")
    openssl("x509", "-req", "-in", root / "server.csr", "-CA", ca, "-CAkey", ca_key, "-CAcreateserial",
        "-days", "1", "-extfile", extensions, "-out", cert)
    signing, public = root / "signing.key", root / "signing.pub"
    openssl("genpkey", "-algorithm", "ED25519", "-out", signing)
    signing.chmod(0o600)
    openssl("pkey", "-in", signing, "-pubout", "-out", public)
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Fleet)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert, key)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    fleet = f"https://127.0.0.1:{server.server_port}"
    env = {k: v for k, v in os.environ.items() if not k.startswith(("TRUSTED_GATEWAY_", "TRUSTED_ROUTER_"))}
    env["NO_PROXY"] = env["no_proxy"] = "127.0.0.1,localhost"
    env.update(TRUSTED_GATEWAY_FLEET_URL=fleet, TRUSTED_GATEWAY_RELAY_URL="https://relay.example/",
        TRUSTED_GATEWAY_ISSUER="test", TRUSTED_GATEWAY_SIGNING_KEY_FILE=str(signing),
        TRUSTED_GATEWAY_PUBLIC_KEY_FILE=str(public), TRUSTED_GATEWAY_FLEET_TOKEN_FILE=str(write("reader", "delegate")))

    def launch(name, args, settings):
        log = (root / (name + ".log")).open("wb")
        logs.append(log)
        child = subprocess.Popen([binary, *args], env=settings, stdout=log, stderr=log)
        children.append(child)

    def connection(address):
        request = urllib.request.Request(address + "/v1/runtime/connections",
            data=json.dumps({"service": {"namespace": "film", "workload": "comfy", "service": "http"}}).encode(),
            headers={"Authorization": "Bearer delegate", "Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(request, timeout=3) as response:
                body = json.load(response)
                assert body[0]["execution"] == execution
                return response.status
        except urllib.error.HTTPError as error:
            return error.code

    try:
        for name, trusted in [("untrusted", False), ("trusted", True)]:
            address = f"127.0.0.1:{port()}"
            settings = dict(env)
            if trusted:
                settings["TRUSTED_GATEWAY_CA_FILE"] = str(ca)
            launch(name, ["gateway", address], settings)
            statuses = []
            def check():
                statuses.append(connection("http://" + address))
                return statuses[-1] == (200 if trusted else 503)
            try:
                eventually(check)
            except AssertionError:
                raise AssertionError(f"{name} gateway statuses={set(statuses)}, fixture paths={set(requests)}") from None
        settings = dict(env, TRUSTED_ROUTER_FLEET_URL=fleet, TRUSTED_ROUTER_ID="relay",
            TRUSTED_ROUTER_TOKEN_FILE=str(write("sync", "sync")), TRUSTED_ROUTER_FLEET_CA_FILE=str(ca))
        launch("relay", ["relay", f"127.0.0.1:{port()}", str(root / "routes.db"), str(public), "test"], settings)
        eventually(lambda: 0 in acknowledgments)
        print("PASS: untrusted Fleet TLS denied; configured CA enables gateway discovery and durable relay ACK")
    finally:
        for child in reversed(children):
            child.terminate()
            try:
                child.wait(timeout=5)
            except subprocess.TimeoutExpired:
                child.kill()
                child.wait()
        server.shutdown()
        server.server_close()
        thread.join()
        for log in logs:
            log.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--router-binary", type=Path, required=True)
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="router-private-ca-") as directory:
        acceptance(str(args.router_binary.resolve()), Path(directory))
