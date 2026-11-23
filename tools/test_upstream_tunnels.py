#!/usr/bin/env python3
"""Exercise unmodified upstream tunnels on loopback; no Fleet credentials needed.

Reports behavior, including failures, rather than treating configuration removal
as proof of active-stream revocation. Logs/certificates/results stay outside the repo.
This is a transport comparison, not a tenant authorization or NAT acceptance test.
"""
import argparse
import asyncio
import base64
import hashlib
import json
import os
import re
from pathlib import Path
import secrets
import socket
import ssl
import subprocess
import urllib.request


def port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def private(path, text):
    path.write_text(text)
    path.chmod(0o600)


class Case:
    def __init__(self, root, kind, binaries):
        self.root, self.kind, self.binaries = root, kind, binaries
        root.mkdir(mode=0o700)
        self.control, self.admin, self.front = port(), port(), port()
        self.exposed = [port(), port()]
        self.token = secrets.token_hex(32)
        self.children, self.logs, self.servers, self.writers = [], [], [], []
        self.active = set()

    async def app(self, tenant, reader, writer):
        self.active.add(writer)
        try:
            writer.write(f"tenant-{tenant}\n".encode())
            await writer.drain()
            mode = await reader.readline()
            if mode == b"EOF\n":
                digest = hashlib.sha256()
                while chunk := await reader.read(65536):
                    digest.update(chunk)
                writer.write(digest.hexdigest().encode())
                await writer.drain()
            elif mode == b"ECHO\n":
                while chunk := await reader.read(65536):
                    writer.write(chunk)
                    await writer.drain()
        except (ConnectionError, OSError):
            pass
        finally:
            writer.close()
            self.active.discard(writer)

    def config(self, enabled):
        q = json.dumps  # TOML quoted strings; never shell interpolation.
        cert, key, pfx = (str(self.root / n) for n in ("cert.pem", "key.pem", "identity.pfx"))
        if self.kind.startswith("chisel"):
            private(self.root / "users.json", json.dumps({f"test:{self.token}":
                ["^" + re.escape(f"R:127.0.0.1:{self.exposed[i]}") + "$" for i in enabled]}))
            return
        if self.kind.startswith("rathole"):
            transport = "websocket" if self.kind.endswith("wss") else "tcp"
            server = f'[server]\nbind_addr="127.0.0.1:{self.control}"\nheartbeat_interval=1\n'
            client = f'[client]\nremote_addr="127.0.0.1:{self.control}"\nheartbeat_timeout=5\nretry_interval=1\n'
            for side in ("server", "client"):
                extra = f'[{side}.transport]\ntype="{transport}"\n'
                if transport == "websocket":
                    extra += f'[{side}.transport.websocket]\ntls=true\n[{side}.transport.tls]\n'
                    extra += (f'pkcs12={q(pfx)}\npkcs12_password="fixture"\n' if side == "server"
                              else f'trusted_root={q(cert)}\nhostname="localhost"\n')
                if side == "server":
                    server += extra
                else:
                    client += extra
            for i in range(2):
                if i in enabled:
                    server += f'[server.services.route{i}]\ntoken="{self.token}"\nbind_addr="127.0.0.1:{self.exposed[i]}"\n'
                client += f'[client.services.route{i}]\ntoken="{self.token}"\nlocal_addr="127.0.0.1:{self.local[i]}"\n'
        else:
            server = (f'bindAddr="127.0.0.1"\nbindPort={self.control}\nproxyBindAddr="127.0.0.1"\n'
                      f'auth.token="{self.token}"\ntransport.tls.certFile={q(cert)}\ntransport.tls.keyFile={q(key)}\n')
            client = (f'loginFailExit=false\nserverAddr="127.0.0.1"\nserverPort={self.front}\nauth.token="{self.token}"\n'
                      f'transport.protocol="wss"\ntransport.tls.trustedCaFile={q(cert)}\ntransport.tls.serverName="localhost"\n'
                      f'webServer.addr="127.0.0.1"\nwebServer.port={self.admin}\nwebServer.user="test"\nwebServer.password="{self.token}"\n')
            for i in enabled:
                client += (f'[[proxies]]\nname="route{i}"\ntype="tcp"\nlocalIP="127.0.0.1"\n'
                           f'localPort={self.local[i]}\nremotePort={self.exposed[i]}\n')
        private(self.root / "server.toml", server)
        private(self.root / "client.toml", client)

    async def tls_front(self, reader, writer):
        # frps expects plain WebSocket behind a TLS-terminating ingress for WSS.
        # Use stdlib TLS only as an isolated test ingress, not a product proxy.
        self.active.add(writer)
        upstream = None
        tasks = []
        try:
            incoming, upstream = await asyncio.open_connection("127.0.0.1", self.control)
            self.active.add(upstream)
            async def copy(source, target):
                while chunk := await source.read(65536):
                    target.write(chunk)
                    await target.drain()
            tasks = [asyncio.create_task(copy(reader, upstream)), asyncio.create_task(copy(incoming, writer))]
            await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
        except OSError:
            pass
        finally:
            for task in tasks:
                task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
            for connection in (writer, upstream):
                if connection:
                    connection.close()
                    self.active.discard(connection)

    async def spawn(self, binary, cfg, role):
        log = (self.root / f"{role}.log").open("wb")
        self.logs.append(log)
        args = [str(binary), str(cfg)] if self.kind.startswith("rathole") else [str(binary), "-c", str(cfg)]
        if self.kind.startswith("chisel"):
            if role == "server":
                args = [str(binary), "server", "--host", "127.0.0.1", "--port", str(self.control),
                    "--reverse", "--authfile", str(self.root / "users.json"),
                    "--tls-cert", str(self.root / "cert.pem"), "--tls-key", str(self.root / "key.pem")]
            else:
                args = [str(binary), "client", "--tls-ca", str(self.root / "cert.pem"),
                    f"https://127.0.0.1:{self.control}",
                    *[f"R:127.0.0.1:{self.exposed[i]}:127.0.0.1:{self.local[i]}" for i in range(2)]]
        child = await asyncio.create_subprocess_exec(*args, stdout=log, stderr=log,
            env={**os.environ, "RUST_LOG": "info", "AUTH": f"test:{self.token}" if role == "client" else ""})
        self.children.append(child)
        return child

    async def connect(self, i):
        reader, writer = await asyncio.wait_for(asyncio.open_connection("127.0.0.1", self.exposed[i]), 2)
        try:
            assert await asyncio.wait_for(reader.readline(), 2) == f"tenant-{i}\n".encode()
        except BaseException:
            writer.close()
            raise
        self.writers.append(writer)
        return reader, writer

    async def ready(self, i):
        for _ in range(100):
            assert all(p.returncode is None for p in self.children), "upstream process exited; inspect private logs"
            try:
                r, w = await self.connect(i)
                return r, w
            except (OSError, TimeoutError, AssertionError):
                await asyncio.sleep(0.1)
        raise AssertionError("tunnel readiness timeout; inspect private logs")

    async def echo(self, r, w, payload=b"probe"):
        try:
            w.write(payload)
            await w.drain()
            return await asyncio.wait_for(r.readexactly(len(payload)), 2) == payload
        except (OSError, asyncio.IncompleteReadError, TimeoutError):
            return False

    async def run(self):
        for i in range(2):
            self.servers.append(await asyncio.start_server(lambda r,w,i=i: self.app(i,r,w), "127.0.0.1", 0))
        self.local = [s.sockets[0].getsockname()[1] for s in self.servers]
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
            "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1",
            "-keyout", str(self.root / "key.pem"), "-out", str(self.root / "cert.pem")],
            check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(["openssl", "pkcs12", "-export", "-inkey", str(self.root / "key.pem"),
            "-in", str(self.root / "cert.pem"), "-out", str(self.root / "identity.pfx"), "-passout", "pass:fixture"],
            check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if self.kind.startswith("frp"):
            tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            tls.load_cert_chain(self.root / "cert.pem", self.root / "key.pem")
            self.servers.append(await asyncio.start_server(self.tls_front, "127.0.0.1", self.front, ssl=tls))
        self.config([0, 1])
        server = await self.spawn(self.binaries[0], self.root / "server.toml", "server")
        client = await self.spawn(self.binaries[1], self.root / "client.toml", "client")
        streams = [await self.ready(i) for i in range(2)]
        for _, w in streams:
            w.write(b"ECHO\n")
            await w.drain()
        payload = bytes(range(256)) * 2048
        result = {"binary_roundtrip": all([await self.echo(r,w,payload) for r,w in streams])}
        r,w = await self.ready(0)
        w.write(b"EOF\n" + payload)
        await w.drain()
        w.write_eof()
        try:
            result["half_close_response"] = await asyncio.wait_for(r.read(), 3) == hashlib.sha256(payload).hexdigest().encode()
        except (OSError, TimeoutError):
            result["half_close_response"] = False
        w.close()
        self.config([1])
        if self.kind.startswith("frp"):
            def reload():
                req = urllib.request.Request(f"http://127.0.0.1:{self.admin}/api/reload")
                req.add_header("Authorization", "Basic " + base64.b64encode(f"test:{self.token}".encode()).decode())
                with urllib.request.urlopen(req, timeout=5) as response:
                    assert response.status == 200
            await asyncio.to_thread(reload)
        closed = False
        for _ in range(20):
            await asyncio.sleep(0.1)
            try:
                _, w = await self.connect(0)
                w.close()
            except (OSError, TimeoutError, AssertionError):
                closed = True
                break
        result["removed_route_rejects_new_connections"] = closed
        result["removed_route_closes_existing_stream"] = not await self.echo(*streams[0])
        result["other_route_survives_removal"] = await self.echo(*streams[1])
        # A process boundary can force drain, but a shared process also loses
        # unrelated routes. Record that cost rather than calling it isolation.
        client.terminate()
        await asyncio.wait_for(client.wait(), 5)
        result["client_stop_closes_existing_stream"] = not await self.echo(*streams[0])
        result["client_stop_also_closes_other_route"] = not await self.echo(*streams[1])
        server.terminate()
        await asyncio.wait_for(server.wait(), 5)
        return result

    async def close(self):
        for writer in [*self.writers, *self.active]:
            writer.close()
        for server in self.servers:
            server.close()
            await server.wait_closed()
        for child in self.children:
            if child.returncode is None:
                child.kill()
            await child.wait()
        for log in self.logs:
            log.close()


async def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rathole", type=Path)
    parser.add_argument("--frp-dir", type=Path)
    parser.add_argument("--chisel", type=Path)
    parser.add_argument("--case", choices=["rathole-tcp", "rathole-wss", "frp-wss", "chisel-wss"])
    parser.add_argument("--artifacts", type=Path, required=True)
    args = parser.parse_args()
    root = args.artifacts.resolve()
    repo = Path(__file__).resolve().parents[1]
    if root.is_relative_to(repo):
        parser.error("artifacts must be outside the repository")
    root.mkdir(mode=0o700, parents=True, exist_ok=False)
    results = {}
    cases = []
    if args.rathole:
        cases.extend([(kind, (args.rathole, args.rathole)) for kind in ("rathole-tcp", "rathole-wss")])
    if args.frp_dir:
        cases.append(("frp-wss", (args.frp_dir / "frps", args.frp_dir / "frpc")))
    if args.chisel:
        cases.append(("chisel-wss", (args.chisel, args.chisel)))
    if not cases or args.case and not any(kind == args.case for kind, _ in cases):
        parser.error("provide the binaries for at least one selected case")
    manifest = {str(binary): hashlib.sha256(binary.read_bytes()).hexdigest()
        for _, binaries in cases for binary in binaries}
    private(root / "binaries.json", json.dumps(manifest, indent=2) + "\n")
    for kind, binaries in cases:
        if args.case and args.case != kind:
            continue
        case = Case(root / kind, kind, binaries)
        try:
            results[kind] = await case.run()
        finally:
            await case.close()
        print(kind, json.dumps(results[kind]), flush=True)
        private(root / "results.json", json.dumps(results, indent=2) + "\n")


if __name__ == "__main__":
    asyncio.run(main())
