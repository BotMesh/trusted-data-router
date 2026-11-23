#!/usr/bin/env python3
"""Real TLS/WSS acceptance behind isolated stateful NATs (Linux, sudo, aiohttp, OpenSSH, rsync).

Two HTTP tenants and an SSH node each sit behind their own NAT; a separate
SSH client behind a fourth NAT reaches that node only through the Router's
access tunnel, using unmodified ssh/rsync with host-key verification.

Only test-owned network namespaces are changed. No host routes, firewall rules,
listeners, production credentials or proof services are used. Generated keys and
logs belong in an external private artifact directory. This models two networks
on one host; physical remote-machine validation remains separate.
"""
import argparse
import asyncio
from contextlib import suppress
import hashlib
import json
import os
from pathlib import Path
import secrets
import ssl
import subprocess
import sys
import tempfile
import time

import aiohttp
from aiohttp import web


def run(*args, **kwargs):
    return subprocess.run(list(map(str, args)), check=True, capture_output=True, **kwargs)


def network(*args):
    return run('sudo', '-n', 'ip', *args)


def firewall(namespace, *args):
    return network('netns', 'exec', namespace, 'iptables', *args)


def private(path, value):
    path.write_text(value)
    path.chmod(0o600)
    return path


async def app(config, index):
    tenant = config['tenants'][index]
    actions = 0

    async def handle(request):
        nonlocal actions
        if request.headers.get('Authorization') != 'Bearer ' + tenant['app_key']:
            raise web.HTTPForbidden()
        assert 'X-Trusted-Access' not in request.headers
        if request.path == '/ws':
            socket = web.WebSocketResponse()
            await socket.prepare(request)
            async for message in socket:
                if message.type == aiohttp.WSMsgType.TEXT:
                    await socket.send_str(message.data)
                elif message.type == aiohttp.WSMsgType.BINARY:
                    await socket.send_bytes(message.data)
            return socket
        if request.path == '/events':
            response = web.StreamResponse(headers={'Content-Type': 'text/event-stream'})
            await response.prepare(request)
            with suppress(ConnectionError, asyncio.CancelledError):
                while True:
                    await response.write(b'data: alive\n\n')
                    await asyncio.sleep(.1)
            return response
        if request.path == '/action' and request.method == 'POST':
            actions += 1
        return web.json_response({'tenant': tenant['name'], 'actions': actions,
                                 'authorization': request.headers['Authorization']})

    application = web.Application()
    application.router.add_route('*', '/{path:.*}', handle)
    runner = web.AppRunner(application, access_log=None)
    await runner.setup()
    await web.TCPSite(runner, '127.0.0.1', config.get('app_port', 8090)).start()
    # A listening canary proves inbound failure comes from the NAT firewall,
    # rather than simply testing a port that nobody has opened.
    if config.get('inbound_canary', False):
        await web.TCPSite(runner, '0.0.0.0', 8091).start()
    await asyncio.Future()


async def proxy(root):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(root / 'server.pem', root / 'server.key')

    async def accept(reader, writer):
        with (root / 'peers.jsonl').open('a') as log:
            log.write(json.dumps(writer.get_extra_info('peername')[0]) + '\n')
        upstream = None
        tasks = []
        try:
            source, upstream = await asyncio.open_connection('127.0.0.1', 8080)

            async def copy(source, destination):
                while data := await asyncio.wait_for(source.read(65536), 25):
                    destination.write(data)
                    await destination.drain()

            tasks = [asyncio.create_task(copy(reader, upstream)),
                     asyncio.create_task(copy(source, writer))]
            await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
        except (OSError, asyncio.TimeoutError):
            pass
        finally:
            for task in tasks:
                task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
            for stream in [writer, upstream]:
                if stream:
                    stream.close()
                    with suppress(OSError, asyncio.TimeoutError):
                        await asyncio.wait_for(stream.wait_closed(), 2)

    server = await asyncio.start_server(accept, '0.0.0.0', 443, ssl=context)
    async with server:
        await server.serve_forever()


async def check(root, config):
    context = ssl.create_default_context(cafile=str(root / 'ca.pem'))
    timeout = aiohttp.ClientTimeout(total=None, connect=3, sock_read=40)
    sockets = []
    tenants = config['tenants']

    def base(tenant):
        # Isolate connector keepalive from application-level WS heartbeats.
        # Client streams enter the loopback relay; every node byte crosses WSS.
        return 'http://127.0.0.1:8080'

    def headers(tenant):
        return {'X-Trusted-Access': tenant['access'], 'Authorization': 'Bearer ' + tenant['app_key']}

    def url(tenant, path):
        return base(tenant) + '/v1/http/' + tenant['route'] + path

    def connections(tenant):
        peers = [json.loads(line) for line in (root / 'peers.jsonl').read_text().splitlines()]
        return peers.count(tenant['outside'])

    async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(ssl=context), timeout=timeout) as client:
        async def ready(tenant):
            async with client.get(base(tenant) + '/v1/ready/' + tenant['route'],
                                  headers={'Authorization': 'Bearer ' + tenant['access']}) as response:
                return response.status == 204

        async def wait_ready(tenant):
            async with asyncio.timeout(45):
                while True:
                    try:
                        if await ready(tenant):
                            return
                    except aiohttp.ClientError:
                        pass
                    await asyncio.sleep(.2)

        try:
            for tenant in tenants:
                await wait_ready(tenant)
                async with client.get(url(tenant, '/echo'), headers=headers(tenant)) as response:
                    assert response.status == 200
                    assert (await response.json())['tenant'] == tenant['name']
                socket = await client.ws_connect(url(tenant, '/ws'), headers=headers(tenant))
                sockets.append(socket)
                await socket.send_bytes(b'\x00\x01\xff')
                assert (await socket.receive()).data == b'\x00\x01\xff'
                async with client.get(url(tenant, '/echo'), headers={**headers(tenant), 'Authorization': 'Bearer wrong'}) as response:
                    assert response.status == 403
            async with client.get(url(tenants[1], '/echo'), headers=headers(tenants[0])) as response:
                assert response.status in (401, 403)

            # No CA bypass and no hostname bypass, even within the private test network.
            for address, trust in [('https://' + tenants[0]['central'], ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)),
                                   ('https://127.0.0.1', context)]:
                try:
                    async with client.get(address, ssl=trust):
                        raise AssertionError('untrusted or mismatched TLS certificate accepted')
                except aiohttp.ClientConnectorCertificateError:
                    pass

            counts = [connections(tenant) for tenant in tenants]
            assert all(counts)
            await asyncio.sleep(40)  # Exceeds the TLS proxy's 25-second idle timeout.
            for tenant, socket, count in zip(tenants, sockets, counts):
                await socket.send_str('after-idle')
                assert (await socket.receive()).data == 'after-idle'
                assert connections(tenant) == count, 'idle connector reconnected instead of staying live'
            print('PASS: overlapping private addresses; outbound TLS/WSS; tenant and app-key isolation; idle continuity', flush=True)

            first, second = tenants
            async with client.post(url(first, '/action'), headers=headers(first)) as response:
                assert (await response.json())['actions'] == 1
            async with client.get(url(first, '/events'), headers=headers(first)) as stream:
                assert (await stream.content.readline()).startswith(b'data:')
                firewall(first['nat'], '-I', 'FORWARD', '1', '-j', 'DROP')
                try:
                    async with asyncio.timeout(37):
                        with suppress(aiohttp.ClientError):
                            async for _ in stream.content:
                                pass
                        assert (await sockets[0].receive()).type in (
                            aiohttp.WSMsgType.CLOSE, aiohttp.WSMsgType.CLOSED, aiohttp.WSMsgType.ERROR)
                        while await ready(first):
                            await asyncio.sleep(.1)
                    async with client.get(url(second, '/echo'), headers=headers(second)) as response:
                        assert response.status == 200
                finally:
                    firewall(first['nat'], '-D', 'FORWARD', '1')
            await wait_ready(first)
            async with client.get(url(first, '/echo'), headers=headers(first)) as response:
                assert response.status == 200
                assert (await response.json())['actions'] == 1, 'connector recovery replayed an action'
            print('PASS: silent network blackhole drains SSE/WS; other tenant survives; recovery never replays actions', flush=True)
        finally:
            for socket in sockets:
                await socket.close()


SSH_OPTIONS = ['-F', '/dev/null', '-o', 'IdentitiesOnly=yes', '-o', 'BatchMode=yes',
               '-o', 'StrictHostKeyChecking=yes', '-o', 'ConnectTimeout=20']


def ssh_check(root, config):
    """Runs inside the client namespace: every byte crosses its NAT and WSS."""
    ssh = root / 'ssh'
    options = [*SSH_OPTIONS, '-i', str(ssh / 'user'), '-o', 'UserKnownHostsFile=' + str(ssh / 'known_hosts')]

    def remote(port, *command, check=True):
        return subprocess.run(['ssh', *options, '-p', str(port), '127.0.0.1', *command],
                              capture_output=True, timeout=60, check=check)

    deadline = time.monotonic() + 45
    while remote(2222, 'echo', 'through-nat', check=False).stdout != b'through-nat\n':
        assert time.monotonic() < deadline, 'ssh through the access tunnel never became ready'
        time.sleep(.5)
    shell = 'ssh ' + ' '.join(options + ['-p', '2222'])
    blob, copy, back = root / 'blob', ssh / 'remote' / 'blob', root / 'blob.back'
    blob.write_bytes(os.urandom(8 << 20))
    digest = hashlib.sha256(blob.read_bytes()).hexdigest()
    run('rsync', '-a', '-e', shell, blob, '127.0.0.1:' + str(copy))
    assert hashlib.sha256(copy.read_bytes()).hexdigest() == digest
    # An interrupted transfer resumes instead of restarting, and is verified.
    with copy.open('r+b') as partial:
        partial.truncate(3 << 20)
    stats = run('rsync', '-a', '--partial', '--append-verify', '--stats', '-e', shell, blob, '127.0.0.1:' + str(copy)).stdout.decode()
    literal = int(next(line for line in stats.splitlines() if line.startswith('Literal data:')).split()[2].replace(',', ''))
    assert literal <= 5 << 20, f'resume resent {literal} bytes instead of only the missing tail'
    assert hashlib.sha256(copy.read_bytes()).hexdigest() == digest
    run('rsync', '-a', '-e', shell, '127.0.0.1:' + str(copy), back)
    assert hashlib.sha256(back.read_bytes()).hexdigest() == digest
    print('PASS: unmodified ssh/rsync (upload, verified resume, download) through client NAT, WSS and access tunnel', flush=True)
    # Another tenant's valid access grant cannot open this route.
    assert remote(2223, 'true', check=False).returncode != 0
    accepted = (root / 'ssh-sshd.log').read_text().count('Accepted publickey')
    peers = [json.loads(line) for line in (root / 'peers.jsonl').read_text().splitlines()]
    assert peers.count(config['ssh_client']['outside']), 'client traffic did not traverse its NAT'
    print(f'PASS: foreign grant rejected on the SSH route; {accepted} authenticated sessions, all via the client NAT', flush=True)


async def probe(host, port, expect_open=False):
    try:
        _, writer = await asyncio.wait_for(asyncio.open_connection(host, port), .8)
    except (OSError, asyncio.TimeoutError):
        if expect_open:
            raise AssertionError('inbound canary must be listening before the denial check')
        return
    writer.close()
    await writer.wait_closed()
    if not expect_open:
        raise AssertionError('firewall unexpectedly allowed a new connection')


def acceptance(binary, python, root, tunnel_binary=None):
    namespaces, processes, logs = [], [], []
    prefix = 'router-nat-' + secrets.token_hex(4)
    central = prefix + '-central'
    script = Path(__file__).resolve()

    def namespace(name):
        network('netns', 'add', name)
        namespaces.append(name)
        network('-n', name, 'link', 'set', 'lo', 'up')

    def command(namespace, *args):
        return ['sudo', '-n', 'ip', 'netns', 'exec', namespace, 'setpriv',
                '--reuid=' + str(os.getuid()), '--regid=' + str(os.getgid()), '--clear-groups',
                'env', 'SSL_CERT_FILE=' + str(root / 'ca.pem'),
                *(['TRUSTED_ROUTER_TUNNEL_BINARY=' + str(tunnel_binary)] if tunnel_binary else []),
                *map(str, args)]

    def spawn(namespace, name, *args):
        log = (root / (name + '.log')).open('wb')
        logs.append(log)
        env = {k: v for k, v in os.environ.items() if not k.startswith(('TRUSTED_', 'SSL_CERT_', 'HTTP_PROXY', 'HTTPS_PROXY', 'ALL_PROXY'))}
        child = subprocess.Popen(command(namespace, *args), env=env, stdout=log, stderr=log)
        processes.append(child)

    def interface(namespace, name, address):
        network('-n', namespace, 'addr', 'add', address, 'dev', name)
        network('-n', namespace, 'link', 'set', name, 'up')

    try:
        namespace(central)
        network('netns', 'exec', central, 'sysctl', '-qw', 'net.ipv4.ip_unprivileged_port_start=443')
        tenants = []
        for i, name in enumerate(['film', 'clawup', 'ssh', 'client'], 1):
            nat, edge = prefix + '-nat' + str(i), prefix + '-edge' + str(i)
            namespace(nat)
            namespace(edge)
            network('-n', central, 'link', 'add', 'wan' + str(i), 'type', 'veth', 'peer', 'name', 'wan', 'netns', nat)
            interface(central, 'wan' + str(i), f'10.82.{i}.2/24')
            interface(nat, 'wan', f'10.82.{i}.1/24')
            network('-n', nat, 'link', 'add', 'lan', 'type', 'veth', 'peer', 'name', 'eth0', 'netns', edge)
            interface(nat, 'lan', '10.83.0.1/24')
            interface(edge, 'eth0', '10.83.0.2/24')
            network('-n', edge, 'route', 'add', 'default', 'via', '10.83.0.1')
            network('netns', 'exec', nat, 'sysctl', '-qw', 'net.ipv4.ip_forward=1')
            firewall(nat, '-P', 'FORWARD', 'DROP')
            firewall(nat, '-A', 'FORWARD', '-m', 'conntrack', '--ctstate', 'ESTABLISHED,RELATED', '-j', 'ACCEPT')
            firewall(nat, '-A', 'FORWARD', '-i', 'lan', '-o', 'wan', '-p', 'tcp', '-d', f'10.82.{i}.2', '--dport', '443', '-m', 'conntrack', '--ctstate', 'NEW', '-j', 'ACCEPT')
            firewall(nat, '-t', 'nat', '-A', 'POSTROUTING', '-o', 'wan', '-s', '10.83.0.0/24', '-j', 'MASQUERADE')
            tenants.append(dict(name=name, edge=edge, nat=nat, central=f'10.82.{i}.2', outside=f'10.82.{i}.1', app_key=name + '-fixture-key'))

        run('openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1', '-subj', '/CN=NAT acceptance CA',
            '-addext', 'basicConstraints=critical,CA:TRUE', '-keyout', root / 'ca.key', '-out', root / 'ca.pem')
        run('openssl', 'req', '-new', '-newkey', 'rsa:2048', '-nodes', '-subj', '/CN=NAT acceptance',
            '-keyout', root / 'server.key', '-out', root / 'server.csr')
        extensions = private(root / 'extensions', 'subjectAltName=' + ','.join(f'IP:{t["central"]}' for t in tenants)
                             + '\nbasicConstraints=CA:FALSE\nextendedKeyUsage=serverAuth\n')
        run('openssl', 'x509', '-req', '-in', root / 'server.csr', '-CA', root / 'ca.pem', '-CAkey', root / 'ca.key',
            '-CAcreateserial', '-days', '1', '-extfile', extensions, '-out', root / 'server.pem')
        key, public = root / 'signing.pem', root / 'public.pem'
        run('openssl', 'genpkey', '-algorithm', 'ED25519', '-out', key)
        key.chmod(0o600)
        run('openssl', 'pkey', '-in', key, '-pubout', '-out', public)
        public.chmod(0o644)
        tenants, (ssh_node, ssh_client) = tenants[:2], tenants[2:]
        for tenant in [*tenants, ssh_node]:
            execution = dict(namespace=tenant['name'], workload='app', allocation_id='one', lease_id='first', generation=1, node_id=tenant['edge'])
            service = dict(namespace=tenant['name'], workload='app', service='ssh' if tenant is ssh_node else 'http')
            grant = dict(iss='nat-test', aud='trusted-data-router/v1', sub=tenant['edge'], nbf=int(time.time()), exp=int(time.time()) + 600,
                         purpose='register', execution=execution, service=service,
                         policy=dict(issuer='nat-test', policy_id='fixture', version=1, sha256='ab' * 32))
            tenant['route'] = hashlib.sha256(json.dumps(['nat-test', execution, service], separators=(',', ':')).encode()).hexdigest()
            private(root / (tenant['name'] + '.jwt'), run(binary, 'sign', key, input=json.dumps(grant).encode()).stdout.decode().strip())
            grant.update(purpose='access', sub=tenant['name'] + '-user')
            tenant['access'] = run(binary, 'sign', key, input=json.dumps(grant).encode()).stdout.decode().strip()
        ssh = root / 'ssh'
        (ssh / 'remote').mkdir(mode=0o700, parents=True)
        run('ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-f', ssh / 'host')
        run('ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-f', ssh / 'user')
        private(ssh / 'authorized_keys', (ssh / 'user.pub').read_text())
        private(ssh / 'known_hosts', '[127.0.0.1]:2222 ' + (ssh / 'host.pub').read_text())
        private(ssh / 'sshd_config', '\n'.join([
            'Port 2022', 'ListenAddress 127.0.0.1', f'HostKey {ssh}/host', f'PidFile {ssh}/sshd.pid',
            f'AuthorizedKeysFile {ssh}/authorized_keys', 'PasswordAuthentication no',
            'KbdInteractiveAuthentication no', 'UsePAM no', 'StrictModes no',
            'AllowUsers ' + run('id', '-un').stdout.decode().strip(), '']))
        private(root / 'ssh-access.jwt', ssh_node['access'])
        private(root / 'foreign-access.jwt', tenants[0]['access'])
        private(root / 'config.json', json.dumps(dict(tenants=tenants, ssh_node=ssh_node, ssh_client=ssh_client, inbound_canary=True)))
        spawn(central, 'relay', binary, 'relay', '127.0.0.1:8080', root / 'router.sqlite', public, 'nat-test')
        spawn(central, 'proxy', python, script, '--component', 'proxy', '--artifacts', root)
        for i, tenant in enumerate(tenants):
            spawn(tenant['edge'], tenant['name'] + '-app', python, script, '--component', 'app', '--index', i, '--artifacts', root)
            spawn(tenant['edge'], tenant['name'] + '-connector', binary, 'connect',
                  'wss://' + tenant['central'] + '/v1/connect/' + tenant['route'], '127.0.0.1:8090', root / (tenant['name'] + '.jwt'))
        spawn(ssh_node['edge'], 'ssh-sshd', '/usr/sbin/sshd', '-D', '-e', '-f', ssh / 'sshd_config')
        spawn(ssh_node['edge'], 'ssh-connector', binary, 'connect',
              'wss://' + ssh_node['central'] + '/v1/connect/' + ssh_node['route'], '127.0.0.1:2022', root / 'ssh.jwt')
        tunnel = 'wss://' + ssh_client['central'] + '/v1/tunnel/' + ssh_node['route']
        spawn(ssh_client['edge'], 'ssh-forward', binary, 'forward', tunnel, '127.0.0.1:2222', root / 'ssh-access.jwt')
        spawn(ssh_client['edge'], 'foreign-forward', binary, 'forward', tunnel, '127.0.0.1:2223', root / 'foreign-access.jwt')
        time.sleep(2)
        assert all(child.poll() is None for child in processes), 'test process failed; inspect private artifact logs'
        for i, tenant in enumerate(tenants, 1):
            run(*command(tenant['edge'], python, script, '--component', 'probe', '--host', '127.0.0.1', '--port', 8091, '--expect-open'))
            network('-n', central, 'route', 'replace', '10.83.0.0/24', 'via', tenant['outside'], 'dev', 'wan' + str(i))
            run(*command(central, python, script, '--component', 'probe', '--host', '10.83.0.2', '--port', 8091))
            run(*command(tenant['edge'], python, script, '--component', 'probe', '--host', tenant['central'], '--port', 80))
        for tenant in (ssh_node, ssh_client):
            run(*command(tenant['edge'], python, script, '--component', 'probe', '--host', tenant['central'], '--port', 80))
        print('PASS: new inbound connections blocked; nodes only allow outbound TCP/443, no UDP', flush=True)
        # Keep diagnostics in the private directory; only assertions/status go to stdout.
        result = subprocess.run(command(central, python, script, '--component', 'check', '--artifacts', root),
                                capture_output=True, timeout=180)
        private(root / 'check.log', (result.stdout + result.stderr).decode(errors='replace'))
        result.check_returncode()
        print(result.stdout.decode(), end='', flush=True)
        result = subprocess.run(command(ssh_client['edge'], python, script, '--component', 'ssh', '--artifacts', root),
                                capture_output=True, timeout=240)
        private(root / 'ssh-check.log', (result.stdout + result.stderr).decode(errors='replace'))
        result.check_returncode()
        print(result.stdout.decode(), end='', flush=True)
    finally:
        # Killing only processes within our named namespaces also stops sudo's
        # children reliably. Existing host services and firewall are untouched.
        for name in reversed(namespaces):
            pids = network('netns', 'pids', name).stdout.decode().split()
            if pids:
                run('sudo', '-n', 'kill', '-TERM', *pids)
        for process in processes:
            with suppress(subprocess.TimeoutExpired):
                process.wait(timeout=5)
        for name in reversed(namespaces):
            pids = network('netns', 'pids', name).stdout.decode().split()
            if pids:
                run('sudo', '-n', 'kill', '-KILL', *pids)
            network('netns', 'del', name)
        for log in logs:
            log.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--router-binary', type=Path)
    parser.add_argument('--tunnel-binary', type=Path, help='Use the pinned upstream Chisel adapter')
    parser.add_argument('--python', type=Path, default=Path(sys.executable))
    parser.add_argument('--artifacts', type=Path)
    parser.add_argument('--component', choices=['app', 'proxy', 'check', 'probe', 'ssh'])
    parser.add_argument('--index', type=int, default=0)
    parser.add_argument('--host')
    parser.add_argument('--port', type=int)
    parser.add_argument('--expect-open', action='store_true')
    args = parser.parse_args()
    if args.component == 'probe':
        asyncio.run(probe(args.host, args.port, args.expect_open))
        return
    if args.component:
        root = args.artifacts
        config = json.loads((root / 'config.json').read_text())
        if args.component == 'ssh':
            ssh_check(root, config)
            return
        asyncio.run(app(config, args.index) if args.component == 'app' else
                    proxy(root) if args.component == 'proxy' else check(root, config))
        return
    if not args.router_binary:
        parser.error('--router-binary is required')
    run('sudo', '-n', 'true')
    if args.artifacts:
        args.artifacts.mkdir(mode=0o700, parents=True, exist_ok=False)
        acceptance(args.router_binary.resolve(), args.python.absolute(), args.artifacts.resolve(), args.tunnel_binary.resolve() if args.tunnel_binary else None)
    else:
        with tempfile.TemporaryDirectory(prefix='router-nat-') as directory:
            acceptance(args.router_binary.resolve(), args.python.absolute(), Path(directory), args.tunnel_binary.resolve() if args.tunnel_binary else None)


if __name__ == '__main__':
    main()
