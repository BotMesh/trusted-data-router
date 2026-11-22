#!/usr/bin/env python3
"""Test a real outbound WSS connector on an authorized SSH test host.

SSH only installs/stops the fixture; it carries no application traffic. A
temporary Cloudflare Quick Tunnel exposes the isolated local relay. This is a
development ingress, not a production deployment recommendation. The client
uses the loopback relay, so SSE travels inside the node's WSS connection (Quick
Tunnels do not support directly proxying HTTP SSE). No host firewall is changed.
Requires Python >=3.11 + aiohttp locally, Python >=3.10 + venv on the SSH host,
openssl, cloudflared, and a compatible Linux router binary. Artifacts stay local.
"""
import argparse
import asyncio
from contextlib import suppress
import hashlib
import io
import json
import os
from pathlib import Path
import re
import shlex
import socket
import subprocess
import sys
import tarfile
import time

import aiohttp

sys.dont_write_bytecode = True
from test_nat import private, run


def port():
    with socket.socket() as listener:
        listener.bind(('127.0.0.1', 0))
        return listener.getsockname()[1]


def stop(process):
    if process and process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()


def worker(root):
    """Self-expiring supervisor owns only its app and connector child processes."""
    config = json.loads((root / 'config.json').read_text())
    config['app_port'] = port()
    private(root / 'config.json', json.dumps(config))
    app = connector = None
    logs = []

    def launch(name, args):
        log = (root / (name + '.log')).open('ab')
        logs.append(log)
        env = {k: v for k, v in os.environ.items() if not k.startswith(('TRUSTED_', 'SSL_CERT_'))}
        return subprocess.Popen(list(map(str, args)), stdout=log, stderr=log, env=env)

    try:
        app = launch('app', [sys.executable, root / 'test_nat.py', '--component', 'app', '--artifacts', root])
        for generation in range(10):
            connector = launch('connector', [root / 'router', 'connect', config['connect_url'],
                                             '127.0.0.1:' + str(config['app_port']), root / 'register.jwt'])
            private(root / 'state.tmp', json.dumps(dict(generation=generation, app=app.pid, connector=connector.pid,
                                                       app_port=config['app_port'])))
            (root / 'state.tmp').replace(root / 'state.json')
            deadline = time.monotonic() + 300
            while time.monotonic() < deadline and not (root / 'stop').exists():
                if app.poll() is not None or connector.poll() is not None:
                    raise RuntimeError('fixture process exited')
                if (root / 'restart').exists():
                    (root / 'restart').unlink()
                    break
                time.sleep(.1)
            else:
                break
            stop(connector)
            # Let the client observe withdrawal before reconnecting.
            time.sleep(2)
    finally:
        stop(connector)
        stop(app)
        private(root / 'stopped', 'done')
        for log in logs:
            log.close()


async def check(base, config, restart):
    route = config['route']
    tenant = config['tenants'][0]
    headers = {'X-Trusted-Access': config['access'], 'Authorization': 'Bearer ' + tenant['app_key']}
    url = base + '/v1/http/' + route
    async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=None, connect=5, sock_read=45)) as client:
        async def wait_ready():
            async with asyncio.timeout(90):
                while True:
                    async with client.get(base + '/v1/ready/' + route,
                                          headers={'Authorization': 'Bearer ' + config['access']}) as response:
                        if response.status == 204:
                            return
                    await asyncio.sleep(.2)

        await wait_ready()
        async with client.get(url + '/echo', headers=headers) as response:
            assert response.status == 200
            assert (await response.json())['tenant'] == tenant['name']
        for override in [{'Authorization': 'Bearer wrong'}, {'X-Trusted-Access': config['other_access']}]:
            async with client.get(url + '/echo', headers={**headers, **override}) as response:
                assert response.status in (401, 403)
        async with client.ws_connect(url + '/ws', headers=headers) as ws:
            await ws.send_bytes(b'\x00\xffremote')
            assert (await ws.receive()).data == b'\x00\xffremote'
            await asyncio.sleep(40)
            await ws.send_str('after-idle')
            assert (await ws.receive()).data == 'after-idle'
            async with client.post(url + '/action', headers=headers) as response:
                assert (await response.json())['actions'] == 1
            async with client.get(url + '/events', headers=headers) as stream:
                assert (await stream.content.readline()).startswith(b'data:')
                await asyncio.to_thread(restart)
                async with asyncio.timeout(15):
                    with suppress(aiohttp.ClientError):
                        async for _ in stream.content:
                            pass
                    assert (await ws.receive()).type in (aiohttp.WSMsgType.CLOSE, aiohttp.WSMsgType.CLOSED, aiohttp.WSMsgType.ERROR)
        await wait_ready()
        async with client.get(url + '/echo', headers=headers) as response:
            assert response.status == 200
            assert (await response.json())['actions'] == 1
        print('PASS: remote outbound WSS; HTTP/SSE/WS; tenant and app-key denial; idle continuity; reconnect without action replay', flush=True)


def acceptance(args):
    root = args.artifacts.resolve()
    root.mkdir(mode=0o700, parents=True, exist_ok=False)
    binary = args.router_binary.resolve()
    script = Path(__file__).resolve()
    ssh_args = ['ssh', '-o', 'BatchMode=yes', '-o', 'ConnectTimeout=10', '-o', 'StrictHostKeyChecking=yes', args.ssh_host]

    def ssh(*command, **kwargs):
        return run(*ssh_args, shlex.join(list(map(str, command))), timeout=120, **kwargs)

    processes, logs, remote, worker_started = [], [], None, False
    try:
        key, public = root / 'signing.pem', root / 'public.pem'
        run('openssl', 'genpkey', '-algorithm', 'ED25519', '-out', key)
        key.chmod(0o600)
        run('openssl', 'pkey', '-in', key, '-pubout', '-out', public)
        public.chmod(0o644)
        address = '127.0.0.1:' + str(port())
        env = {k: v for k, v in os.environ.items() if not k.startswith(('TRUSTED_', 'SSL_CERT_'))}
        for name, command in [
            ('relay', [binary, 'relay', address, root / 'router.sqlite', public, 'remote-test']),
            ('ingress', [args.cloudflared, '--config', private(root / 'empty.yml', '{}\n'), 'tunnel', '--no-autoupdate',
                         '--protocol', 'http2', '--url', 'http://' + address]),
        ]:
            log = (root / (name + '.log')).open('wb')
            logs.append(log)
            processes.append(subprocess.Popen(list(map(str, command)), env=env, stdout=log, stderr=log))
        deadline = time.monotonic() + 60
        while time.monotonic() < deadline:
            assert all(process.poll() is None for process in processes), 'relay/ingress exited; inspect private logs'
            match = re.search(r'https://[a-z0-9-]+\.trycloudflare\.com', (root / 'ingress.log').read_text())
            if match:
                break
            time.sleep(.2)
        else:
            raise TimeoutError('temporary ingress did not become ready')

        remote = ssh('mktemp', '-d', '/tmp/trusted-router-acceptance.XXXXXXXX').stdout.decode().strip()
        assert re.fullmatch(r'/tmp/trusted-router-acceptance\.[A-Za-z0-9]+', remote)
        execution = dict(namespace='remote-fixture', workload='app', allocation_id='one', lease_id=root.name,
                         generation=1, node_id=args.ssh_host)
        service = dict(namespace='remote-fixture', workload='app', service='http')
        grant = dict(iss='remote-test', aud='trusted-data-router/v1', sub=args.ssh_host, nbf=int(time.time()),
                     exp=int(time.time()) + 900, purpose='register', execution=execution, service=service,
                     policy=dict(issuer='remote-test', policy_id='fixture', version=1, sha256='cd' * 32))
        route = hashlib.sha256(json.dumps(['remote-test', execution, service], separators=(',', ':')).encode()).hexdigest()

        def sign():
            return run(binary, 'sign', key, input=json.dumps(grant).encode()).stdout.decode().strip()

        private(root / 'register.jwt', sign())
        config = dict(route=route, tenants=[dict(name='remote-fixture', app_key='remote-fixture-app-key')],
                      connect_url=match[0].replace('https://', 'wss://') + '/v1/connect/' + route)
        # The remote node receives only the registration capability, never the signer or client grants.
        private(root / 'config.json', json.dumps(config))
        archive = io.BytesIO()
        with tarfile.open(fileobj=archive, mode='w:gz') as tar:
            for path, name in [(binary, 'router'), (script, 'test_remote.py'), (script.with_name('test_nat.py'), 'test_nat.py'),
                               (root / 'config.json', 'config.json'), (root / 'register.jwt', 'register.jwt')]:
                tar.add(path, arcname=name)
        ssh('tar', '-xzf', '-', '-C', remote, input=archive.getvalue())
        ssh('python3', '-m', 'venv', remote + '/venv')
        ssh(remote + '/venv/bin/python', '-m', 'pip', 'install', '--disable-pip-version-check', 'aiohttp==3.14.5')
        launch = ('import subprocess,sys; from pathlib import Path; p=Path(sys.argv[1]); '
                  'log=(p/"worker.log").open("wb"); '
                  'subprocess.Popen([str(p/"venv/bin/python"),str(p/"test_remote.py"),"--worker",str(p)], '
                  'stdin=subprocess.DEVNULL,stdout=log,stderr=log,start_new_session=True)')
        ssh('python3', '-c', launch, remote)
        worker_started = True
        grant.update(purpose='access', sub='remote-user')
        config['access'] = sign()
        grant['execution'] = dict(execution, namespace='other-tenant')
        grant['service'] = dict(service, namespace='other-tenant')
        config['other_access'] = sign()
        asyncio.run(check('http://' + address, config, lambda: ssh('touch', remote + '/restart')))
        state = json.loads(ssh('cat', remote + '/state.json').stdout)
        assert state['generation'] == 1, 'connector did not restart exactly once'
        listeners = ssh('ss', '-H', '-ltnp', 'sport = :' + str(state['app_port'])).stdout.decode()
        assert '127.0.0.1:' + str(state['app_port']) in listeners
        assert '0.0.0.0:' + str(state['app_port']) not in listeners
        private(root / 'remote-listeners.txt', listeners)
        print('PASS: remote app preserved across connector restart; no node public listener configured', flush=True)
    finally:
        if remote:
            try:
                if worker_started:
                    ssh('touch', remote + '/stop')
                    for _ in range(20):
                        status = ssh('python3', '-c', 'import pathlib,sys; print((pathlib.Path(sys.argv[1])/"stopped").exists())', remote)
                        if status.stdout.strip() == b'True':
                            break
                        time.sleep(.5)
                    else:
                        raise RuntimeError('remote supervisor did not confirm cleanup; it will expire within 300 seconds')
                    for name in ['worker.log', 'app.log', 'connector.log', 'state.json']:
                        private(root / ('remote-' + name), ssh('cat', remote + '/' + name).stdout.decode())
                ssh('rm', '-rf', '--', remote)
            finally:
                for process in reversed(processes):
                    stop(process)
                for log in logs:
                    log.close()
        else:
            for process in reversed(processes):
                stop(process)
            for log in logs:
                log.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--worker', type=Path, help=argparse.SUPPRESS)
    parser.add_argument('--ssh-host')
    parser.add_argument('--router-binary', type=Path)
    parser.add_argument('--artifacts', type=Path)
    parser.add_argument('--cloudflared', default='cloudflared')
    args = parser.parse_args()
    if args.worker:
        worker(args.worker)
    elif all([args.ssh_host, args.router_binary, args.artifacts]):
        acceptance(args)
    else:
        parser.error('--ssh-host, --router-binary and --artifacts are required')


if __name__ == '__main__':
    main()
