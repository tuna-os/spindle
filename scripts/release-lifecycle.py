#!/usr/bin/env python3
"""Rehearse a real schema-2 → schema-3 upgrade and offline rollback.

Requires old and candidate binaries; keeps only a redacted JSON verdict.
The fixture's media blobs are copied separately, as an operator must do.
"""
import argparse
import contextlib
import hashlib
import json
import pathlib
import shutil
import socket
import subprocess
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request


class Instance:
    def __init__(self, root):
        self.root = root
        root.mkdir()
        with socket.socket() as sock:
            sock.bind(('127.0.0.1', 0))
            port = sock.getsockname()[1]
        self.base = f'http://127.0.0.1:{port}'
        self.data = root / 'data'
        self.config = root / 'spindle.toml'
        self.config.write_text(
            f'[server]\nname = "upgrade.local"\nbind = "127.0.0.1:{port}"\n'
            f'[storage]\npath = "{self.data}"\n'
            '[ratelimit]\nenabled = false\n[federation]\nenabled = false\n'
            '[push]\nenabled = false\n[previews]\nenabled = false\n')

    @contextlib.contextmanager
    def serve(self, binary):
        with (self.root / 'server.log').open('ab') as log:
            process = subprocess.Popen([str(binary), str(self.config)], stdout=log, stderr=log)
            try:
                deadline = time.monotonic() + 45
                while True:
                    if process.poll() is not None:
                        raise RuntimeError(f'server exited: {self.root.name}')
                    try:
                        self.request('GET', '/_matrix/client/versions')
                        break
                    except (urllib.error.URLError, TimeoutError, ConnectionError):
                        if time.monotonic() > deadline:
                            raise RuntimeError('server readiness timed out')
                        time.sleep(0.1)
                yield self
            finally:
                process.terminate()
                try:
                    process.wait(timeout=15)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()

    def request(self, method, path, body=None, token=None, raw=False):
        headers = {}
        if token:
            headers['Authorization'] = f'Bearer {token}'
        if isinstance(body, bytes):
            headers['Content-Type'] = 'application/octet-stream'
        elif body is not None:
            body = json.dumps(body).encode()
            headers['Content-Type'] = 'application/json'
        req = urllib.request.Request(self.base + path, body, headers, method=method)
        with urllib.request.urlopen(req, timeout=30) as response:
            content = response.read()
            return content if raw else json.loads(content)

    def command(self, binary, verb, *args, succeeds=True):
        result = subprocess.run([str(binary), verb, str(self.config), *map(str, args)],
                                capture_output=True, timeout=90)
        if (result.returncode == 0) != succeeds:
            raise RuntimeError(f'{verb}: unexpected exit {result.returncode}: '
                               + result.stderr.decode(errors='replace'))
        return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--old', type=pathlib.Path, required=True)
    parser.add_argument('--candidate', type=pathlib.Path, required=True)
    parser.add_argument('--commit', required=True)
    parser.add_argument('--report', type=pathlib.Path, required=True)
    args = parser.parse_args()
    old, candidate = args.old.resolve(), args.candidate.resolve()
    payload = b'Spindle release lifecycle: media survives a real migration.\n'
    with tempfile.TemporaryDirectory(prefix='spindle-upgrade-') as scratch:
        root = pathlib.Path(scratch)
        source, rollback, restored = [Instance(root / name) for name in
                                      ('source', 'rollback', 'restored')]
        with source.serve(old):
            registered = source.request('POST', '/_matrix/client/v3/register', {
                'username': 'operator', 'password': 'release-fixture-password',
                'auth': {'type': 'm.login.dummy', 'session': 'release-fixture'}})
            token = registered['access_token']
            user_id, device_id = registered['user_id'], registered['device_id']
            room = source.request('POST', '/_matrix/client/v3/createRoom', {
                'room_version': '11', 'name': 'upgrade fixture'}, token)['room_id']
            state_path = '/_matrix/client/v3/rooms/' + urllib.parse.quote(room, safe='') + '/state/m.room.topic/'
            source.request('PUT', state_path, {'topic': 'survives migration'}, token)
            media = source.request('POST', '/_matrix/media/v3/upload', payload, token)['content_uri']
        backup = root / 'before.backup'
        source.command(old, 'backup', backup)
        rollback.command(old, 'restore', backup)
        shutil.copytree(source.data / 'media', rollback.data / 'media', dirs_exist_ok=True)
        rollback.command(old, 'verify-media')
        media_path = '/_matrix/client/v1/media/download/' + media.removeprefix('mxc://')

        def verify(instance, binary):
            with instance.serve(binary):
                instance.request('GET', '/_matrix/client/v3/sync', token=token)
                assert instance.request('GET', state_path, token=token)['topic'] == 'survives migration'
                assert instance.request('GET', media_path, token=token, raw=True) == payload

        verify(rollback, old)
        # Migration is explicit, irreversible, and repeatable. Dry-run must not
        # prevent the previous binary from reading the same restored fixture.
        planned = rollback.command(candidate, 'migrate', '--dry-run')
        assert b'CANNOT be undone' in planned.stdout, 'the drill must cross a real schema boundary'
        verify(rollback, old)
        migrated = rollback.command(candidate, 'migrate')
        assert b'CANNOT be undone' in migrated.stdout
        repeated = rollback.command(candidate, 'migrate')
        assert b'already at this binary' in repeated.stdout
        rollback.command(candidate, 'verify-media')
        verify(rollback, candidate)
        rollback.command(old, 'backup', root / 'must-refuse.backup', succeeds=False)
        upgraded = root / 'after.backup'
        rollback.command(candidate, 'backup', upgraded)
        restored.command(candidate, 'restore', upgraded)
        shutil.copytree(rollback.data / 'media', restored.data / 'media', dirs_exist_ok=True)
        restored.command(candidate, 'verify-media')
        verify(restored, candidate)
        # Drain a real mailbox, restart with push disabled, then resume from
        # the acknowledged token. Consumed rows must not reset the counter.
        with restored.serve(candidate):
            restored.request('PUT', '/_matrix/client/v3/sendToDevice/m.room.encrypted/restart-proof',
                             {'messages': {user_id: {device_id: {'ciphertext': 'fixture'}}}}, token)
            delivered = restored.request('GET', '/_matrix/client/v3/sync', token=token)
            assert len(delivered['to_device']['events']) == 1
            acknowledged = restored.request('GET', '/_matrix/client/v3/sync?since=' +
                                            urllib.parse.quote(delivered['next_batch'], safe=''), token=token)
            assert not acknowledged['to_device']['events']
            since = acknowledged['next_batch']
        with restored.serve(candidate):
            path = '/_matrix/client/v3/rooms/' + urllib.parse.quote(room, safe='') + '/send/m.room.message/after-restart'
            sent = restored.request('PUT', path, {'msgtype': 'm.text', 'body': 'after restart'}, token)['event_id']
            resumed = restored.request('GET', '/_matrix/client/v3/sync?since=' +
                                       urllib.parse.quote(since, safe=''), token=token)
            assert any(event['event_id'] == sent for event in resumed['rooms']['join'][room]['timeline']['events'])
        # Rollback starts from the original backup, never from migrated data.
        recovery = Instance(root / 'recovery')
        recovery.command(old, 'restore', backup)
        shutil.copytree(source.data / 'media', recovery.data / 'media', dirs_exist_ok=True)
        recovery.command(old, 'verify-media')
        verify(recovery, old)
    report = {'candidate': args.commit, 'old_commit': '496a77a029026a3acd087b4851c42e746bd9b9db',
              'migration': 'content_digest 2 -> 3', 'result': 'passed',
              'checks': ['old backup/restore', 'dry-run preserves old readability',
                         'real migration and idempotence', 'old binary refuses new schema',
                         'new backup/restore', 'media and state survive', 'drained mailbox restart', 'old backup rollback'],
              'media_sha256': hashlib.sha256(payload).hexdigest()}
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()
