"""Per-evaluation private broker lifecycle inside an already verified Linux host boundary.

No model or production publication is started here. The child sees only the
synthetic fixture, its own private records and read-only runtime code; it never
mounts the CLI authentication directory. This is not a default Skill dependency.
"""
from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path
import shutil
import subprocess
import sys
import time


ROOT = Path(__file__).resolve().parents[1]


def readonly_model_command(command: list[str], work: Path) -> list[str]:
    """Mount only the generated bare remote read-only for the model process.

    Must run inside the separately verified outer runtime, not against a host
    root. The sibling private broker keeps its own writable view. Codex still
    applies root-denied, network-denied tool permissions inside this view.
    """
    work = work.resolve()
    bare = work.parent / 'remote.git'
    if (sys.platform != 'linux' or ROOT != Path('/repo')
            or not Path('/runtime/codex').is_file() or Path('/mnt/c').exists()
            or work.parent.parent != Path('/tmp') or work.name != 'work'
            or not work.parent.name.startswith('gsp-behavior-eval-')
            or not bare.is_dir() or bare.is_symlink()):
        raise ValueError('read-only model mount requires the verified dedicated outer runtime')
    # Codex protects these names under every writable root. Materialize its
    # known empty destinations before the kernel read-only mount is applied.
    # They are not Git objects/config and do not alter the fixture's refs.
    for name in ('.git', '.agents', '.codex'):
        target = bare / name
        if not target.is_dir() or target.is_symlink() or any(target.iterdir()):
            raise ValueError('bare remote metadata mount placeholders must be empty directories')
    # A root bind makes inherited device submounts nodev. Recreate a minimal
    # /dev so CLI subprocesses can open /dev/null; no host device is mounted.
    return ['/usr/bin/bwrap', '--bind', '/', '/', '--ro-bind', str(bare), str(bare),
            '--dev', '/dev', '--', *command]


def broker_command(work: Path, private: Path, *, snapshot: bool = False) -> list[str]:
    work, private = work.resolve(), private.resolve()
    if sys.platform != 'linux' or work.name != 'work' or not work.parent.name.startswith('gsp-behavior-eval-'):
        raise ValueError('private broker requires a generated Linux fixture')
    if private.is_relative_to(work.parent) or work.parent.is_relative_to(private):
        raise ValueError('private records must be outside the model fixture root')
    command = ['/usr/bin/bwrap', '--unshare-user', '--uid', '1000', '--gid', '1000',
        '--unshare-pid', '--unshare-ipc', '--unshare-uts', '--unshare-net', '--new-session',
        '--die-with-parent', '--cap-drop', 'ALL', '--clearenv', '--ro-bind', '/usr', '/usr',
        '--symlink', 'usr/bin', '/bin', '--symlink', 'usr/sbin', '/sbin',
        '--symlink', 'usr/lib', '/lib', '--symlink', 'usr/lib64', '/lib64',
        '--proc', '/proc', '--dev', '/dev', '--tmpfs', '/tmp',
        '--ro-bind', str(ROOT), str(ROOT),
        '--bind', str(work.parent), str(work.parent), '--bind', str(private), str(private),
        '--setenv', 'PATH', '/usr/bin:/bin', '--setenv', 'HOME', '/tmp/broker-home',
        '--setenv', 'PYTHONDONTWRITEBYTECODE', '1', '--chdir', str(work), '--',
        '/usr/bin/python3', '-I', str(ROOT / 'scripts/fixture_broker.py'),
        '--work', str(work), '--bare', str(work.parent / 'remote.git'), '--private', str(private),
        '--spool', str(work / '.eval/broker-io')]
    if snapshot:
        command.append('--snapshot-evidence')
    return command


class PrivateFixtureRuntime:
    def __init__(self, work: Path, private: Path):
        self.work, self.private = work.resolve(), private.resolve()
        self.process = None
        self.streams = []
        self.pre = None
        self.endpoints = []
        self.sealed_post = None
        self.finalization = None

    def __enter__(self):
        self.private.mkdir(parents=True, exist_ok=False)
        self.private.chmod(0o700)
        for name in ('remote-state.json', 'fixture-plan.json'):
            source = self.work / '.eval' / name
            if not source.is_file() or source.is_symlink():
                raise ValueError('fixture controls must exist before model startup')
            shutil.move(str(source), str(self.private / name))
        shutil.copyfile(ROOT / 'scripts/fixture_broker_client.py', self.work / '.eval/fixture_control.py')
        (self.work / '.eval/broker-io').mkdir()
        for name in ('.git', '.agents', '.codex'):
            (self.work.parent / 'remote.git' / name).mkdir(exist_ok=False)
        # These files no longer contain private controls, but the model needs
        # only the client and candidate Skill; do not stage unused implementation.
        for name in ('behavior_fixture_spec.py', 'materialize_behavior_fixture.py'):
            source = self.work / '.eval' / name
            if source.is_file() and not source.is_symlink():
                shutil.move(str(source), str(self.private / ('staged-unused-' + name)))
        self.pre = self.snapshot()
        command = broker_command(self.work, self.private)
        (self.private / 'launch.json').write_text(json.dumps(command, indent=2))
        self.streams = [(self.private / name).open('w', encoding='utf-8') for name in ('server-stdout.txt', 'server-stderr.txt')]
        try:
            self.process = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=self.streams[0],
                                            stderr=self.streams[1], env={'PATH': '/usr/bin:/bin'},
                                            start_new_session=True)
        except OSError:
            self.close()
            raise
        deadline = time.monotonic() + 10
        while not (self.private / 'ready.json').exists():
            if self.process.poll() is not None or time.monotonic() >= deadline:
                self.close()
                raise RuntimeError('private fixture broker failed to become ready')
            time.sleep(0.02)
        return self

    def snapshot(self) -> dict:
        result = subprocess.run(broker_command(self.work, self.private, snapshot=True),
            env={'PATH': '/usr/bin:/bin'}, capture_output=True, text=True, timeout=45, check=False)
        if result.returncode:
            (self.private / 'snapshot-error.txt').write_text(result.stderr, encoding='utf-8')
            raise RuntimeError('private fixture snapshot unavailable')
        envelope = json.loads(result.stdout)
        self.endpoints.append(envelope['attribution_snapshot'])
        (self.private / f'snapshot-{len(self.endpoints):03d}.json').write_text(json.dumps(envelope, indent=2), encoding='utf-8')
        return envelope['grading_state']

    def evidence(self, post: dict) -> dict:
        if self.sealed_post is None or post != self.sealed_post:
            raise RuntimeError('final evidence requires the matching quiescent post snapshot')
        state = json.loads((self.private / 'remote-state.json').read_text())
        records = self.private / 'observations.jsonl'
        observations = [json.loads(line)['observation'] for line in records.read_text().splitlines()] if records.exists() else []
        if len(self.endpoints) < 2:
            raise RuntimeError('private endpoint snapshots missing')
        return {'source': 'isolated_parent_broker',
            'plan': json.loads((self.private / 'fixture-plan.json').read_text()),
            'pre': deepcopy(self.endpoints[0]), 'post': deepcopy(self.endpoints[-1]),
            'runtime': deepcopy(state['fixture_runtime']), 'observations': observations,
            'finalization': deepcopy(self.finalization)}

    def finish(self) -> dict:
        """Settle the owned broker before sampling final state and journals."""
        if self.sealed_post is not None:
            return deepcopy(self.sealed_post)
        if self.process is None:
            raise RuntimeError('private broker was not started')
        with (self.private / 'stop-requested.json').open('x', encoding='utf-8') as stream:
            json.dump({'version': 1}, stream)
        try:
            exit_code = self.process.wait(timeout=45)
        except subprocess.TimeoutExpired as error:
            self.close()
            raise RuntimeError('private broker did not settle before final snapshot') from error
        if exit_code != 0 or not (self.private / 'stopped.json').is_file():
            raise RuntimeError('private broker did not confirm a clean stop')
        # Import on the parent side only, after the last possible broker writer
        # exited. Model responses and writable spool files are not proof.
        from fixture_broker import validate_terminal_records
        self.finalization = {'version': 1, 'status': 'quiescent',
                             **validate_terminal_records(self.private)}
        self.sealed_post = self.snapshot()
        return deepcopy(self.sealed_post)

    def close(self):
        if self.process is not None and self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=5)
        for stream in self.streams:
            stream.close()

    def __exit__(self, *_):
        self.close()
