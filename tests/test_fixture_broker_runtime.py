"""Parent lifecycle contracts; actual Linux mount tests run separately."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import fixture_broker_runtime as runtime


class PrivateRuntimeTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='gsp-runtime-test-')
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.work = self.root / 'gsp-behavior-eval-synthetic' / 'work'
        self.work.mkdir(parents=True)
        (self.work.parent / 'remote.git').mkdir()
        self.private = self.root / 'private'

    def test_broker_mounts_no_cli_control_or_authentication(self):
        with patch.object(runtime.sys, 'platform', 'linux'):
            command = runtime.broker_command(self.work, self.private)
        self.assertIn('--unshare-net', command)
        self.assertIn('--clearenv', command)
        self.assertEqual(command[command.index('--cap-drop') + 1], 'ALL')
        mounts = [tuple(command[i + 1:i + 3]) for i, value in enumerate(command)
                  if value in ('--bind', '--ro-bind')]
        self.assertEqual(mounts, [('/usr', '/usr'), (str(runtime.ROOT), str(runtime.ROOT)),
            (str(self.work.parent.resolve()), str(self.work.parent.resolve())),
            (str(self.private.resolve()), str(self.private.resolve()))])
        self.assertNotIn('/control', command)
        self.assertNotIn('/runtime', command)

    def test_private_records_cannot_overlap_fixture(self):
        with patch.object(runtime.sys, 'platform', 'linux'):
            for private in (self.work, self.work.parent, self.work / 'private', self.root):
                with self.subTest(private=private), self.assertRaises(ValueError):
                    runtime.broker_command(self.work, private)

    def test_nonlinux_or_nongenerated_fixture_rejected(self):
        with patch.object(runtime.sys, 'platform', 'win32'), self.assertRaises(ValueError):
            runtime.broker_command(self.work, self.private)
        with patch.object(runtime.sys, 'platform', 'linux'), self.assertRaises(ValueError):
            runtime.broker_command(self.root / 'ordinary' / 'work', self.private)

    def test_readonly_wrapper_rejects_use_on_unverified_host(self):
        with self.assertRaisesRegex(ValueError, 'verified dedicated outer runtime'):
            runtime.readonly_model_command(['codex', 'exec'], self.work)

    def test_snapshot_uses_private_subprocess_not_workspace_claims(self):
        self.private.mkdir()
        broker = runtime.PrivateFixtureRuntime(self.work, self.private)
        envelope = {'grading_state': {'actual_git_branches': {'main': 'a' * 40}},
                    'attribution_snapshot': {'state': {'branches': {'main': 'a' * 40}}, 'git': {}}}
        with patch.object(runtime, 'broker_command', return_value=['synthetic-snapshot']) as command, \
             patch.object(runtime.subprocess, 'run', return_value=subprocess.CompletedProcess(
                 [], 0, json.dumps(envelope), '')) as run:
            actual = broker.snapshot()
        command.assert_called_once_with(self.work.resolve(), self.private.resolve(), snapshot=True)
        self.assertEqual(run.call_args.kwargs['env'], {'PATH': '/usr/bin:/bin'})
        self.assertEqual(actual, envelope['grading_state'])
        self.assertEqual(broker.endpoints, [envelope['attribution_snapshot']])
        self.assertEqual(json.loads((self.private / 'snapshot-001.json').read_text()), envelope)

    def test_failed_snapshot_is_not_an_empty_success(self):
        self.private.mkdir()
        broker = runtime.PrivateFixtureRuntime(self.work, self.private)
        with patch.object(runtime, 'broker_command', return_value=['synthetic']), \
             patch.object(runtime.subprocess, 'run', return_value=subprocess.CompletedProcess([], 1, '', 'synthetic failure')), \
             self.assertRaisesRegex(RuntimeError, 'snapshot unavailable'):
            broker.snapshot()
        self.assertEqual(broker.endpoints, [])
        self.assertTrue((self.private / 'snapshot-error.txt').is_file())

    def test_finish_waits_for_validated_broker_exit_before_snapshot_and_is_idempotent(self):
        self.private.mkdir()
        (self.private / 'stopped.json').write_text('{}')
        broker = runtime.PrivateFixtureRuntime(self.work, self.private)
        broker.process = Mock()
        calls = []
        broker.process.wait.side_effect = lambda **kwargs: calls.append('wait') or 0
        receipt = {'version': 1, 'status': 'quiescent', 'accepted': 1, 'observable': 1}
        def validate(path):
            self.assertTrue((path / 'stop-requested.json').is_file())
            calls.append('validate')
            return receipt
        def snapshot():
            calls.append('snapshot')
            return {'actual_git_branches': {'main': 'a' * 40}}
        with patch('fixture_broker.validate_terminal_records', side_effect=validate), \
             patch.object(broker, 'snapshot', side_effect=snapshot):
            first = broker.finish()
            first['actual_git_branches'].clear()
            second = broker.finish()
        self.assertEqual(calls, ['wait', 'validate', 'snapshot'])
        self.assertEqual(second['actual_git_branches']['main'], 'a' * 40)
        self.assertEqual(broker.finalization, receipt)

    def test_finish_cannot_sample_a_live_or_incomplete_broker(self):
        for result in (1, subprocess.TimeoutExpired('synthetic', 45), 0):
            with self.subTest(result=result), tempfile.TemporaryDirectory() as directory:
                broker = runtime.PrivateFixtureRuntime(self.work, Path(directory))
                broker.process = Mock()
                if isinstance(result, Exception):
                    broker.process.wait.side_effect = [result, 0]
                else:
                    broker.process.wait.return_value = result
                with patch.object(broker, 'snapshot') as snapshot, self.assertRaises(RuntimeError):
                    broker.finish()
                snapshot.assert_not_called()
                self.assertIsNone(broker.sealed_post)

    def test_evidence_cannot_use_a_live_or_different_endpoint(self):
        broker = runtime.PrivateFixtureRuntime(self.work, self.private)
        with self.assertRaisesRegex(RuntimeError, 'quiescent post snapshot'):
            broker.evidence({})
        broker.sealed_post = {'branches': {'main': 'a' * 40}}
        with self.assertRaisesRegex(RuntimeError, 'quiescent post snapshot'):
            broker.evidence({'branches': {'main': 'b' * 40}})

    def test_close_terminates_only_owned_child_and_closes_streams(self):
        broker = runtime.PrivateFixtureRuntime(self.work, self.private)
        broker.process = Mock()
        broker.process.poll.return_value = None
        broker.process.wait.side_effect = [subprocess.TimeoutExpired('synthetic', 5), 0]
        broker.streams = [Mock(), Mock()]
        broker.close()
        broker.process.terminate.assert_called_once_with()
        broker.process.kill.assert_called_once_with()
        for stream in broker.streams:
            stream.close.assert_called_once_with()

    def test_start_failure_preserves_private_controls_and_closes_streams(self):
        (self.work / '.eval').mkdir()
        for name in ('remote-state.json', 'fixture-plan.json'):
            (self.work / '.eval' / name).write_text('{}')
        broker = runtime.PrivateFixtureRuntime(self.work, self.private)
        with patch.object(runtime.PrivateFixtureRuntime, 'snapshot', return_value={}), \
             patch.object(runtime, 'broker_command', return_value=['synthetic']), \
             patch.object(runtime.subprocess, 'Popen', side_effect=OSError('synthetic spawn failure')), \
             self.assertRaises(OSError):
            broker.__enter__()
        for name in ('remote-state.json', 'fixture-plan.json'):
            self.assertFalse((self.work / '.eval' / name).exists())
            self.assertTrue((self.private / name).is_file())
        self.assertTrue(all(stream.closed for stream in broker.streams))
        self.assertIsNone(broker.process)
        for name in ('.git', '.agents', '.codex'):
            self.assertTrue((self.work.parent / 'remote.git' / name).is_dir())
