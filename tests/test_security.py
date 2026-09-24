import copy
import dataclasses
import hashlib
import json
import math
import os
import sys
import tempfile
import unittest
from unittest.mock import patch

from e03 import core


class PortableValidation(unittest.TestCase):
    def test_default_untrusted_execution_refused_before_launch(self):
        with patch.object(core.subprocess, 'Popen') as launch:
            with self.assertRaises(core.IsolationUnavailableError):
                core.run_sandboxed('print(1)')
            launch.assert_not_called()

    def test_truthy_values_do_not_bypass_trust_boundary(self):
        for value in (1, 'true', [], None, False):
            with self.subTest(value=value), self.assertRaises(core.IsolationUnavailableError):
                core.run_sandboxed('print(1)', trusted_code=value)

    def test_explicit_trust_routes_to_named_runner(self):
        with patch.object(core, 'run_trusted_python', return_value={'test': 'record'}) as run:
            self.assertEqual(core.run_sandboxed('x', trusted_code=True), {'test': 'record'})
            run.assert_called_once_with('x', None, '')

    def test_unsupported_platform_fails_before_launch(self):
        with patch.object(core.sys, 'platform', 'win32'), patch.object(core.subprocess, 'Popen') as launch:
            with self.assertRaises(core.UnsupportedPlatformError):
                core.run_trusted_python('print(1)')
            launch.assert_not_called()

    def test_macos_is_not_silently_assumed_supported(self):
        with patch.object(core.sys, 'platform', 'darwin'):
            with self.assertRaises(core.UnsupportedPlatformError):
                core.run_trusted_python('print(1)')

    def test_policy_immutable(self):
        policy = core.ExecutionPolicy()
        with self.assertRaises(dataclasses.FrozenInstanceError):
            policy.cpu_seconds = 0

    def test_policy_snapshot_is_detached(self):
        policy = core.ExecutionPolicy()
        snapshot = policy.as_dict()
        snapshot['memory_mb'] = 1
        self.assertEqual(policy.memory_mb, 256)

    def test_bypassed_frozen_policy_is_revalidated(self):
        policy = core.ExecutionPolicy()
        object.__setattr__(policy, 'max_output_bytes', -1)
        with patch.object(core.subprocess, 'Popen') as launch:
            with self.assertRaises(ValueError):
                core.run_trusted_python('x', policy)
            launch.assert_not_called()

    def test_falsey_policy_not_replaced_by_default(self):
        for policy in (False, 0, {}, []):
            with self.assertRaises(TypeError):
                core.run_trusted_python('x', policy)

    def test_wall_limits_are_finite(self):
        for value in (float('nan'), float('inf'), -1, 0, 61, 10**1000):
            with self.subTest(value=value), self.assertRaises(ValueError):
                core.ExecutionPolicy(wall_timeout_s=value)

    def test_boolean_and_coerced_policy_values_rejected(self):
        for name in ('wall_timeout_s', 'cpu_seconds', 'memory_mb', 'max_output_bytes', 'max_file_bytes'):
            for value in (True, '1', None):
                with self.subTest(name=name, value=value), self.assertRaises(TypeError):
                    core.ExecutionPolicy(**{name: value})

    def test_file_size_bounds(self):
        for value in (0, -1, 64*1024*1024+1):
            with self.assertRaises(ValueError):
                core.ExecutionPolicy(max_file_bytes=value)

    def test_code_input_bounds_before_platform_check(self):
        for value in (None, b'x', 1):
            with self.assertRaises(TypeError):
                core.run_trusted_python(value)
        for value in ('x'*(core.MAX_CODE_BYTES+1), '\ud800'):
            with self.assertRaises(ValueError):
                core.run_trusted_python(value)

    def test_stdin_bounds_before_platform_check(self):
        with self.assertRaises(TypeError):
            core.run_trusted_python('x', stdin_text=b'x')
        with self.assertRaises(ValueError):
            core.run_trusted_python('x', stdin_text='x'*(core.MAX_STDIN_BYTES+1))

    def test_utf8_byte_limit(self):
        with patch.object(core, 'MAX_CODE_BYTES', 8):
            with self.assertRaises(ValueError):
                core.run_trusted_python('界'*3)

    def test_receipt_hash_binds_all_fields(self):
        record = {'schema': 'e03/execution-record/v2', 'policy': {'cpu_seconds': 1},
                  'stdout': 'x', 'isolation': {'enforced': []}}
        record['receipt_digest'] = core._record_digest(record)
        self.assertTrue(core.verify_receipt(record))
        for key, value in (('policy', {'cpu_seconds': 2}), ('stdout', 'y'), ('isolation', {})):
            altered = copy.deepcopy(record)
            altered[key] = value
            self.assertFalse(core.verify_receipt(altered))

    def test_malformed_receipt_returns_false(self):
        for record in (None, [], {'schema': 'bad'}, {'schema': 'e03/execution-record/v2', 'x': float('nan')},
                       {'schema': 'e03/execution-record/v2', 'x': object()}):
            self.assertFalse(core.verify_receipt(record))
        record = {'schema': 'e03/execution-record/v2'}
        record['cycle'] = record
        self.assertFalse(core.verify_receipt(record))

    def test_isolation_lists_have_no_guaranteed_descendant_claim(self):
        self.assertIn('filesystem write confinement', core.NOT_ENFORCED)
        self.assertIn('escaped-session descendant containment', core.NOT_ENFORCED)
        self.assertFalse(any('no surviving' in value for value in core.ENFORCED))


@unittest.skipUnless(sys.platform.startswith('linux'), 'Linux execution backend')
class LinuxExecution(unittest.TestCase):
    def test_observed_output_digest_and_stdin_binding(self):
        record = core.run_trusted_python('print("hello")', stdin_text='secret')
        self.assertEqual(record['stdout_digest'], 'sha256:'+hashlib.sha256(b'hello\n').hexdigest())
        self.assertEqual(record['stdin_digest'], 'sha256:'+hashlib.sha256(b'secret').hexdigest())
        self.assertTrue(record['stream_capture_complete'])
        self.assertTrue(record['resource_setup_confirmed'])
        self.assertTrue(core.verify_receipt(record))

    def test_output_flood_stops_without_parent_buffer_growth(self):
        code = 'import os\nwhile True: os.write(1,b"x"*16384)'
        record = core.run_trusted_python(code, core.ExecutionPolicy(max_output_bytes=1000))
        self.assertEqual(record['verdict'], 'KILLED_OUTPUT_LIMIT+OUTPUT_TRUNCATED')
        self.assertEqual(len(record['stdout']), 1000)
        self.assertLessEqual(record['observed_bytes']['stdout'], 1000+core.CHUNK_BYTES)
        self.assertFalse(record['stream_capture_complete'])
        self.assertLess(record['duration_s'], 3)

    def test_stderr_prefix_is_not_silently_replaced_by_last_4096(self):
        record = core.run_trusted_python('import sys; sys.stderr.write("x"*6000)',
                                         core.ExecutionPolicy(max_output_bytes=7000))
        self.assertEqual(len(record['stderr']), 6000)
        self.assertFalse(record['output_truncated'])

    def test_binary_output_decodes_with_explicit_observed_digest(self):
        record = core.run_trusted_python('import os; os.write(1,b"\\xff\\xfe")')
        self.assertEqual(record['stdout'], '\ufffd\ufffd')
        self.assertEqual(record['observed_bytes']['stdout'], 2)
        self.assertTrue(core.verify_receipt(record))

    def test_large_stdin_and_stderr_do_not_deadlock(self):
        code = 'import sys; sys.stderr.write("e"*50000); sys.stderr.flush(); print(len(sys.stdin.read()))'
        record = core.run_trusted_python(code, stdin_text='x'*100000)
        self.assertEqual(record['verdict'], 'COMPLETED')
        self.assertEqual(record['stdout'].strip(), '100000')

    def test_closed_output_streams_still_obey_wall_deadline(self):
        record = core.run_trusted_python('import os,time; os.close(1); os.close(2); time.sleep(5)',
                                         core.ExecutionPolicy(wall_timeout_s=0.3))
        self.assertEqual(record['verdict'], 'KILLED_WALL_TIMEOUT')
        self.assertLess(record['duration_s'], 2)

    def test_unknown_signal_not_mislabeled_resource_limit(self):
        record = core.run_trusted_python('import os,signal; os.kill(os.getpid(),signal.SIGTERM)')
        self.assertEqual(record['verdict'], 'KILLED_SIGNAL')

    def test_per_file_size_limit(self):
        code = 'import os\ntry:\n with open("large", "wb") as output:\n  output.write(b"x"*10000)\n  output.flush()\nfinally:\n print(os.stat("large").st_size)'
        record = core.run_trusted_python(code, core.ExecutionPolicy(max_file_bytes=1024))
        self.assertNotEqual(record['verdict'], 'COMPLETED')
        self.assertLessEqual(int(record['stdout'].strip()), 1024)

    def test_receipts_do_not_share_mutable_isolation_lists(self):
        first = core.run_trusted_python('pass')
        first['isolation']['enforced'].clear()
        second = core.run_trusted_python('pass')
        self.assertTrue(second['isolation']['enforced'])

    def test_startup_failure_cannot_claim_enforcement_or_run_code(self):
        with patch.object(core, '_LAUNCHER', 'raise RuntimeError("setup failed")'):
            record = core.run_trusted_python('print("must not run")')
        self.assertEqual(record['verdict'], 'SETUP_FAILED')
        self.assertFalse(record['resource_setup_confirmed'])
        self.assertEqual(record['isolation']['enforced'], [])
        self.assertEqual(record['stdout'], '')

    def test_run_from_multithreaded_parent(self):
        from concurrent.futures import ThreadPoolExecutor
        with ThreadPoolExecutor(max_workers=2) as pool:
            records = list(pool.map(core.run_trusted_python, ['print(1)', 'print(2)']))
        self.assertEqual([r['stdout'].strip() for r in records], ['1', '2'])

    def test_file_listing_is_bounded(self):
        record = core.run_trusted_python('from pathlib import Path\nfor i in range(110): Path(str(i)).touch()')
        self.assertEqual(len(record['sandbox_files_left']), 100)
        self.assertTrue(record['file_listing_truncated'])

    def test_detached_pipe_holder_does_not_hang_parent(self):
        # The child deliberately exits itself shortly; this tests bounded pipe
        # draining without claiming detached-session containment.
        import time
        code = 'import subprocess,sys; subprocess.Popen([sys.executable,"-I","-c","import time; time.sleep(1.5)"], start_new_session=True)'
        try:
            record = core.run_trusted_python(code, core.ExecutionPolicy(wall_timeout_s=5))
            self.assertEqual(record['verdict'], 'OUTPUT_INCOMPLETE')
            self.assertFalse(record['stream_capture_complete'])
            self.assertLess(record['duration_s'], 1.5)
        finally:
            time.sleep(2)
