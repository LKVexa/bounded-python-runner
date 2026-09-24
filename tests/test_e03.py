import unittest
import sys

from e03.core import ExecutionPolicy, run_trusted_python as run_sandboxed


class Policies(unittest.TestCase):
    def test_bounds(self):
        for bad in (dict(wall_timeout_s=0), dict(wall_timeout_s=120),
                    dict(cpu_seconds=0), dict(memory_mb=8)):
            with self.assertRaises(ValueError):
                ExecutionPolicy(**bad)


@unittest.skipUnless(sys.platform.startswith("linux"), "Linux execution backend")
class Execution(unittest.TestCase):
    def test_completed_with_output_and_receipt(self):
        r = run_sandboxed('print("hello sandbox")')
        self.assertEqual(r["verdict"], "COMPLETED")
        self.assertEqual(r["stdout"].strip(), "hello sandbox")
        self.assertTrue(r["code_digest"].startswith("sha256:"))
        self.assertTrue(r["receipt_digest"].startswith("sha256:"))

    def test_stdin(self):
        r = run_sandboxed("import sys; print(sys.stdin.read().upper())",
                          stdin_text="abc")
        self.assertIn("ABC", r["stdout"])

    def test_failure_verdict(self):
        r = run_sandboxed("raise ValueError('boom')")
        self.assertEqual(r["verdict"], "FAILED")
        self.assertIn("boom", r["stderr"])

    def test_wall_timeout_killed(self):
        r = run_sandboxed("import time\nwhile True: time.sleep(0.1)",
                          ExecutionPolicy(wall_timeout_s=1.0))
        self.assertEqual(r["verdict"], "KILLED_WALL_TIMEOUT")
        self.assertLess(r["duration_s"], 5)

    def test_cpu_limit_killed(self):
        r = run_sandboxed("while True: pass",
                          ExecutionPolicy(wall_timeout_s=10, cpu_seconds=1))
        self.assertIn(r["verdict"].split("+")[0],
                      ("KILLED_RESOURCE_LIMIT", "KILLED_SIGNAL", "KILLED_WALL_TIMEOUT", "FAILED"))
        self.assertLess(r["duration_s"], 6)

    def test_memory_limit(self):
        r = run_sandboxed("x = bytearray(500 * 1024 * 1024)",
                          ExecutionPolicy(memory_mb=64))
        self.assertIn(r["verdict"], ("FAILED", "KILLED_RESOURCE_LIMIT", "KILLED_SIGNAL"))
        self.assertNotEqual(r["verdict"], "COMPLETED")

    def test_output_cap_truncates_and_flags(self):
        r = run_sandboxed("print('x' * 200000)",
                          ExecutionPolicy(max_output_bytes=1000))
        self.assertIn("OUTPUT_TRUNCATED", r["verdict"])
        self.assertLessEqual(len(r["stdout"]), 1001)
        # digest covers only observed bytes; output-limit termination may leave unread data
        self.assertTrue(r["stdout_digest"].startswith("sha256:"))


@unittest.skipUnless(sys.platform.startswith("linux"), "Linux execution backend")
class Isolation(unittest.TestCase):
    def test_environment_cleared(self):
        r = run_sandboxed("import os; print(len(os.environ), "
                          "os.environ.get('HOME'), os.environ.get('PATH'))")
        self.assertIn("None None", r["stdout"].replace("0 ", "", 1))

    def test_fresh_cwd_and_relative_writes(self):
        r1 = run_sandboxed("import os; print(sorted(os.listdir('.')))\n"
                           "open('scratch.txt','w').write('x')")
        self.assertIn("['snippet.py']", r1["stdout"])   # fresh sandbox
        self.assertIn("scratch.txt", r1["sandbox_files_left"])
        r2 = run_sandboxed("import os; print(sorted(os.listdir('.')))")
        self.assertIn("['snippet.py']", r2["stdout"])   # nothing leaks across

    def test_isolated_interpreter_flag(self):
        r = run_sandboxed("import sys; print(sys.flags.isolated)")
        self.assertEqual(r["stdout"].strip(), "1")

    def test_limitations_stated_never_overclaimed(self):
        r = run_sandboxed("print(1)")
        self.assertIn("network egress blocking", r["isolation"]["not_enforced"])
        self.assertIn("CPU rlimit", r["isolation"]["enforced"])
        self.assertIn("BLOCKED", r["isolation"]["note"])

    def test_deterministic_digests(self):
        a = run_sandboxed("print('stable')")
        b = run_sandboxed("print('stable')")
        self.assertEqual(a["code_digest"], b["code_digest"])
        self.assertEqual(a["stdout_digest"], b["stdout_digest"])


@unittest.skipUnless(sys.platform.startswith("linux"), "Linux execution backend")
class Hardening(unittest.TestCase):
    """New tests for the 0.1.1-partial repairs (A020 audit)."""

    # F1: max_output_bytes must be validated like every other knob.
    def test_max_output_bytes_validated(self):
        for bad in (-5, 0, 16 * 1024 * 1024 + 1):
            with self.assertRaises(ValueError):
                ExecutionPolicy(max_output_bytes=bad)
        with self.assertRaises(TypeError):
            ExecutionPolicy(max_output_bytes=1000.0)
        r = run_sandboxed("print('ok')", ExecutionPolicy(max_output_bytes=1))
        self.assertIn("OUTPUT_TRUNCATED", r["verdict"])  # positive path

    # F2/F5: typed argument contract instead of leaked internal errors.
    def test_code_and_stdin_type_contract(self):
        for bad in (None, b"print(1)", 42):
            with self.assertRaises(TypeError):
                run_sandboxed(bad)
        with self.assertRaises(TypeError):
            run_sandboxed("print(1)", stdin_text=b"x")
        with self.assertRaises(TypeError):
            run_sandboxed("print(1)", policy=object())
        self.assertEqual(run_sandboxed("print(1)")["verdict"], "COMPLETED")

    # F3: non-int rlimit knobs must be rejected at policy construction,
    # not explode later inside preexec_fn as SubprocessError.
    def test_rlimit_knobs_require_int(self):
        for kw in (dict(cpu_seconds=2.5), dict(memory_mb=64.0),
                   dict(cpu_seconds=True), dict(memory_mb=True)):
            with self.assertRaises(TypeError):
                ExecutionPolicy(**kw)

    # F4: a grandchild spawned by the snippet must not survive the
    # wall-clock kill — the whole process group dies with the attempt.
    def test_no_surviving_descendants_after_wall_kill(self):
        import os as _os
        import tempfile as _tf
        import time as _time
        marker = _tf.mktemp(prefix="e03-orphan-")
        code = (
            "import subprocess, time\n"
            f"subprocess.Popen(['/bin/sh','-c','sleep 2; echo alive > {marker}'])\n"
            "while True: time.sleep(0.1)\n")
        r = run_sandboxed(code, ExecutionPolicy(wall_timeout_s=1.0))
        self.assertEqual(r["verdict"], "KILLED_WALL_TIMEOUT")
        _time.sleep(3)
        try:
            self.assertFalse(_os.path.exists(marker),
                             "grandchild outlived the sandboxed attempt")
        finally:
            if _os.path.exists(marker):
                _os.remove(marker)

    def test_isolation_lists_group_kill(self):
        r = run_sandboxed("print(1)")
        self.assertIn("original process-group termination attempted",
                      r["isolation"]["enforced"])


if __name__ == "__main__":
    unittest.main()
