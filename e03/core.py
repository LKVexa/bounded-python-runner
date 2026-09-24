"""Linux resource-bounded execution for trusted code, not a security sandbox.

Untrusted execution is refused. Filesystem/network access and escaped process
sessions are not contained. Receipts are unsigned consistency records.
"""
from __future__ import annotations
import dataclasses
import hashlib
import json
import math
import os
import selectors
import signal
import subprocess
import sys
import tempfile
import time
import uuid

VERSION = "0.1.2a1"
MAX_CODE_BYTES = 256 * 1024
MAX_STDIN_BYTES = 1024 * 1024
MAX_FILES_REPORTED = 100
CHUNK_BYTES = 16384
DRAIN_SECONDS = 0.5


class IsolationUnavailableError(RuntimeError):
    """A hostile-code containment backend is not implemented."""


class UnsupportedPlatformError(RuntimeError):
    """Bounded execution requires the verified Linux resource backend."""


def _digest(data):
    return "sha256:" + hashlib.sha256(data).hexdigest()


@dataclasses.dataclass(frozen=True)
class ExecutionPolicy:
    wall_timeout_s: float = 5.0
    cpu_seconds: int = 3
    memory_mb: int = 256
    max_output_bytes: int = 65536
    max_file_bytes: int = 8 * 1024 * 1024

    def __post_init__(self):
        if type(self.wall_timeout_s) not in (int, float):
            raise TypeError("wall_timeout_s must be a built-in real number")
        if not 0 < self.wall_timeout_s <= 60 or not math.isfinite(self.wall_timeout_s):
            raise ValueError("wall_timeout_s must be finite and in (0, 60]")
        for name, low, high in (("cpu_seconds", 1, 30), ("memory_mb", 32, 2048),
                               ("max_output_bytes", 1, 16 * 1024 * 1024),
                               ("max_file_bytes", 1, 64 * 1024 * 1024)):
            value = getattr(self, name)
            if type(value) is not int:
                raise TypeError(name + " must be an integer")
            if not low <= value <= high:
                raise ValueError(name + " outside supported range")

    def as_dict(self):
        return dataclasses.asdict(self)


ENFORCED = ("fresh temporary cwd per attempt", "isolated interpreter (-I)",
    "empty environment passed to interpreter", "CPU rlimit", "address-space rlimit",
    "per-file size rlimit", "64-descriptor rlimit", "core dumps disabled",
    "parent wall-clock termination", "streamed output cap",
    "original process-group termination attempted")
NOT_ENFORCED = ("network egress blocking", "filesystem read confinement",
    "filesystem write confinement", "kernel namespaces/seccomp", "process-count containment",
    "escaped-session descendant containment", "aggregate disk/inode quota")

# Resource setup runs in a newly executed interpreter, avoiding preexec_fn in
# the potentially multithreaded parent. The status FD closes before user code.
_LAUNCHER = r'''
import json, os, resource, runpy, sys
p = json.loads(sys.argv[1])
script, ready = sys.argv[2], int(sys.argv[3])
resource.setrlimit(resource.RLIMIT_CPU, (p["cpu_seconds"], p["cpu_seconds"]))
memory = p["memory_mb"] * 1024 * 1024
resource.setrlimit(resource.RLIMIT_AS, (memory, memory))
resource.setrlimit(resource.RLIMIT_FSIZE, (p["max_file_bytes"], p["max_file_bytes"]))
resource.setrlimit(resource.RLIMIT_NOFILE, (64, 64))
resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
os.write(ready, b"R")
os.close(ready)
sys.argv = [script]
runpy.run_path(script, run_name="__main__")
'''


def _kill_group(proc):
    try:
        os.killpg(proc.pid, signal.SIGKILL)
        return True
    except ProcessLookupError:
        return True
    except OSError:
        return False


def _collect(proc, ready_fd, stdin, policy, started):
    outputs = {name: bytearray() for name in ("stdout", "stderr")}
    hashes = {name: hashlib.sha256() for name in outputs}
    counts = {name: 0 for name in outputs}
    reason, ready, offset, drain_deadline = None, False, 0, None
    complete, group_terminated = True, True
    deadline = started + policy.wall_timeout_s
    with selectors.DefaultSelector() as selector:
        def register(stream, event, name):
            os.set_blocking(stream if type(stream) is int else stream.fileno(), False)
            selector.register(stream, event, name)

        def remove(stream):
            selector.unregister(stream)
            if type(stream) is not int:
                stream.close()

        register(proc.stdout, selectors.EVENT_READ, "stdout")
        register(proc.stderr, selectors.EVENT_READ, "stderr")
        register(ready_fd, selectors.EVENT_READ, "ready")
        if stdin:
            register(proc.stdin, selectors.EVENT_WRITE, "stdin")
        else:
            proc.stdin.close()
        while selector.get_map():
            now = time.monotonic()
            if drain_deadline is None and now >= deadline:
                reason = "KILLED_WALL_TIMEOUT"
                group_terminated = _kill_group(proc) and group_terminated
                drain_deadline = now + DRAIN_SECONDS
            elif drain_deadline is None and proc.poll() is not None:
                group_terminated = _kill_group(proc) and group_terminated
                drain_deadline = now + DRAIN_SECONDS
            if drain_deadline is not None and now >= drain_deadline:
                complete = False
                break
            until = drain_deadline if drain_deadline is not None else deadline
            events = selector.select(max(0, min(0.05, until - now)))
            for key, _ in events:
                name, stream = key.data, key.fileobj
                if name == "stdin":
                    try:
                        count = os.write(key.fd, stdin[offset:offset + CHUNK_BYTES])
                    except BlockingIOError:
                        continue
                    except BrokenPipeError:
                        remove(stream)
                        continue
                    offset += count
                    if offset == len(stdin):
                        remove(stream)
                    continue
                try:
                    chunk = os.read(key.fd, CHUNK_BYTES)
                except BlockingIOError:
                    continue
                if not chunk:
                    remove(stream)
                    continue
                if name == "ready":
                    ready = chunk == b"R"
                    remove(stream)
                    continue
                counts[name] += len(chunk)
                hashes[name].update(chunk)
                available = max(0, policy.max_output_bytes - len(outputs[name]))
                outputs[name].extend(chunk[:available])
                if counts[name] > policy.max_output_bytes:
                    reason = reason or "KILLED_OUTPUT_LIMIT"
                    group_terminated = _kill_group(proc) and group_terminated
                    complete = False
                    # Stop collecting immediately: escaped writers cannot make
                    # post-timeout draining or hashing unbounded.
                    break
            if any(count > policy.max_output_bytes for count in counts.values()):
                break
    if reason is None and proc.poll() is None:
        try:
            proc.wait(timeout=max(0, deadline - time.monotonic()))
        except subprocess.TimeoutExpired:
            reason = "KILLED_WALL_TIMEOUT"
    group_terminated = _kill_group(proc) and group_terminated
    for stream in (proc.stdin, proc.stdout, proc.stderr):
        if stream is not None and not stream.closed:
            stream.close()
    remaining = max(DRAIN_SECONDS, deadline - time.monotonic()) if reason is None else DRAIN_SECONDS
    try:
        proc.wait(timeout=remaining)
    except subprocess.TimeoutExpired:
        reason = reason or "KILLED_WALL_TIMEOUT"
        group_terminated = _kill_group(proc) and group_terminated
        try:
            proc.kill()
        except ProcessLookupError:
            pass
        try:
            proc.wait(timeout=DRAIN_SECONDS)
        except subprocess.TimeoutExpired:
            reason, complete = "TERMINATION_FAILED", False
    return outputs, hashes, counts, reason, ready, complete, group_terminated


def _encoded(value, name, limit):
    if type(value) is not str:
        raise TypeError(name + " must be a string")
    if len(value) > limit:
        raise ValueError(name + " byte budget exceeded")
    try:
        data = value.encode("utf-8")
    except UnicodeError as exc:
        raise ValueError(name + " contains invalid Unicode") from exc
    if len(data) > limit:
        raise ValueError(name + " byte budget exceeded")
    return data


def _record_digest(record):
    return _digest(json.dumps({k: v for k, v in record.items() if k != "receipt_digest"},
        sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode())


def verify_receipt(record):
    """Bounded consistency check, not authentication of an execution claim."""
    if type(record) is not dict or record.get("schema") != "e03/execution-record/v2":
        return False
    pending, values, string_size = [(record, 0)], 0, 0
    while pending:
        item, depth = pending.pop()
        values += 1
        if values > 2000 or depth > 5:
            return False
        if type(item) is dict:
            if len(item) > 2000 or any(type(k) is not str for k in item):
                return False
            pending.extend((v, depth + 1) for v in item.values())
            pending.extend((k, depth + 1) for k in item)
        elif type(item) is list:
            if len(item) > 2000:
                return False
            pending.extend((v, depth + 1) for v in item)
        elif type(item) is str:
            if len(item) > 16 * 1024 * 1024:
                return False
            string_size += len(item)
            if string_size > 40 * 1024 * 1024:
                return False
        elif type(item) is int:
            if item.bit_length() > 64:
                return False
        elif type(item) is float:
            if not math.isfinite(item):
                return False
        elif item is not None and type(item) is not bool:
            return False
    try:
        return type(record.get("receipt_digest")) is str and record["receipt_digest"] == _record_digest(record)
    except (ValueError, TypeError, UnicodeError, RecursionError):
        return False


def run_sandboxed(code, policy=None, stdin_text="", *, trusted_code=False):
    """Legacy entry point: refuse untrusted execution; opt-in is explicit."""
    if trusted_code is not True:
        raise IsolationUnavailableError("untrusted-code containment is unavailable; use an external sandbox")
    return run_trusted_python(code, policy, stdin_text)


def run_trusted_python(code, policy=None, stdin_text=""):
    """Run code already trusted by the caller on Linux with process ceilings.

    This function grants the snippet the caller's filesystem/network authority.
    """
    code_bytes = _encoded(code, "code", MAX_CODE_BYTES)
    stdin_bytes = _encoded(stdin_text, "stdin_text", MAX_STDIN_BYTES)
    if policy is None:
        policy = ExecutionPolicy()
    if type(policy) is not ExecutionPolicy:
        raise TypeError("policy must be an ExecutionPolicy")
    policy = ExecutionPolicy(**policy.as_dict())  # Revalidate even bypassed frozen fields.
    if not sys.platform.startswith("linux"):
        raise UnsupportedPlatformError("bounded execution requires Linux; no child was launched")
    try:
        import resource
        for name in ("RLIMIT_CPU", "RLIMIT_AS", "RLIMIT_FSIZE", "RLIMIT_NOFILE", "RLIMIT_CORE"):
            getattr(resource, name)
    except (ImportError, AttributeError) as exc:
        raise UnsupportedPlatformError("required Linux rlimits unavailable") from exc
    attempt, wall_started, started = str(uuid.uuid4()), time.time(), time.monotonic()
    with tempfile.TemporaryDirectory(prefix="e03-") as directory:
        script = os.path.join(directory, "snippet.py")
        with open(script, "wb") as stream:
            stream.write(code_bytes)
        read_fd, write_fd = os.pipe()
        proc = None
        try:
            proc = subprocess.Popen([sys.executable, "-I", "-c", _LAUNCHER,
                json.dumps(policy.as_dict()), script, str(write_fd)],
                cwd=directory, env={}, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, close_fds=True, pass_fds=(write_fd,), start_new_session=True)
            os.close(write_fd)
            write_fd = None
            output, hashes, counts, reason, ready, complete, group_terminated = _collect(
                proc, read_fd, stdin_bytes, policy, started)
        finally:
            if write_fd is not None:
                os.close(write_fd)
            os.close(read_fd)
            if proc is not None:
                _kill_group(proc)
                for stream in (proc.stdin, proc.stdout, proc.stderr):
                    if stream is not None and not stream.closed:
                        stream.close()
                if proc.poll() is None:
                    try:
                        proc.kill()
                        proc.wait(timeout=DRAIN_SECONDS)
                    except (OSError, subprocess.TimeoutExpired):
                        pass
        files = []
        with os.scandir(directory) as entries:
            for entry in entries:
                files.append(entry.name)
                if len(files) > MAX_FILES_REPORTED:
                    break
        files_truncated = len(files) > MAX_FILES_REPORTED
        files = sorted(files[:MAX_FILES_REPORTED])
    rc = proc.returncode
    if reason is not None:
        verdict = reason
    elif not ready:
        verdict = "SETUP_FAILED"
    elif not group_terminated:
        verdict = "TERMINATION_FAILED"
    elif not complete:
        verdict = "OUTPUT_INCOMPLETE"
    elif rc == 0:
        verdict = "COMPLETED"
    elif rc is not None and rc < 0:
        verdict = "KILLED_RESOURCE_LIMIT" if -rc in (signal.SIGXCPU, signal.SIGXFSZ) else "KILLED_SIGNAL"
    else:
        verdict = "FAILED"
    truncated = any(count > policy.max_output_bytes for count in counts.values())
    if truncated:
        verdict += "+OUTPUT_TRUNCATED"
    record = {"schema": "e03/execution-record/v2", "kernel_version": VERSION,
        "attempt_id": attempt, "started_at_unix": wall_started,
        "code_digest": _digest(code_bytes), "stdin_digest": _digest(stdin_bytes),
        "policy": policy.as_dict(), "verdict": verdict, "return_code": rc,
        "stdout": bytes(output["stdout"]).decode("utf-8", errors="replace"),
        "stderr": bytes(output["stderr"]).decode("utf-8", errors="replace"),
        "stdout_digest": "sha256:"+hashes["stdout"].hexdigest(),
        "stderr_digest": "sha256:"+hashes["stderr"].hexdigest(),
        "observed_bytes": counts, "digest_scope": "observed stream bytes",
        "stream_capture_complete": complete, "output_truncated": truncated,
        "resource_setup_confirmed": ready, "process_group_termination_succeeded": group_terminated,
        "sandbox_files_left": files, "file_listing_truncated": files_truncated,
        "duration_s": round(time.monotonic() - started, 6),
        "isolation": {"enforced": list(ENFORCED) if ready else [], "not_enforced": list(NOT_ENFORCED),
            "note": "trusted code only; hostile-code isolation remains BLOCKED; detached descendants may survive"}}
    record["receipt_digest"] = _record_digest(record)
    return record
