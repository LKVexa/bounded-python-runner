# Bounded Python Runner

**0.1.2a1 — experimental partial candidate, JY-S023-P001 / E03**

Runs **trusted Python code only** on Linux with process resource ceilings,
bounded output capture and unsigned execution receipts. It is not a security
sandbox. The source baseline's untrusted-code execution claim was unsafe:
filesystem/network authority and detached descendants were not contained.
The legacy run_sandboxed entry point now refuses execution by default.

## Install and use

Python 3.10+; no third-party runtime packages. Actual execution requires Linux.
Importing, policy validation and receipt consistency checks also work on Windows;
execution raises UnsupportedPlatformError there before starting a child.

~~~sh
python -m pip install .
python -m unittest discover -s tests -t .
~~~

~~~python
from e03.core import ExecutionPolicy, run_trusted_python, verify_receipt

# Only code already trusted with this account's filesystem/network authority.
record = run_trusted_python('print("hello")', ExecutionPolicy(wall_timeout_s=2))
assert record["verdict"] == "COMPLETED"
assert verify_receipt(record)
~~~

Use a separate externally managed containment system for adversarial code.
Calling run_sandboxed(code) raises IsolationUnavailableError. Its compatibility
escape hatch requires the exact keyword trusted_code=True and routes to the
same trusted runner; truthy strings/integers do not opt in. The named trusted
runner is preferable because it makes the boundary visible at the call site.

## Process and resource contract

A run creates a private temporary working directory containing snippet.py and
starts sys.executable with -I, an empty passed environment, closed inherited
descriptors and a new process session. Python may initialize locale-related
environment values itself. This is not a guarantee of an empty os.environ.

Resource setup runs in the new interpreter, before the snippet, avoiding
preexec_fn in a potentially multithreaded parent. A separate pipe confirms
successful setup before execution. Linux rlimits cover CPU time, address space,
per-file size, 64 open descriptors and disabled core dumps. A setup failure
cannot claim those controls were enforced. Limits are process-level and inherited;
they are not aggregate cgroup quotas across descendants.

ExecutionPolicy is immutable and copied/revalidated at launch:

| Setting | Default | Accepted range |
| --- | --- | --- |
| wall_timeout_s | 5 seconds | finite (0, 60] |
| cpu_seconds | 3 | integer 1..30 |
| memory_mb | 256 | integer 32..2048 |
| max_output_bytes | 65,536 per stream | integer 1..16 MiB |
| max_file_bytes | 8 MiB per file | integer 1..64 MiB |

Code is capped at 256 KiB UTF-8 and stdin at 1 MiB. Invalid Unicode and coerced
policy values are refused before launch. A selector streams stdin/stdout/stderr
without communicate() buffering. Each output prefix is retained up to its raw-
byte cap. Exceeding either cap terminates the original process group and stops
capture, rather than continuing to collect an unbounded stream. Hashes cover
observed raw bytes only, with byte counts and capture/truncation flags. UTF-8
replacement decoding can expand the encoded display string beyond the raw cap.

Wall timeout requests SIGKILL for the original process group. After the main
process exits, remaining pipe drain is bounded to 0.5 seconds. Direct-child
termination waits are bounded too. Process creation, filesystem operations and
temporary-directory cleanup are outside a strict total API deadline.

## Explicit limits of isolation

The snippet can read and write outside its working directory, access the network
and act with the caller's account privileges. There is no chroot, namespace,
seccomp, network filter, process-count containment or aggregate disk/inode quota.
Fresh cwd is organization, not filesystem confinement. Per-file size limits do
not prevent many small files. Temporary-directory cleanup can be expensive or
fail if trusted code changes permissions or creates excessive content.

Children that create another process session can escape the original group kill
and survive; records state this limitation. Bounded pipe draining prevents such
a child from indefinitely holding the parent in output collection, but does not
contain or terminate it. No “no surviving descendants” claim is made. Run with
minimal OS privileges and supply only code you trust with those privileges.

## Verdicts and receipt v2

COMPLETED requires exit zero, confirmed resource setup and complete stream capture.
FAILED records a nonzero normal exit. KILLED_WALL_TIMEOUT and KILLED_OUTPUT_LIMIT
identify parent termination triggers. SIGXCPU/SIGXFSZ are classified as
KILLED_RESOURCE_LIMIT; other signals are KILLED_SIGNAL because a signal alone
does not prove a resource-limit cause. OUTPUT_INCOMPLETE reports a bounded drain
ending before EOF, SETUP_FAILED reports unconfirmed setup, and TERMINATION_FAILED
reports a failed termination attempt. +OUTPUT_TRUNCATED marks exceeded raw caps.
MemoryError is a failure; it is never reported as COMPLETED.

Records include code/stdin hashes, policy snapshot, timestamps, monotonic duration,
return code, displayed output, observed-byte hashes/counts, stream completeness,
resource-setup confirmation, termination status, up to 100 top-level filenames
with a truncation flag, and detached isolation lists. The receipt_digest binds
all other record fields. verify_receipt performs bounded hash consistency only;
it does not authenticate who ran code, establish trustworthy execution, validate
the semantic truth of a record or prevent a creator from rehashing a forgery.

No receipts are persisted automatically. Output and filenames may contain
sensitive data; hashes are unsalted and are not anonymization. Operational errors
such as launch/directory/cleanup failures can raise exceptions without a receipt.

## Verification and migration

49 tests: 18 inherited checks, adapted for the trusted Linux contract, plus 31
new regressions. Windows runs 19 portable checks and explicitly skips 30 Linux
execution checks. Linux CI runs the execution suite, including output floods,
timeouts, memory/file ceilings, pipe backpressure, detached pipe holders, startup
failure, threaded-parent launches and receipt binding. Source and installed-wheel
Windows results are in [CHECK_RUNS](docs/CHECK_RUNS.json); CI covers Linux Python
3.10/3.12/3.14 and Windows Python 3.12. See [AUDIT](docs/AUDIT.md) and [SECURITY](SECURITY.md).

0.1.1-partial -> 0.1.2a1 changes execution trust, platform and receipt contracts.
Use run_trusted_python only for reviewed trusted code; untrusted workloads require
an external backend. Minimum address-space policy is now 32 MiB. Output cap
exceedance now terminates execution, hashes describe observed bytes, stderr is
not silently reduced to its final 4,096 characters, and receipt v2 covers every
field. Signaled exits no longer automatically mean a resource-limit kill.

The original 796-item program, G0–G9 certification, isolation-backend selection,
multi-language execution and formal platform qualification remain open. Linux
tests do not certify adversarial isolation; Windows execution is unsupported.

## License

Copyright 2026 **RUSSELL PHILIP SMITHSON**.
[Apache License 2.0](LICENSE), with [NOTICE](NOTICE).
No third-party source is vendored; see [THIRD-PARTY-NOTICES](THIRD-PARTY-NOTICES.md).
