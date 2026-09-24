# Audit and hardening — 0.1.2a1

Date: 2026-09-23. Source: JY-S023-P001 / 0.1.1-partial / run-0001 / product.
Reviewed execution policy, process lifecycle, I/O, resource setup, receipts and
tests. The original source remains separate from this delivery checkout.

## Repaired findings

- Untrusted execution was offered without filesystem/network containment, and
  fresh cwd was described as confinement. The default legacy path now refuses;
  the explicitly named trusted-code runner documents inherited OS authority.
- Windows failed on import of resource. Imports and portable validation now work;
  unsupported execution platforms fail before launch. Linux-only execution is
  explicit and no Windows execution qualification is claimed.
- communicate() buffered arbitrary output before truncating it. A nonblocking
  selector now bounds retained prefixes and terminates on output overflow. Digests
  cover observed bytes, not unread or post-termination output.
- Timeout cleanup could hang while a detached descendant held pipes open. Drain
  and direct-child waits are bounded; detached descendant containment is explicitly
  not claimed. No blanket “no surviving descendants” assertion remains.
- preexec_fn applied limits in a potentially threaded parent fork. Setup now runs
  in a fresh interpreter, with a private setup-confirmation pipe closed before
  snippet execution. Failed setup cannot claim enforced resource controls.
- Mutable policies and falsey policy substitution could bypass validation. Frozen
  fields, exact types, finite bounds and a revalidated launch snapshot repair this.
  Code/stdin UTF-8 budgets and per-file/descriptor/core limits are explicit.
- Every signaled exit was mislabeled resource-limit termination. Known resource
  signals and unknown signals now have distinct verdicts; duration is monotonic.
- Receipt digests omitted policy, returned output and isolation claims, and shared
  lists could be mutated across runs. All record fields are now digest-bound and
  detached; verify_receipt checks bounded consistency without claiming authenticity.
- stderr was silently cut to a final 4,096-character slice after prefix truncation.
  Both displayed streams now follow the stated raw-byte-prefix cap consistently.

## Verification and release

Baseline could not import on Windows (resource unavailable); its historical 18-test
Linux evidence is retained separately. Current suite: 49 tests, with 19 portable
checks and 30 Linux execution checks. Source/installed-wheel Windows runs skip
Linux execution explicitly. GitHub CI must pass the actual Linux execution suite
on Python 3.10/3.12/3.14, plus portable Windows checks on 3.12, before publication.
No adversarial-isolation qualification follows from these tests.

31 new regressions cover default refusal, platform/trust handling, policy mutation,
input bounds, output floods, binary output, backpressure, closed/held pipes,
file limits, startup failure, threaded launches, bounded listings and receipt
binding. Inherited snippets are now passed to the named trusted runner, Linux
execution tests are platform-marked, and unknown-signal/isolation expectations
reflect the corrected contract. One inherited filename described relative writes
as confinement and was renamed.

The initial Linux CI run exposed a file-limit fixture that left a buffered file
unclosed: finalizer flush errors could be ignored while the process exited zero.
The regression now flushes/closes explicitly and independently checks the file
size is at most its configured cap. COMPLETED describes process exit/setup/capture,
not a guarantee that every application I/O operation succeeded.

Process behavior was checked against official Python documentation:
[subprocess](https://docs.python.org/3/library/subprocess.html),
[resource](https://docs.python.org/3/library/resource.html), and
[selectors](https://docs.python.org/3/library/selectors.html).

Version 0.1.1-partial -> 0.1.2a1; execution receipts v1 -> v2. README explains
trusted-code use, unsupported platforms, output termination and single-process
resource ceilings. Added packaging, pinned-action CI, README, security guidance
and Apache 2.0 LICENSE/NOTICE naming RUSSELL PHILIP SMITHSON. No runtime dependency
requires upgrading; no third-party source is vendored or build-tool scan claimed.
The 796-item program, G0–G9 and a real hostile-code backend remain open.
