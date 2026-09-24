# 0.1.2a1 — 2026-09-23

- Refuse untrusted execution; expose explicit Linux trusted-code execution.
- Bound streamed output and pipe draining; clarify detached descendants can survive.
- Move resource setup to a fresh interpreter with setup confirmation.
- Freeze/revalidate policies, bound inputs and add file/descriptor/core ceilings.
- Bind full receipt v2 records and distinguish signal causes with monotonic timing.
- Add 31 regressions, packaging, CI, README and Apache 2.0 LICENSE/NOTICE.
- Windows supports validation/import only; original isolation certifications stay open.

# Changelog — E03 Sandboxed Code Execution (JY-S023-P001)

## 0.1.1-partial — 2026-09-14 (A020 audit repairs)

Baseline fingerprint: build-0001 `product.zip`
sha256 `6174964e34830d5d8376d05b5c98f245b87a72048614d8f9f71c939b569b4e6a`
(baseline version 0.1.0-partial; baseline suite 13/13 PASS before audit).

All findings below were reproduced live on the unmodified baseline
before fixing. Repairs only tighten sandbox behaviour; no baseline
runtime restriction was weakened or removed.

### A020-F1 — `max_output_bytes` unvalidated
- Observed: `ExecutionPolicy(max_output_bytes=-5)` accepted; run
  returned verdict `COMPLETED+OUTPUT_TRUNCATED` with stdout silently
  corrupted by a negative slice (`'hello\n'` -> `'h'`); `0` also
  accepted and always flagged truncation.
- Expected: rejected at construction like every other policy knob.
- Fix: validated int in [1, 16777216]; ValueError outside, TypeError
  for non-int.

### A020-F2 — non-str `code` leaks bare TypeError from file write
- Observed: `run_sandboxed(None)` / `run_sandboxed(b"...")` raised the
  internal `TypeError: write() argument must be str...` from inside
  the sandbox-file write.
- Fix: explicit typed contract — `TypeError("code must be str (...)")`
  raised before any sandbox work.

### A020-F3 — non-int rlimit knobs accepted, explode in preexec_fn
- Observed: `ExecutionPolicy(cpu_seconds=2.5)` accepted; the run then
  failed with `subprocess.SubprocessError: Exception occurred in
  preexec_fn` (rlimits never applied).
- Fix: `cpu_seconds`, `memory_mb`, `max_output_bytes` must be real
  ints (bool rejected); `wall_timeout_s` must be a real number.

### A020-F4 — grandchild processes survive the wall-clock kill
- Observed: a snippet that spawned a background `/bin/sh` child then
  spun forever was killed at the wall timeout, but the grandchild kept
  running after `run_sandboxed` returned and wrote a file outside the
  (already deleted) sandbox.
- Fix: snippet now runs in its own session/process group
  (`start_new_session=True`); on wall timeout — and unconditionally in
  a fail-closed `finally` sweep — the entire group receives SIGKILL.
  `isolation.enforced` now lists "process-group kill (no surviving
  descendants)". This tightens the sandbox boundary only.

### A020-F5 — non-str `stdin_text` leaks bare AttributeError
- Observed: `run_sandboxed("print(1)", stdin_text=b"x")` raised
  `AttributeError: 'bytes' object has no attribute 'encode'`.
- Fix: typed contract as F2. A non-ExecutionPolicy `policy` is also
  rejected with TypeError.

### Compatibility
- All 13 baseline tests pass unchanged; 5 focused tests added (18/18).
- Public API unchanged for all previously valid inputs; previously
  invalid inputs now fail fast with documented ValueError/TypeError
  instead of leaking internal errors or corrupting output.
- Isolation limitations statement unchanged: still NOT kernel-grade
  isolation; network egress and filesystem reads remain unconfined.

### Rollback
Restore build-0001 `product.zip` (sha256 above); no data formats or
persistent state involved.
