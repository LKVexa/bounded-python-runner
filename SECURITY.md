# Security boundaries

This is a trusted-code resource runner, not an adversarial sandbox. The legacy
untrusted entry point refuses by default. Do not feed hostile, unreviewed or
model-generated code directly to run_trusted_python or opt in with trusted_code=True
unless it has been reviewed and is trusted with the account's authority.

Filesystem reads/writes, network access, process creation and escaped sessions
remain possible. Fresh cwd, -I, an empty passed environment, Linux rlimits and
original-group termination do not establish containment. Child CPU/memory limits
are not aggregate quotas, per-file limits are not total disk/inode quotas, and
privileged execution can bypass protections. Use an external security boundary
for untrusted code; no such backend is implemented by this package.

Output is drained incrementally and execution stops on the raw-byte cap. Hashes
cover only observed bytes. Detached pipe holders cannot keep collection open
indefinitely, but detached descendants may survive. Process startup, filesystem
operations and directory cleanup are not bounded by a total API deadline.

Execution records are unsigned and unanchored. The digest checks consistency of
all fields, not their truth or authorship. Rehashed fabricated records can pass
verify_receipt. Output and filenames may contain secrets; unsalted hashes are
not anonymous. No storage, redaction, retention or authorization service is supplied.

Only Linux execution is supported. Windows/macOS fail before child launch.
No third-party runtime package is required, and no build-tool vulnerability scan
or original gate certification is claimed. Use synthetic snippets when reporting
defects; never include credentials or private execution output in public reports.
