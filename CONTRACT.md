# FLW PAM Workflow Lab — fixed implementation contract

Build a working **local workflow laboratory**, not a production PAM, authentication server, credential broker, or real access-grant integration. Python 3.11+ standard library only. CLI actors are explicit strings trusted at the current OS-user boundary; they are not authenticated identities. Do not implement HTTP/login/passwords. No secrets, real grants, external services, or network calls. SQLite audit is ordinary transactional storage, NOT WORM or tamper-proof against a database/OS owner.

## Files and API

Developer owns only `workflow.py`. QA owns only `test_workflow.py`. Reviewer owns only `security-review.json`. This file is immutable. Tests must use tempfile directories and deterministic clock where needed; no databases or output logs in the source tree. Importing workflow must have no side effects.

Export `class Workflow` from workflow.py:

`Workflow(db_path, resources=("db-read", "server-shell"), clock=time.time)` initializes schema idempotently. db_path is a path or string. resources is a nonempty list/tuple of distinct nonempty strings; persist the resource allowlist in SQLite on first initialization, and reject reopening the same DB with a different allowlist. clock is a callable returning a finite nonnegative numeric timestamp; reject invalid clock values including bool. Use separate connections per method (or equally thread-safe design) and transactions. Use SQL parameters everywhere.

Methods (keyword and positional arguments supported):

- `request(actor, resource, reason, ttl=300) -> dict`: actor/reason nonempty non-whitespace strings; resource must be in configured allowlist; ttl strictly int, 1..3600 (bool is invalid). Creates unique opaque string id, status `pending`, created_at=current clock, expires_at=created_at+ttl, approved_by=None. Return request record. Invalid input raises ValueError and creates neither request nor audit event.
- `approve(actor, request_id) -> dict`: only pending/unexpired request; approver nonempty string distinct from original requester; records status `approved`, approved_by=actor. Approval does NOT extend expires_at. Otherwise ValueError and no mutation/audit.
- `deny(actor, request_id, reason) -> dict`: only pending/unexpired request; actor nonempty and distinct from requester, reason nonempty. Sets status `denied`. Otherwise ValueError and no mutation/audit.
- `revoke(actor, request_id, reason) -> dict`: only approved request; actor must equal requester or approved_by; reason nonempty. Sets status `revoked`, even if already expired. Otherwise ValueError and no mutation/audit.
- `get(request_id) -> dict`: unknown id raises ValueError.
- `check(request_id, actor, resource) -> dict`: read-only decision containing `allowed: bool`, `reason: str`. Actor/resource/request_id must be nonempty strings; invalid types/blank raise ValueError. Evaluate in this order: missing request -> `unknown_request`; different resource -> `resource_mismatch`; different requester actor -> `actor_mismatch`; now>=expires_at -> `expired`; status != approved -> `not_approved`; otherwise `allowed` true with reason `allowed`. No audit mutation on check/get.
- `audit() -> list[dict]`: all events ascending `seq`; each contains seq(int), timestamp(number), action(`request|approve|deny|revoke`), actor(str), request_id(str), details(dict). Details for request include resource/reason/ttl; deny and revoke include reason. Each successful mutation commits exactly ONE audit event in the SAME SQLite transaction as the request mutation; rollback both on error.

Request records must contain `id`, `actor`, `resource`, `reason` (original request reason), `ttl`, `created_at`, `expires_at`, `status`, `approved_by`. Additional fields allowed. All returned dict values must be JSON serializable.

Lifecycle: pending->approved OR denied; approved->revoked; denied/revoked terminal, no repeated approval/revocation. At exact expiry check denies. Expired pending cannot be approved/denied. Double approval (including concurrent competing calls) must not succeed twice. Transactions must preserve state/audit consistency; tests should test audit write failure rollback with SQLite trigger or equivalent. No override/admin backdoor or grant-until-approved shortcut.

## CLI

`python workflow.py --db PATH request --actor alice --resource db-read --reason demo --ttl 300`
`python workflow.py --db PATH approve ID --actor bob`
`python workflow.py --db PATH deny ID --actor bob --reason policy`
`python workflow.py --db PATH revoke ID --actor alice --reason finished`
`python workflow.py --db PATH check ID --actor alice --resource db-read`
`python workflow.py --db PATH audit`
`python workflow.py --db PATH show ID`

Each successful command prints one JSON document. Errors print JSON error and exit2; check prints JSON and returns0 when allowed,1 when denied. Other successes exit0. Argparse usage errors may use normal argparse stderr. No resource configuration CLI needed in this slice: CLI default allowlist applies. CLI supports `--help`.

## Verification

`python3 -B -m unittest -v` must run real unit tests and pass. Cover full happy lifecycle, different approver, invalid/overlarge/bool TTL, resource allowlist and durable reopen policy, expiry boundary, deny/revoke terminal states, actor/resource check mismatch, unknown request, persisted records/audit across instances, no mutation on invalid commands, SQL parameter safety, concurrent approval single winner, audit insertion failure rollback, and CLI allowed/denied/error exit codes. Runtime no dependencies beyond standard library.

Security reviewer must inspect current code AND tests and write the declared JSON review. Any real blocking workflow defect -> request_changes with specific findings, never approval to satisfy a score. An honest lab limitation already stated here is not a blocker by itself. Do not claim production readiness, authentication, WORM audit, or integration with actual grants.
