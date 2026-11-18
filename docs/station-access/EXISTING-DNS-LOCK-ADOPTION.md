# Existing unmarked DNS controller lock: protected adoption

**Scope:** recovery of a *preexisting* `STATE_DIRECTORY/dns-controller/controller.lock` that predates the durable identity marker. This is **not** initialization of an empty controller, historic legacy migration, restoring a lost lock, or permission to publish DNS/ACME records. No lock replacement, host enrollment, account/provider mutations, STATE reset or service reload are authorized.

## Preconditions (station Work, read-only)

1. Freeze DNS writers through the protected deployment/controller supervisor; demonstrate no old-version or external writer can start between review and commit. `flock` detects cooperating active writers but **cannot certify an uncooperative or subsequently restarted old binary**. Verify a single supervisor and service UID, installed-byte revisions and activation state independently.
2. Preserve an immutable, out-of-tree forensic copy of the **existing** lock and directory metadata, existing review receipts, journal/controller service history, generic Host UUID `305a221a-ef73-42a8-af21-a0b28bca5201`, installation `fdf20ffe-2353-40a8-a198-508e103f4348`, STATE logical UUID `8c7affc9-8be7-4959-9040-d144b5b4dc98`, and signing identity. Backup is evidence, not a new source of authority. The existing controller directory is never renamed or reconstructed.
3. Establish protected `STATE_DIRECTORY`, fixed `HOST_DNS_CONFIGURATION`, 0700 controller dir, 0600 service-owned regular **empty** lock with one link, no symlink, stable device/inode, no preexisting marker, no controller configuration, no ledger or other foreign artifacts. Existing `dns-review-<digest>.json` files may be retained if protected and internally valid. A missing, occupied, nonempty or replaced lock **blocks** adoption.
4. The actual station must still have no DNS assignments/grants/certificate assignments. The operator identity must be an active administrator. Do not use AWS A-record evidence or a DNS provider write to satisfy these prerequisites.

## Operator contract

Use the **pinned, installed** station command, not ad hoc JSON or Python snippets:

```text
python -m django adopt_dns_controller_lock review --owner <ACTIVE_ADMIN_PK>
python -m django adopt_dns_controller_lock commit --owner <SAME_ADMIN_PK> --review-id <EXACT_REVIEW_SHA256>
python -m django adopt_dns_controller_lock inspect --owner <SAME_ADMIN_PK> --review-id <EXACT_REVIEW_SHA256>
```

The standard station manage.py entrypoint and settings must be used at runtime (the lines above show only the CLI arguments). Review holds the original lock, inventories every allowed protected file by inode, length, mode and SHA-256, and saves a short-lived 10-minute review. **A separate operator approval of the exact receipt** is required before `commit`. Commit rechecks the complete original inventory and lock identity under exclusive flock, refuses intervening changes, and `O_EXCL` creates **only** `controller-lock-identity.json` bound to the original dev/inode and the reviewed receipt. It fsyncs marker and directory. It never truncates, replaces or recreates the original `controller.lock`.

Inspect and ordinary writer startup re-check the durable identity against the same hash-bound review and original lock. A repeated exact commit is idempotent. Interrupted/partial marker creation is a blocking uncertainty; **do not delete or hand-edit it**. Separately capture the on-disk marker and reason for a new reviewer disposition before any recovery. Review cannot run if a marker already exists.

## Native acceptance (not source CI)

Native Work must verify: original inode unchanged; exact review inventory, operator approval and installed-byte attestations; second process exclusion (while first holds the lock), restart/reboot reopen; unchanged Host/installation/STATE/signing identity; no database/ledger creation, Cloudflare/API writes or generic-to-AWS relabel; crash immediately before and after marker creation; and fail-closed on evidence drift, original inode replacement, symlinks, foreign state, active writer and incomplete marker.

Keep [station-access #5](https://github.com/zog144/station-access/issues/5) and stacked PRs #4/#6 open/draft. After successful adoption, the original **separate** empty shared DNS bootstrap `review → operator approve → commit → inspect` can proceed. Hostname ownership review/approval remains separate from either operation.
