# Historical identity and scheduler artifacts — NOT INSTALLABLE

**Publication classification: legacy source fixtures only.** These exact-text
snapshots are retained for provenance and SR-06 review. They are deliberately
stored under `docs/` as `.txt` files, outside runtime declarations and
deployable `deployment/` directories. They are **not** valid Zog
application specifications or systemd units to deploy, copy, enable,
schedule, package as runtime artifacts, or turn into active jobs.

| Archived file | Historical issue | Required replacement |
| --- | --- | --- |
| `vnc-application.py.txt` | Nonpersistent, multi-instance VNC program contains `user="regular"` | Separately approved workspace-specific identity/runtime contract; **not** the persistent-singleton application grant |
| `station-deployment-jobs.service.txt` and `.timer.txt` | Named `station-access` account, static host paths, deployable-looking recurring SSM mutation job | Reviewed selected finite worker/host-deploy owner with immutable view, protected state, original durable operation identity and narrow dispatch authority |
| `host-dns-reconcile.service.txt` and `.timer.txt` | Named user, static paths and a second potentially competing DNS writer | Independently approved **single** DNS reconciliation owner, protected credential/ledger bindings and explicit native installation or controller worker contract |

The controller's production station web application is instead
`integration/production/station-access/application.py`, declaring
`persistent=True`, `multiple_instances=False` and
`execution_identity="application"` without named program users.
The `zog-execution-identity-v1` application grant is not a shortcut for the
historical nonpersistent VNC example or worker timers.

These fixtures retain their original historical bytes; the source-publication
guard checks their fixed Git blob hashes. For an authorized implementation of
workers or desktop identity, create new, reviewed contracts and new runtime
source paths. Never rename these files back to executable suffixes merely to
install them. Existing job logic and ledgers remain in their maintained owners;
quarantine does **not** delete or change business logic.

SR-06 owner disposition (2026-10-21): box-control and root-control classified
all five archived declarations as non-installable historical examples. The
table and identity boundary above summarize why none is a valid controller
runtime or scheduler declaration, and identify the contracts required before
any new workspace or worker integration is considered.

The detailed review remains in the private project history. This public
summary stands on its own and requires no access to private records.
No native installation or production identity is authorized by this directory.
