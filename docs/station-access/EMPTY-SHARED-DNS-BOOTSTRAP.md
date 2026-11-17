# Fresh empty shared DNS-controller bootstrap

**Source-only candidate for station-access #5, stacked on PR #4.** This operator-controlled state machine serves a *previously unconfigured isolated station*. It does not migrate a real legacy writer or declare certificate authority for the enrolled generic Host.

## Protected admission before review

The authorized station deployment must explicitly configure HOST_DNS_CONFIGURATION to this fixed path:

    <STATION_ACCESS_STATE_DIRECTORY>/dns-controller/configuration.json

STATION_ACCESS_STATE_DIRECTORY must already exist, be service-owned and not be a symlink. The bootstrap exclusively creates only the fresh dns-controller subdirectory (0700), protected O_NOFOLLOW/0600 controller lock, fixed configuration and empty ledger. Operate as the station service UID.

Prerequisites:

- PR #4 exact source, dependencies and additive host_registry.0017 migration installed and attested on the retained isolated station, with database backup, original HostIdentity, managed admission, TLS CA and signer unchanged.
- Real active Django superuser established through supported administrator bootstrap; no direct ORM seeding.
- Genuine Cloudflare ProviderCredential encrypted under HOST_VAULT_CONFIGURATION and bound to the reviewed Cloudflare account and current revision. Never put its token in CLI arguments, GitHub, logs or evidence attachments.
- Exact Cloudflare account/zone and reserved DNS prefix independently selected by the authorized operator.
- No previously owned DNS assignment, additional destination, name grant, certificate assignment or local DNS controller. Preexisting legacy controllers use the separate existing migration path.
- Fresh account/zone/parent-delegation/SOA/complete record inventory checks. Provider GET is not DNS write permission; no provider write is attempted.

This path is separate from migrate_host_dns review/commit: that cutover requires a real legacy controller and nonempty AWS-backed host/A record evidence. No AWS identity or legacy record is synthesized.

## Protected CLI and exact operator decisions

Use the actual protected owner and vault metadata:

~~~sh
python manage.py bootstrap_empty_host_dns review \
  --owner '<active superuser numeric PK>' \
  --credential '<vault ProviderCredential UUID>' \
  --credential-revision '<current revision>' \
  --zone-id '<reviewed Cloudflare zone ID>' \
  --prefix-label hosts
~~~

The operation does read-only Cloudflare and DNS authority/inventory checks. The only initial lock provisioning is in this fresh protected bootstrap: it exclusively creates the mode-0600 controller.lock and durably binds its device/inode into controller-lock-identity.json. Subsequent bootstrap attempts and ordinary controller writers **must reopen exactly that inode** without recreating a missing or replaced pathname. Missing lock or identity, symlink, altered owner/mode, or inode drift is a blocking integrity fault requiring separate operator-reviewed recovery; existing legacy controllers need explicit protected lock adoption, never an implicit first-writer creation. It saves a hash-bound ten-minute review with nonce, and returns the reviewed account/zone/prefix, owner, credential revision, digest and expiry plus provider_writes=0 and unknown write permission. No host, record, token or signed policy is created.

**The authorized operator must inspect and separately approve this exact review receipt** before:

~~~sh
python manage.py bootstrap_empty_host_dns commit \
  --owner '<same active superuser PK>' \
  --review-id '<exact unexpired 64-hex review>'
~~~

Commit repeats current owner, credential, Cloudflare zone/delegation and full record inventory checks. It creates a network-register schema-v1 SqliteStateStore with exactly the reviewed connection/binding and *empty* record/operation inventory. The durable config is mode 0600. Only after the ledger and audit are independently verified does controller.json become writer=shared, stage=active under the original single-writer lock. The DB keeps nonsecret review/zone security audit.

A partial commit stays fenced. Before ledger creation the process saves a durable creating-ledger marker; if the database later cannot be found, **stop** rather than recreating it, even if the final config was not yet published. Before publishing writer=shared it attests the exact SQLite schema/meta, **one** reviewed connection, **one** reviewed binding and no additional record, operation, adoption, allocation, reservation, receipt, membership or unknown rows. The accepted ledger file is regular, non-symlink, service-owned, mode 0600; its device/inode identity is durably captured in the ledger-ready marker. If a complete ledger exists and commit was interrupted, the exact same review may be independently revalidated and resumed. On later shared-runtime reopen, original static ownership and file inode are verified while legitimate later membership history remains allowed. No generic reset, changed review ID, new cloud host or manually fabricated ledger is supported.

Read back installed bytes without any provider call:

~~~sh
python manage.py bootstrap_empty_host_dns inspect \
  --owner '<same active superuser PK>' \
  --review-id '<exact review ID>'
~~~

The inspect command authenticates the operator, review, committed marker, configuration file, ledger metadata, connection/binding and active shared-controller state, with provider_writes=0. In addition, reopen the ordinary dns_shared.open_runtime under the protected service; the primary controller must contain *zero* selected A-record hosts.

Record a native receipt with exact installed source/wheel, migration, service UID/GID, boot/InvocationID, original enrolled Host/installation/STATE/registry/fingerprint, protected file permissions and **zero provider writes**. Do not label source CI as native acceptance.

## Subsequent hostname review and separate approval

Only after successful native controller verification, the unchanged generic Host may proceed through PR #4 manage_managed_dns01_hostname review, using fresh managed session/admission, exact HostIdentity and protected Cloudflare credential/zone. The intended reviewed name is issuer-test.zog-network-demo.uk for Let's Encrypt staging DNS-01 (not an A-record destination). The hostname command performs independent read-only zone/namespace verification and returns its *own* short-lived receipt requiring a second explicit operator authorization before its own commit.

A hostname name grant is **not** a signed certificate assignment, DNS TXT/A record, Cloudflare token transfer, Certbot grant or permission to issue a certificate. Global signer activation, selected runtime, credential delivery, ACME, nginx and reboot remain separate acceptance gates.

## Protected pre-open ledger verification

Before any SQLite database connection during shared runtime, status or recovery, the station verifies the ledger file through an O_NOFOLLOW descriptor. It requires a single-linked regular file, service UID and mode 0600, matching pathname/device/inode, and the durable identity when available. An invalid path blocks without opening SQLite. Checks repeat after database readback. The service-owned protected directory and exclusive controller lock are required; native acceptance must verify exclusive service access and demonstrate that ledger substitution cannot be performed by another running process.

## Mandatory refusal conditions

- Existing controller/config/legacy assignment/ledger or double writer: **STOP**, never adopt, migrate or overwrite through this path.
- Missing/corrupt, foreign-owner, symlink or insecure directory, lock, ledger or config: **STOP**; never auto-repair.
- Review expiry before preparation; wrong operator/credential revision, Cloudflare account/zone, DNS namespace/delegation/inventory: **STOP**.
- Interrupted creation and missing ledger: **STOP**; no silent reconstruction of uncertain history.
- Any change to existing Host UUID, installation, STATE UUID, approved Ed25519 key, registry or managed session: **STOP**. This bootstrap does not write those objects.

**Native status: NOT RUN.** Keep station-access #5 open until the exact installed-byte and protected native readback receipts are accepted.
