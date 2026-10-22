# Registries, DNS and cloud credentials

## Separate credentials, authority and published records

Administration → Registries stores reviewed provider credential configurations; Cloud credentials stores AWS identities; Deployments records intended beacon destinations and bounded jobs. Saving credentials or configuration is **not** a provider write, registrar purchase, DNS ownership proof, or permission to provision an EC2 host. The component responsible for DNS operations is network-register, not arbitrary UI JavaScript.

Cloudflare and Porkbun have distinct account, API, and DNS capabilities. Older [Registries and Deployments](../REGISTRIES-DEPLOYMENTS.md) and [Porkbun onboarding](../PORKBUN-ONBOARDING.md) passes describe a Cloudflare-only station controller and Porkbun **read-only credential checks** at those revisions. Later [DNS membership](../DNS-MEMBERSHIP.md), [destination setup](../DNS-SETUP.md) and [additional destinations](../DNS-DESTINATIONS.md) introduce separate reviewed name-reservation/destination operations. These documents describe different **stages**, not one timeless provider-support table. Check the installed network-register version, bindings and active reconciler before claiming Porkbun publication is operational.

## Protected credential lifecycle

Registry provider secrets are encrypted using station-access's dedicated protected vault keyring, separately bound to provider/account/row revision. A password or API secret entered on the page is not returned through metadata, audit events or normal GET responses. Blank edits preserve existing secret values; a deliberate replacement must pass current-revision/CSRF checks. A database-only backup is insufficient to recover encrypted values without the separately backed-up vault keyring.

Cloud credentials distinguish AWS SDK default-chain resolution from explicitly saved keys. An explicit **Check AWS identity** call uses bounded regional STS `GetCallerIdentity` and checks the expected account; it does **not** prove EC2, SSM, billing or provisioning permissions. Temporary saved credentials have an expiry but no automatic rotation just because the operator entered that timestamp. Disabled entries do not revoke credentials at AWS or cancel ongoing jobs. Consult [Cloud credentials](../CLOUD-CREDENTIALS.md).

## Trusted DNS evidence before reconciliation

A target address is derived from approved, fresh **signed host** evidence reconciled against authoritative AWS inventory, not by simply trusting the beacon's public IP or a stale EC2 response. The [DNS evidence gate](../DNS-EVIDENCE.md) binds enrolled Host UUID/key, cloud account/region/instance, inventory address, current desired assignment/revision and freshness. A new migration cannot upgrade historical unsigned reports into trusted signed evidence; wait for fresh signed heartbeats and successful account/region scans. A failed scan, stopped host, revoked key, conflicting address or missing identity must block publication rather than guess.

The DNS writer is a centrally owned reconciler with durable ledger state, provider-specific authority checks and a single-writer boundary. A separate read-only readiness or "check access" action must not call provider mutation APIs. Before a new controller is activated, explicitly review/adopt legacy record identity and disable the former writer; two concurrent writers over the same names are an integrity risk.

## Names, membership and controlled lifecycle

A DNS name reservation is not the mutable Host display label. The [shared membership workflow](../DNS-MEMBERSHIP.md) uses review/confirm to reserve a label for an exact approved host; this creates durable publication intent. The shared worker independently rechecks evidence before writing A records. **Unpublish** records intent while keeping name ownership. **Release** is a separate reviewed operation after confirmed provider absence, preserving tombstones, allocation generation and security audit evidence. Archiving or deleting a host cannot bypass outstanding DNS ownership and assignment blockers.

[Additional destinations](../DNS-DESTINATIONS.md) permit separately bound provider/domain ledgers and revisions for one host. Destination-specific reserve, enable, unpublish, cancel (only an uncommitted reservation) and release require exact state and authorization. A partial write between provider/ledger/database layers must be recovered from the same operation; removing metadata to "clear" a conflict is unsafe. Existing destinations with owned ledgers require explicit reviewed import; the UI cannot silently adopt foreign records.

## Provider setup and bounded diagnostics

[DNS setup](../DNS-SETUP.md) defines the reviewed selection of an empty zone and current credential binding. Read-only inspection of credentials or provider inventory cannot prove write access or registrant ownership. Cloudflare DNS policy and Porkbun policy may differ in TTL and permissible operations; follow the exact provider's implemented contract rather than assuming interoperability from a displayed domain. [DNS destinations](../DNS-DESTINATIONS.md) describes the distinction between GUI host actions and operator-only destination installation.

Administration → Deployments saves registry destination intent separately from actual beacon installation. Only a reviewed, identity-bound and time-limited [deployment job](../DEPLOYMENT-JOBS.md) can apply a supported destination change on an already owned host; worker receipt does not prove the newly added registry has accepted a signed heartbeat.

## Failure handling and checklist

1. Verify the selected provider, account/zone identity, vault readiness, credential revision and purpose-specific scope.
2. Validate the current enrolled key, authenticated host/AWS inventory agreement, DNS owner epoch, desired revision and name availability.
3. Distinguish a **review**, a **reservation**, a **pending provider write**, a **published record**, **unpublish intent** and **confirmed release**.
4. On an uncertain provider result, recover the existing ledger/operation and avoid duplicate or contrary mutations.
5. Before archiving a host, unpublish/release every owned destination and resolve independent key, archive and token blockers.
6. Preserve ledgers, registry database and protected vault backups as a coordinated recovery unit.

### Authoritative material

- [Registries and Deployments](../REGISTRIES-DEPLOYMENTS.md)
- [Cloud credentials and bounded AWS diagnostics](../CLOUD-CREDENTIALS.md)
- [Trusted DNS evidence gate](../DNS-EVIDENCE.md)
- [Shared DNS reservation and release](../DNS-MEMBERSHIP.md)
- [DNS destination setup](../DNS-SETUP.md)
- [Additional destination lifecycle](../DNS-DESTINATIONS.md)
- [Porkbun onboarding historical limits](../PORKBUN-ONBOARDING.md)
- [Host archival dependency checks](../REGISTRY-REMOVAL-MATCHING.md)

This chapter unifies concepts without asserting that source-only changes have been cut over on the current command center.

## Read-only DNS reconciliation inspection (October 2026)

An administrator may manually inspect the assigned primary or additional DNS
destination from the host DNS panel. The GET endpoints
`/api/hosts/<host-id>/dns-preview/` and
`/api/hosts/<host-id>/dns-destinations/<binding-id>/preview/` use
the pinned `network-register` `DnsEngine.preview()` contract.
Station-access selects trusted host evidence, destination, desired state
and revision on the server; browser input cannot supply a desired address,
provider credentials, publication action or a controller operation ID.

The response is a bounded, sanitized `schema=1, read_only=true` preview:
`candidate`, `no-op` or `blocked` with a reason and, if inspected,
the matching provider inventory. A missing inventory
(`observed_count=null`) is **not** proof that the name is absent.
A candidate does not reserve, prepare, submit, cancel or replay a
mutation. Actual writes remain the separately reviewed central worker
and must revalidate the original authority and ledger. The preview
checks the retained administrator ownership, controller writer state,
host verification, provider authority and scope after provider reads.
Denied or stale evidence fails closed with no raw provider errors.

Read-only inspection still performs remote provider **GET** operations.
It is intentionally user-triggered, never auto-polled, and requires an
administrator session. Responses are no-store. The frontend never shows
an "Apply preview" button. The source-only integration does not claim
live provider connectivity, public DNS propagation, production adoption
or cutover.
