# Setup readiness and provider checks — station-access 0.4.3

This pass builds on workspace-launcher commit `f4a0486978400b41379bf3645331f20f77ba26b8` from `unstable`. It preserves the workspace launcher guard and existing Registries/Deployments features. The beaconer and host-deploy bundle were unchanged in that historical pass. Current source ownership and installation are described in [DEPENDENCIES.md](DEPENDENCIES.md).

## Administration → Setup readiness

`/setup` reads `/api/setup/readiness/`, restricted to authenticated superusers. It examines local configuration and database observations only. It does not call AWS, Cloudflare, a beacon endpoint or box-control, acquire the DNS writer lock, reconcile state, create keys, or start services. Refreshing the page performs no application-data mutation.

The page distinguishes:

- **Configured:** an input is saved or a configuration file is present/readable; service operation has not been established.
- **Recently observed:** a recorded observation meets the stated freshness criteria. Its evidence timestamp is displayed.
- **Needs attention:** failed, stale, missing or inconsistent inputs/observations need inspection.
- **Not configured / Not checked:** configuration or a verification facility is absent.
- **Blocked:** the current source explicitly disables a capability pending a dependency contract.

Checks cover administrator accounts, protected vault, public HTTPS settings, cached provider checks, beacon destination intent, DNS controller binding/credential availability, AWS inventory, signed reports, DNS reconciliation, controller project configuration, workspace launch, archive issuer configuration, mirror readiness reports, and backup/recovery. Grouping separates local-station, central-registry and optional-service concerns. There is deliberately no aggregate “installation ready” score: not every station needs every optional service, and configured values do not prove operational success.

Observation limits are ten minutes for inventory/DNS, three minutes for signed host and mirror reports, and fifteen minutes for successful provider checks. Future timestamps are not accepted as fresh. Saved destination lists remain installation intent, without a claim that beaconers have installed them. Certificate renewal, firewall reachability, rootfs integrity, daemon health, archive download acceptance and backup recoverability remain explicit unchecked items.

The workspace-launcher blocker follows the existing `workspace_applications.LAUNCH_BLOCK` declaration. Do not enable launch merely because a project directory exists. Readiness needs to evolve with the box-control attachment contract rather than bypass it.

## Registries → Check access and list domains

This explicit administrator action makes one Cloudflare `GET /zones` request, filtered by the saved account ID, page 1, maximum 50 zones. It uses network-register's HTTPS client and redirect rejection. It never calls a DNS mutation, domain purchase, token-creation or account-management endpoint. Visiting Registries alone does not make this request.

The list represents **Cloudflare zones visible to this credential**, not proof of registrant ownership or a complete registrar purchase inventory. A successful read cannot establish DNS-write permission. An empty result does not confirm account access. Additional pages are reported as available rather than silently claiming completeness.

The upstream contract is documented at https://developers.cloudflare.com/api/resources/zones/methods/list/ : the endpoint accepts Zone Read permission and an account-ID filter. Missing read scope, a wrong account, revocation or a transport failure may all prevent this diagnostic. This is not a reason to grant broader privileges automatically; preserve the least privileges required for the intended DNS operations.

`POST /api/setup/registries/<credential UUID>/check/` requires CSRF and the displayed credential revision. One row per provider credential records attempt ID, revision, timestamps, status and a bounded sanitized domain list. No token, raw provider response or raw error string is persisted or returned. Domain records must identify the same account; foreign-account or malformed results are rejected. Provider errors become fixed, nonsecret diagnostic messages.

A durable per-account cooldown is 60 seconds. A 60-second global check lease prevents ordinary simultaneous checks across accounts. The existing network-register request timeout is 40 seconds, with no automatic replay. Database/security locks are released before network I/O. A worker interrupted during a check can be retried after the lease expires. Attempt IDs prevent a late result overwriting a newer attempt; credential revision checks prevent a result for a replaced credential being shown as current. No access-token authorization or DNS selection changes as a result of the check.

GET responses re-evaluate evidence age. The frontend shows check timestamps, stale evidence and first-page truncation, and offers refresh. Failed readiness refreshes clear the old display. Porkbun remains explicitly unsupported by the provider adapter; no check is attempted.

## Migration and deployment

Apply `host_registry.0008_provider_access_checks` before switching application code. This only adds the provider-check table; existing credentials, identities, hosts, DNS ownership and workspace data are unchanged. Back up the database and deploy the rebuilt frontend together with the backend. No new secret or environment setting is required. Rollback can restore the previous application code while leaving the additive check table in place.

This implementation pass was verified locally and published to `unstable`; it was not deployed to the live command center. Provider verification used fixtures, not the live Cloudflare account. Historical live beacon override evidence was retained privately and is not part of this public manual; current source behavior is governed by [REGISTRIES-DEPLOYMENTS.md](REGISTRIES-DEPLOYMENTS.md).

## Validation

182 Django tests passed: 117 registry/security/setup and 65 station/workspace tests. 51 frontend tests passed and the production build succeeded. New tests cover permissions/CSRF, explicit read-only request selection, revision races, attempt replacement, cooldown and expired leases, future/stale observations, no transaction held during provider I/O, fixed error redaction, foreign-account rejection, empty/partial results, unavailable vault/provider, and read-only readiness without controller/network/database changes. Frontend tests cover status distinctions, failed-refresh clearing, explicit provider checking, stale/partial evidence and throttling.

## Open decisions and dependency blockers

| Work | What is unresolved | Suggested first scope |
| --- | --- | --- |
| Apply settings to hosts | Who executes deployments: central host-deploy/SSM jobs, or approved beaconers pulling desired configuration? How are completion and rollback acknowledged? | Explicit Apply to selected AWS hosts through host-deploy; preserve per-host revisions and report installation separately from heartbeat receipt. Local/on-premise transport can follow. |
| Domain and HTTPS bootstrap | Which existing domain/subdomain is authoritative, how an initial controller is bound, which certificate challenge is supported, and how a name change migrates ownership and clients. | Select an existing Cloudflare zone; do not purchase domains or rename existing assignments implicitly. |
| Multiple central hosts | Approval state, signing keys, replay state and DNS ownership need a shared durability/failover design. A URL list is not controller redundancy. | Keep one authoritative controller; additional destinations remain observation-only until leader selection and fencing are designed. |
| Cloud onboarding | Execution location, delegated account/role boundaries, region scope and eventual GCP support. | AWS role/SSM preflight first, with explicit target/account confirmation for provisioning. |
| Workspace launch | The box-control durable workspace/display/network attachment and namespace ownership contract is still a dependency. End-to-end graphical acceptance needs a suitable rootfs. | Integrate the agreed controller contract when delivered; retain the current launch guard meanwhile. |
| Archive/bootstrap | Persistent station-access application preparation/upgrade, issuer-key provisioning and storage/adapter wiring need end-to-end validation. | Verify one mirror and one approved consumer with existing scoped authorization before automation. |
| Porkbun | The external network-register 0.4.0 dependency supports credential checks and domain listing. | Automatic Porkbun DNS reconciliation remains unsupported here; use the pinned dependency set in [DEPENDENCIES.md](DEPENDENCIES.md). |
| Backup/recovery | Backup destination, retention, encryption-key custody, authorized restore operators and periodic restore tests. | An explicit encrypted off-host backup/restore workflow covering database and separately protected keys/controller state. |

The read-only readiness page can absorb new truthful observations as these contracts arrive. It must not convert unknown service states into green status solely to complete a checklist.
