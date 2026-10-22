# station-access documentation traceability

**Migration stage:** chapter navigation added; no original source is deleted or reclassified as deployed behavior.

| Existing document | Canonical chapter(s) | Treatment |
|---|---|---|
| [APPLICATION-SOFTWARE.md](APPLICATION-SOFTWARE.md) | Workspaces and application runtime | Detailed original retained; review unique requirements and status |
| [ARCHIVE-AUTHORIZATION.md](ARCHIVE-AUTHORIZATION.md) | Deployment and gateway integration | Detailed original retained; review unique requirements and status |
| [ARCHIVES-API.md](ARCHIVES-API.md) | Deployment and gateway integration; API and contract reference | Detailed original retained; review unique requirements and status |
| [BOX-CONTROL-ADAPTER.md](BOX-CONTROL-ADAPTER.md) | Workspaces and application runtime; API and contract reference | Detailed original retained; review unique requirements and status |
| [BOX-CONTROL-LOGS.md](BOX-CONTROL-LOGS.md) | Workspaces and application runtime | Detailed original retained; review unique requirements and status |
| [CLOUD-CREDENTIALS.md](CLOUD-CREDENTIALS.md) | Registries, DNS and cloud credentials | Detailed original retained; review unique requirements and status |
| [DEPENDENCIES.md](DEPENDENCIES.md) | Portal, users and roles | Detailed original retained; review unique requirements and status |
| [DEPLOYMENT-JOBS.md](DEPLOYMENT-JOBS.md) | Deployment and gateway integration | Detailed original retained; review unique requirements and status |
| [DNS-DESTINATIONS.md](DNS-DESTINATIONS.md) | Registries, DNS and cloud credentials | Detailed original retained; review unique requirements and status |
| [DNS-EVIDENCE.md](DNS-EVIDENCE.md) | Registries, DNS and cloud credentials | Detailed original retained; review unique requirements and status |
| [DNS-MEMBERSHIP.md](DNS-MEMBERSHIP.md) | Registries, DNS and cloud credentials | Detailed original retained; review unique requirements and status |
| [DNS-SETUP.md](DNS-SETUP.md) | Portal, users and roles; Registries, DNS and cloud credentials | Detailed original retained; review unique requirements and status |
| [FRONTEND-INSTALLATION.md](FRONTEND-INSTALLATION.md) | Portal, users and roles; Operations and recovery | Detailed original retained; review unique requirements and status |
| [FRONTEND-LICENSE-REVIEW.md](FRONTEND-LICENSE-REVIEW.md) | Portal, users and roles; Provenance and licensing | Detailed original retained; review unique requirements and status |
| [GENERATION-PROVENANCE.md](GENERATION-PROVENANCE.md) | Hosts and enrollment; Provenance and licensing | Detailed original retained; review unique requirements and status |
| [HOST-GENERATION-AND-EXPORT.md](HOST-GENERATION-AND-EXPORT.md) | Hosts and enrollment | Detailed original retained; review unique requirements and status |
| [MANAGED-SESSION-RECOVERY.md](MANAGED-SESSION-RECOVERY.md) | Operations and recovery | Detailed original retained; review unique requirements and status |
| [MANAGED-SESSIONS.md](MANAGED-SESSIONS.md) | Operations and recovery | Detailed original retained; review unique requirements and status |
| [MIRROR-STARTUP-CONTRACT.md](MIRROR-STARTUP-CONTRACT.md) | Deployment and gateway integration | Detailed original retained; review unique requirements and status |
| [PORKBUN-ONBOARDING.md](PORKBUN-ONBOARDING.md) | Registries, DNS and cloud credentials | Detailed original retained; review unique requirements and status |
| [PORTAL.md](PORTAL.md) | Portal, users and roles | Detailed original retained; review unique requirements and status |
| [PROVENANCE-ENCOUNTERS.md](PROVENANCE-ENCOUNTERS.md) | Provenance and licensing | Detailed original retained; review unique requirements and status |
| [PYPI-NAMESPACE.md](PYPI-NAMESPACE.md) | Portal, users and roles | Detailed original retained; review unique requirements and status |
| [REGISTRIES-DEPLOYMENTS.md](REGISTRIES-DEPLOYMENTS.md) | Deployment and gateway integration; Registries, DNS and cloud credentials | Detailed original retained; review unique requirements and status |
| [REGISTRY-REMOVAL-MATCHING.md](REGISTRY-REMOVAL-MATCHING.md) | Registries, DNS and cloud credentials | Detailed original retained; review unique requirements and status |
| [ROLES-VAULT-ADMIN.md](ROLES-VAULT-ADMIN.md) | Portal, users and roles | Detailed original retained; review unique requirements and status |
| [SETUP-READINESS.md](SETUP-READINESS.md) | Portal, users and roles; Hosts and enrollment | Detailed original retained; review unique requirements and status |
| [SIGNED-HOST-PROTOCOL.md](SIGNED-HOST-PROTOCOL.md) | Hosts and enrollment | Detailed original retained; review unique requirements and status |
| [STATION-PRODUCTION-CUTOVER.md](STATION-PRODUCTION-CUTOVER.md) | Operations and recovery | Detailed original retained; review unique requirements and status |
| [USERS-AND-RELEASE.md](USERS-AND-RELEASE.md) | Portal, users and roles | Detailed original retained; review unique requirements and status |
| [VNC-WORKSPACES.md](VNC-WORKSPACES.md) | Workspaces and application runtime | Detailed original retained; review unique requirements and status |
| [WEBSOCKIFY.md](WEBSOCKIFY.md) | Workspaces and application runtime | Detailed original retained; review unique requirements and status |
| [WORKSPACE-AGENT-API.md](WORKSPACE-AGENT-API.md) | Workspaces and application runtime; API and contract reference | Detailed original retained; review unique requirements and status |
| [WORKSPACE-PROVENANCE.md](WORKSPACE-PROVENANCE.md) | Workspaces and application runtime; Provenance and licensing | Detailed original retained; review unique requirements and status |
| [integration/IMAGE-BUILD.md](integration/IMAGE-BUILD.md) | Deployment and gateway integration | Detailed original retained; review unique requirements and status |

**Coverage:** 35/35 existing Markdown documents assigned. Machine-readable schemas/examples remain at their existing paths. A later consolidation must validate internal links, exact contract versions, historical claims and tests before removing duplicates.

## Editorial consolidation progress — 2026-10-12

This pass replaces the listed canonical chapter placeholders with substantive summaries of current source contracts. The original reference documents remain at their stable paths for exact schemas, historical status and implementation-specific details. A synthesized chapter is not yet a deletion authorization for any referenced file.

| Synthesized reader chapter | Primary preserved evidence | Status |
|---|---|---|
| [Portal, users and roles](guide/portal-users-and-roles.md) | PORTAL.md · USERS-AND-RELEASE.md · ROLES-VAULT-ADMIN.md · SETUP-READINESS.md | Reader synthesis committed; original detail preserved |
| [Workspaces and application runtime](guide/workspaces-and-application-runtime.md) | VNC-WORKSPACES.md · WORKSPACE-AGENT-API.md · APPLICATION-SOFTWARE.md · BOX-CONTROL-LOGS.md | Reader synthesis committed; original detail preserved |
| [Provenance and licensing](guide/provenance-and-licensing.md) | GENERATION-PROVENANCE.md · PROVENANCE-ENCOUNTERS.md · WORKSPACE-PROVENANCE.md · FRONTEND-LICENSE-REVIEW.md | Reader synthesis committed; original detail preserved |

**Editorial boundary:** The remaining manual chapters still need full synthesis. The retained documents must be compared line-by-line for unique requirements, example validity, duplicate claims, implemented-versus-historical status and explicit acceptance evidence before any source deletion. Machine-readable schemas and release provenance remain standalone. Source change does not establish production deployment or stable-release readiness.

## Editorial consolidation progress — 2026-10-12, continuation

The following chapter entry points now contain substantive synthesis of the preserved detailed sources. Unique versioned contracts, source evidence and historical acceptance declarations remain under their existing paths; the prose has **not** authorized deletion of any original document or production deployment.

| Reader chapter | Important preserved sources | Status |
|---|---|---|
| [Deployment and gateway integration](guide/deployment-and-gateway-integration.md) | DEPLOYMENT-JOBS.md · STATION-PRODUCTION-CUTOVER.md · PRODUCTION-STATE-MIGRATION.md · integration/IMAGE-BUILD.md | Synthesized; detailed contract retained |
| [Operations and recovery](guide/operations-and-recovery.md) | VNC-WORKSPACES.md · BOX-CONTROL-LOGS.md · ARCHIVES-API.md · SIGNED-HOST-PROTOCOL.md | Synthesized; detailed contract retained |

**Unresolved editorial work:** Reconcile source claims and examples against the current implementation before replacing detailed files; complete the remaining chapter summaries; audit duplicate or superseded requirements separately from live acceptance. This is documentation review, not a component release candidate.

## Editorial consolidation progress — 2026-10-12, enrollment and contracts

Two further reader chapters replace placeholders with reviewed conceptual synthesis. Detailed source contracts and immutable schemas remain at their original paths, including older dated implementation and acceptance reports. Where later sources supersede an earlier limitation, the consolidated chapter names the change in scope without deleting the historical evidence.

| Consolidated chapter | Preserved contract or evidence | Treatment |
|---|---|---|
| [Hosts and enrollment](guide/hosts-and-enrollment.md) | SIGNED-HOST-PROTOCOL.md · HOST-GENERATION-AND-EXPORT.md · MANAGED-SESSIONS.md · REGISTRY-REMOVAL-MATCHING.md | Synthesis committed; original authoritative sources retained |
| [Registries, DNS and cloud credentials](guide/registries-dns-and-cloud-credentials.md) | REGISTRIES-DEPLOYMENTS.md · CLOUD-CREDENTIALS.md · DNS-EVIDENCE.md · DNS-MEMBERSHIP.md · DNS-SETUP.md · DNS-DESTINATIONS.md | Synthesis committed; original authoritative sources retained |

**Evidence boundary:** This editorial work makes no production cutover, host mutation, rootfs publication, source-pin update or new acceptance claim. Remaining chapters and line-by-line reconciliation of redundant historical notes are separate tasks.

## Requirement-family reconciliation — 2026-10-12

The machine-client API, browser APIs, signed Host ingestion and mTLS compiler observer have different principals. Consolidating their descriptions does not merge their security/authorization contracts.

| ID and requirement family | Reader synthesis | Retained detailed sources | Deduplication disposition |
|---|---|---|---|
| **SA-UI-01** — Browser/session permission, Workspace ownership, private state and CRUD | [Portal/users](guide/portal-users-and-roles.md), [Architecture](README.md) | [Portal](PORTAL.md), [Roles/vault](ROLES-VAULT-ADMIN.md) | Retain exact Django UI/API and vault semantics |
| **SA-AGENT-02** — Read-only Workspace API, exact grants and ownership-snapshot invalidation | [API reference](guide/api-and-contract-reference.md) | [Workspace API](WORKSPACE-AGENT-API.md), [JSON schema](contracts/workspace-agent-v1.schema.json) | Preserve machine-readable schema/examples and v0.1.1 HTTP acceptance |
| **SA-RPC-03** — mTLS read-only compiler observer and immutable owner epoch | [API](guide/api-and-contract-reference.md), [Deployment](guide/deployment-and-gateway-integration.md) | [Compiler observer](COMPILER-OWNER-RPC.md) | Keep exact producer pin and host-deploy live acceptance gap; never merge observer with gateway writer |
| **SA-HOST-04** — Signed Host enrollment, generation evidence, approval and archival dependencies | [Hosts](guide/hosts-and-enrollment.md) | [Signed protocol](SIGNED-HOST-PROTOCOL.md), [Host generation](HOST-GENERATION-AND-EXPORT.md), [Matching](REGISTRY-REMOVAL-MATCHING.md) | Keep signed request/response profile and versioned exports |
| **SA-DNS-05** — DNS evidence, reservation, membership, unpublish/release and provider authority | [DNS](guide/registries-dns-and-cloud-credentials.md) | [Old registries](REGISTRIES-DEPLOYMENTS.md), [Porkbun onboarding](PORKBUN-ONBOARDING.md), [DNS membership](DNS-MEMBERSHIP.md), [Destinations](DNS-DESTINATIONS.md) | Old provider limitations are date-scoped; preserve later ledger and provider-specific contracts |
| **SA-CUT-06** — Independent station/archive persistent ownership, restricted host exports and cutover | [Deployment](guide/deployment-and-gateway-integration.md), [Recovery](guide/operations-and-recovery.md) | [Older cutover](STATION-PRODUCTION-CUTOVER.md), [Separate state](PRODUCTION-STATE-MIGRATION.md) | Later design supersedes older single-application composition; retain older handoff as historical, no live cutover inference |
| **SA-EVID-07** — Generation/workspace provenance, patch/license gaps, exact archive snapshot | [Provenance](guide/provenance-and-licensing.md), [API](guide/api-and-contract-reference.md) | [Generation](GENERATION-PROVENANCE.md), [Workspace](WORKSPACE-PROVENANCE.md), [Archives](ARCHIVES-API.md) | Keep read-only evidence binding, scope and Unknown states |

**Retirement gate:** Before removing a source file, enumerate every `MUST`, `MUST NOT`, API field, error/status meaning, request identity, example path, test limit, unique historical result and licensing notice. Verify each surviving destination against the exact reviewed implementation and version. Keep an immutable know-file reference for dated evidence, update all inbound links, run source/packaging checks, and obtain an explicit commit review. No original documents are retired by this matrix.
