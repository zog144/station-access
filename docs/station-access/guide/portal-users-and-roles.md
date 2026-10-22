# Portal, users and roles

## Station-access is a network-facing presentation boundary

Station-access is the React/Django browser interface for Zog workspaces, applications, invocation-scoped logs, host administration and provenance. Django calls box-control through its trusted **local Python interface**; the browser never receives arbitrary direct controller/systemd access. User permissions, authenticated host evidence and privileged controller operations are different trust boundaries.

The source guide's [portal documentation](../PORTAL.md) describes the current local launcher and configuration. With the compatible Python environment, `python serve.py --state-directory /absolute/private/station-state` initializes database state and can serve the application. An initialization-only mode prepares state without serving. The first administrator is created only for a database with no users; existing users/passwords must survive subsequent startup. The same STATE directory is needed for management commands. Merely starting Django does **not** install a rootfs, TLS, TurboVNC, websockify or a ready workspace controller.

## State and deployment are explicit

SQLite, deployment secrets, credential vault material and workspace locks belong to a writable **deployment state** location, not source, the Python wheel or immutable application artifacts. The source's configuration variables distinguish trusted project paths, allowed HTTPS hosts/CSRF origins, proxy trust and optional archive/vault/DNS services. Frontend source is compiled during image/application construction; the Python runtime must not need Node/npm or a mutable frontend build directory to serve production assets. See [frontend installation](../FRONTEND-INSTALLATION.md) and [immutable application software](../APPLICATION-SOFTWARE.md).

## Readers, administrators and credential access

Ordinary authenticated workspace owners may view only their authorized workspaces, applications and runtimes; administrator-only surfaces include global application-software inspection, build logs, registry credentials and some generation details. Access checks precede controller reads where appropriate. The host-card vault stores protected credentials outside the database encryption context; an administrator's deliberate reveal is audited, time-limited and returned with `Cache-Control: no-store`. The vault key must be backed up separately and never packaged into a reusable image. See [host roles and vault](../ROLES-VAULT-ADMIN.md) and [user administration](../USERS-AND-RELEASE.md).

Authentication to the browser does **not** grant access to station-access's separate Workspace API credential or a future compiler mutation principal. Issued machine-client grants are scoped, time-bounded, tied to exact workspace identities, revocable, and distinct from noVNC grants. See [Workspace API](../WORKSPACE-AGENT-API.md).

## Setup readiness is evidence, not a deployment verdict

Administration → Setup readiness distinguishes configured inputs from recently observed services, missing/not-checked capabilities, blocked dependencies and stale evidence. It is observational and does not call AWS, deploy software, reconcile DNS or activate a desktop merely because the page is viewed. There is intentionally no single global installation-ready score: optional features differ by deployment. See [readiness categories and limits](../SETUP-READINESS.md).

## Operator and development entry points

- [Portal startup, configuration and API boundaries](../PORTAL.md)
- [Dependency and runtime constraints](../DEPENDENCIES.md)
- [Frontend installation and compiled assets](../FRONTEND-INSTALLATION.md)
- [Administrative users, releases and host credentials](../USERS-AND-RELEASE.md)
- [Role/vault evidence and operational cautions](../ROLES-VAULT-ADMIN.md)
- [Readiness checks](../SETUP-READINESS.md)

Specific historical acceptance versions in these references are retained as evidence; they do not independently certify the current running production instance.
