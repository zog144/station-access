# station-access: public source development rules

This source belongs to the Zog station-access component. The canonical
public repository is `zog144/station-access`; the component is imported as
`zog.station_access` within the project-wide `zog` Python namespace.

## Source changes

- Submit ordinary source development through reviewed `unstable` commits.
  `main` promotion requires explicit approval; use non-forced updates.
- The public source must never contain deployment state, passwords, token
  values, SSH/TLS private keys, source-archive caches, generated wheels,
  frontend `dist`, `node_modules`, host-specific service credentials,
  historical private handoff manifests, or independent execution evidence.
- Regular ChatGPT development chats use the connected GitHub plugin for source
  operations; Git-capable Work environments can run isolated checkouts and
  tests. Version-share is the existing *privileged installer* provenance
  path until a separately reviewed Git-source adapter is accepted.
- Keep source tests, database migrations, public licensing texts and complete
  third-party notice inputs in this repository. Do not silently discard old
  Django migrations or reinterpret a missing producer as proof of readiness.

## Dependencies and CI

- The ten companion source revisions are pinned in
  `public-companion-pins.json`. A candidate is not a production or CI
  acceptance: consumer tests must pass against exact, immutable public
  Git commits before that manifest's status may become `accepted`.
- Never fall back to historical `*-old` repositories, moving Git refs,
  a bare package name from PyPI, or a private-token checkout.
- Public GitHub Actions use read-only repository access and unprivileged
  source-only Django, Python, React, license-evidence, wheel and static
  checks. Native systemd, PAM/greetd, VNC, AWS/SSM, ACME/DNS and controller
  grant acceptance remain separately authorized Work tests.
- Build with Node 24/npm 11.9 and use `npm ci` from the committed lockfile.
  Generated frontend notices must accompany the actual published bundle.

## Licensing and runtime authority

Station-access-owned original source, documentation and artwork for this new
public export use `BSD-3-Clause OR GPL-3.0-only`. The complete legal texts
are retained in `LICENSES/`, and third-party licenses remain independent.
This statement does not rewrite the original private development records or
grant rights to independently authored components.

Station-access is the user-facing observer and orchestrator, not the owner of
host provisioning, immutable rootfs compilation, archive leases, protected
Cloudflare token delivery, DNS writes, privileged certificate installation or
controller-execution identities. Keep mutable persistent state distinct from
immutable application software views. The production application uses the
controller-owned `execution_identity="application"` contract; any legacy
remote-VNC fixture referring to `regular` is *not* a host account provision.
Never use a remote VNC session as a local greetd/PAM seat.

Do not claim public publication, Actions pass or live host cutover until exact
source revision, tests and owner acceptance provide separate evidence.
