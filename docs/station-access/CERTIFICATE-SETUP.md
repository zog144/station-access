# Station HTTPS certificate setup — source consumer contract

**Date:** 2026-10-14. **Producer:** `zog144/certify-manage` at
`a495932b103f8cc4855218b2a709116a32aeb753`, contract
`zog-certify-manage-v1`. **Status:** Station administrator proposal and
fail-closed status UI only. No live host-owner request or delivery API yet.

## Responsibilities and boundaries

Station-access is **not a certificate authority or an nginx controller**.
Its admin-only `GET/POST /api/setup/certificates/` accepts exactly a
revisioned **operator proposal** for the fixed certificate
`station-web`. The proposal is validated with
`zog.certify_manage.model.Authorization.from_dict`, preserving the
issuer's canonical hostname, email, explicit ACME directory, challenge
and DNS-plugin rules. A proposed hostname is **not** the protected,
administrator-issued host-owner policy that certify-manage's CLI
requires. It cannot authorize issuance, renewal, preparation,
challenge ingress, archive role selection or certificate publication.

The persisted row is `host_registry.CertificateSetupProposal`, database
migration `0014`; it belongs to station's persistent SQLite state and
is protected by the station administrator session/CSRF and optimistic
revision check. Only one hostname and the fixed `station-web` ID are
permitted in this initial UI. No token, PEM, private key, custom Certbot
flag, filesystem path or arbitrary service ID is accepted or stored.
An operator may explicitly select HTTP-01 or DNS-01/Cloudflare; the
controller later provisions the **separate** DNS credential and
approved challenge route. The UI never guesses a public FQDN or ACME
directory, and no production/staging directory is implicitly selected.

The API's read-only response is `zog-station-certificate-setup-v1`.
Owner request is `unavailable`. Certificate health, expiration,
fingerprint and renewal status are **not observed**. `issued`,
`delivered`, `nginx_loaded`, `browser_verified` are distinct
`not_observed` states; `https_readiness=not_verified`. The
separation is intentional: a locally valid SAN/expiry does not prove
that nginx loaded a certificate, nor that a browser trusts the
current public endpoint. No expiration values, fingerprints or
renewal failures are invented. The page and Setup readiness share
this fail-closed interpretation.

`POST /api/setup/certificates/request/` refuses every payload,
including prepare, issue and reconcile, with HTTP 503
`owner-interface-unavailable` and `safe_to_issue=false`.
It does not create an operation, use Certbot, call arbitrary CLI,
invoke the host controller, publish to nginx, or alter the archive
scheduler. This is a deliberate **integration gate**, not a working
issuance request. Host-deploy must publish a versioned authenticated,
scoped owner request and read-only certificate observations contract
before replacing this refusal. A station-access web superuser is
not automatically authorized to invoke the host certificate issuer.

The existing station compiler observer mTLS certificate is a
*different identity* with only compiler.status/dispatch.status
scope; it must never be reused as ACME issuer, publisher, nginx,
DNS provider or host-owner certificate-management credentials.

## Future host-owner binding and acceptance

Owner implementation must give the station an explicitly approved
certificate ID and host policy version, a bounded request-ID based
prepare/issue/reconcile capability, and a **separate** redacted,
authenticated observation stream. Return issuance health and expiry,
renewal attempts/failures, private delivery generation, nginx-loaded
generation and independently verified external HTTPS trust as distinct
fields, with observed timestamps and stale/unavailable semantics.
Never have station infer a positive state from a local file, saved
proposal, certificate SAN or issuance CLI exit code. Recheck policy,
grant, provider authorization and current owner state before accepting
each operation. On lost replies/restart reconcile by durable request ID,
not duplicate ACME orders. No application-supplied raw Certbot args,
private certificates, publication paths or nginx reload permissions.

Host-deploy decides the **restricted pre-HTTPS bootstrap channel**
and external TLS/port-80/443 routes; station-access does not open a
public unauthenticated fallback. First boot on a headless server needs
equivalent operator proposal/status through an authenticated management
path. Host-install owns durable enablement ordering, controller grants,
software view selection and policy provisioning. Certify-manage owns
issuer-only state and private staging. Host-deploy owns certificate
delivery, nginx config validation, reload/rollback and live external
HTTPS acceptance. A certificate candidate cannot change archive
roles or the retained compiler writer.

## Tests and source-only evidence

```sh
python tools/test-backend.py tests.host_registry.test_certificate_setup
python tools/test-backend.py tests.host_registry.test_readiness
npm ci --prefix frontend
npm test --prefix frontend -- --run
```

The test suite exercises exact producer policy validation, no
implicit authority, CSRF/authentication, optimistic revisions,
nonsecret response surfaces, refusal of every owner action,
noninterference with DNS, mirror role and host jobs, as well as the
form's independent lifecycle displays. Real ACME/DNS-01 or HTTP-01,
host grants, protected issuer policy bindings, owner API,
certificate publication, nginx reload and external TLS validation
remain separate live acceptance requirements. **No production
cutover is authorized by this consumer implementation.**
