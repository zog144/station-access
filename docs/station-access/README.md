# station-access technical manual

This manual groups station-access documentation into lasting technical topics instead of chronological feature notes. The original detailed documents remain intact while their requirements, contracts, examples, and historical status claims are reconciled.

## Architecture at a glance

Station-access is the **React/Django network-facing presentation and administration boundary**, not a second host controller or compiler owner. It holds browser sessions, user/workspace permissions, Host registry and credential-vault state, observational archive/DNS/provenance views, and constrained user-requested actions. The trusted local `zog.box_control` library manages workspace/application lifecycles; host-identify/host-discover produce signed Host evidence; host-deploy owns EC2 and compiler dispatch. Image-build publishes immutable software to be consumed by the controller.

A production installation keeps immutable Python/frontend runtime bytes **separate** from durable station SQLite/secrets and the archive-mirror application's independently owned object/catalogue STATE. Browser login does not convey machine-client Workspace API grants, VNC tokens, Ed25519 host identity, archive access grants or mTLS compiler-observer privileges. Each identity is scoped to its own transport and owner.

The manual's [API and contract reference](guide/api-and-contract-reference.md) distinguishes browser/session APIs from the read-only machine-client Workspace API and the separately configured mTLS compiler-observation bridge. [Workspaces](guide/workspaces-and-application-runtime.md), [Hosts](guide/hosts-and-enrollment.md), [DNS](guide/registries-dns-and-cloud-credentials.md) and [Deployment](guide/deployment-and-gateway-integration.md) explain the corresponding state/evidence bases. CI and a tested source contract are not proof of a production cutover.

## Chapters

- [Portal, users and roles](guide/portal-users-and-roles.md)
- [Workspaces and application runtime](guide/workspaces-and-application-runtime.md)
- [Hosts and enrollment](guide/hosts-and-enrollment.md)
- [Deployment and gateway integration](guide/deployment-and-gateway-integration.md)
- [Registries, DNS and cloud credentials](guide/registries-dns-and-cloud-credentials.md)
- [Provenance and licensing](guide/provenance-and-licensing.md)
- [Operations and recovery](guide/operations-and-recovery.md)
- [API and contract reference](guide/api-and-contract-reference.md)

## References and traceability

The [traceability map](TRACEABILITY.md) identifies detailed source documents and their target chapters. Versioned machine-readable contracts, schemas, operational examples and verification records retain their independent paths. For current executable behavior consult the repository's root README and implementation.
