# Hosts and enrollment

## Host identity, authentication, and approval

A Host is a durable registry identity, not a mutable display label, AWS instance ID, public IP address, or DNS record. Host-install and host-identify are responsible for the persistent installation identity and per-host Ed25519 key; host-discover transports signed evidence; station-access is the registry, approval, and read-side administration boundary.

HTTPS authenticates the station endpoint and protects transport. An RFC 9421 host signature demonstrates possession of the private key, **not** approval or permission to control infrastructure. The administrator must explicitly approve the exact key fingerprint for the immutable Host UUID. Neither claimed AWS properties nor a matching label can substitute for that approval. A changed or revoked key needs fresh approval and fresh evidence. Browser login/CSRF, machine-key signatures, and separate archive access tokens are three independent authorization domains.

The [signed-host protocol](../SIGNED-HOST-PROTOCOL.md) defines the closed signature profile, request body and replay protection, host-key persistence, enrollment, signed heartbeat admission, revocation ordering and token boundaries. An earlier bearer migration is historical; do not treat a bearer report as signed evidence or allow it to overwrite signed-only fields.

## Enrollment and matching existing records

An arriving host must be matched against retained enrollment evidence rather than automatically taking control of whichever record shares a cloud ID or label. Identity matching also considers AWS account/region/instance, key approval, historical records, and ambiguous multiple matches. A new fingerprint may be pending while the old identity remains authoritative. The [registry removal and matching contract](../REGISTRY-REMOVAL-MATCHING.md) requires explicit review and dependency checks before archival; archival does not delete provider assets, terminate EC2, revoke keys, erase history, or reset DNS allocations.

The registered Host UUID persists across name changes and retained observations. A cloud instance address is a changing observation, not host identity. Enrollment approval alone does not enroll a host in DNS publication, assign archive permissions, install station-access, or activate a managed control session.

## Signed heartbeat and host-generation evidence

Each accepted heartbeat is bound to the approved host key and records an authenticated observation with bounded freshness semantics. The [host-generation producer chain](../HOST-GENERATION-AND-EXPORT.md) originates slot/installation evidence in host-install, carries it via host-discover, and accepts it at station-access **only on a signed path**. Selected HOST-A/HOST-B slot and actually booted slot are separate facts: a host using a transitional boot root can have a selected slot but an unknown booted Zog slot. Never infer inactive-slot or generation provenance from absence of evidence.

Host Detail resolves exact generation evidence against archived root-filesystem observations. Unresolved and conflicting digest matches remain visible rather than choosing a convenient snapshot. Generation provenance links and JSON exports have an independent administrator authorization boundary. No host-beacon statement alone establishes a complete software provenance graph.

## Experimental managed sessions

The [managed session producer](../MANAGED-SESSIONS.md) documents an *opt-in*, disabled-by-default enrollment/session surface with a dedicated signing authority. It requires approved host-key signatures, exact installation/STATE volume/authority/registry binding, a carried checkpoint and replay protection. Session tokens are short-lived and bound to those identities. Missing or conflicting checkpoint state is a recovery problem, not permission to mint a new history.

The [managed-session recovery notes](../MANAGED-SESSION-RECOVERY.md) and host-discover supervisor contract describe consumer-side restart and uncertainty handling. Local fixtures or a diagnostic read-only managed beacon do not authorize remote command delivery; a production control API, generalized writer, or full supervisor acceptance must be separately implemented and verified.

## Operator reading and evidence checklist

1. Inspect immutable Host UUID, approved key fingerprint, enrollment state and archival blockers.
2. Check the signed heartbeat's accepted time, approval epoch, cloud identity and observation freshness.
3. Compare the accepted account/region/instance and public address with a successful AWS inventory scan; do not trust a self-asserted address alone.
4. For host installation, compare selected versus actually booted slot and treat absent/conflicting rootfs evidence explicitly.
5. For DNS, archive or deployment actions, follow the **separate** capability/policy and review workflows, never extending key approval into blanket authority.

### Source contracts

- [Signed enrollment, heartbeat and revocation](../SIGNED-HOST-PROTOCOL.md)
- [Record matching, removal and archival dependencies](../REGISTRY-REMOVAL-MATCHING.md)
- [Host generation and provenance export](../HOST-GENERATION-AND-EXPORT.md)
- [Experimental managed admission/session producer](../MANAGED-SESSIONS.md)
- [Managed session recovery](../MANAGED-SESSION-RECOVERY.md)
- [Deployment inspection and destination application](../DEPLOYMENT-JOBS.md)

**Acceptance boundary:** Source and CI checks do not prove that the current production station and its host-discover clients run every documented protocol revision.
