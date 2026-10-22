"""Station-side certificate proposal/status boundary (no certificate authority).

Only host-deploy may authorize a policy and issue, reconcile, publish, or
reload. These views have no certbot/OS subprocess, DNS or proxy mutation.
"""
from django.db import transaction
from django.db.models import F
from zog.certify_manage.model import Authorization, PolicyError
from .models import CertificateSetupProposal

SCHEMA = "zog-station-certificate-setup-v1"
OWNER_CONTRACT = "not-implemented"
LIFECYCLE = ("issued", "delivered", "nginx_loaded", "browser_verified")
STATUSES = ("not_observed", "pending", "verified", "failed", "stale")


class ProposalConflict(ValueError):
    pass


def _proposal(policy, revision, updated=None):
    return {
        "schema": SCHEMA, "read_only_status": True,
        "owner_request_available": False, "authorization": "operator-proposal-only",
        "revision": revision, "updated_at": updated,
        "proposal": policy or None,
        "owner": {"state": "unavailable", "reason": "owner-interface-not-configured"},
        "certificate": {
            "health": "not_observed", "expires_at": None,
            "days_remaining": None, "fingerprint_sha256": None,
            "renewal": "not_observed",
        },
        "lifecycle": {name: "not_observed" for name in LIFECYCLE},
        "https_readiness": "not_verified",
    }


def snapshot():
    row = CertificateSetupProposal.objects.filter(pk=1).first()
    return _proposal(row.proposed_policy if row else None,
                     row.revision if row else 0,
                     row.updated_at.isoformat() if row else None)


def save_proposal(value):
    if type(value) is not dict or set(value) != {"revision", "proposal"}:
        raise PolicyError("invalid-proposal-fields")
    version = value["revision"]
    if type(version) is not int or not 0 <= version <= 2**63 - 2:
        raise PolicyError("invalid-revision")
    # Must use *producer* canonical policy grammar; no alternative CA/ACME
    # guesswork or arbitrary commands from browser input. The fixed service
    # identity is not caller chosen.
    auth = Authorization.from_dict(value["proposal"])
    if auth.certificate_id != "station-web" or len(auth.hostnames) != 1:
        raise PolicyError("station-web-certificate-required")
    with transaction.atomic():
        # Ensure one row, while existing DB transaction serializes revision.
        row, _ = CertificateSetupProposal.objects.get_or_create(
            pk=1, defaults={"revision": 0, "proposed_policy": {}})
        if row.revision != version:
            raise ProposalConflict("proposal-revision-changed")
        updated = CertificateSetupProposal.objects.filter(
            pk=1, revision=version).update(
                revision=F("revision") + 1, proposed_policy=auth.canonical())
        if updated != 1:
            raise ProposalConflict("proposal-revision-changed")
    return snapshot()


def refuse_owner_request():
    # Until host-deploy defines authenticated, constrained request binding,
    # it is unsafe to treat any Django action as a host authorization.
    return {"code": "owner-interface-unavailable",
            "detail": "An authorized host-owner certificate request interface is not available",
            "safe_to_issue": False}
