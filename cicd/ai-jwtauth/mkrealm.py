#!/usr/bin/env python3
"""Emit the Keycloak realm this scenario imports.

Generated rather than checked in as a literal because one user deliberately
carries ~50 padding roles: the bearer capture reassembles a header value
across parser fragments, and only a token large enough to cross a read
boundary exercises that. Writing those roles out by hand would bury the two
roles that actually carry meaning.

Realm shape:
  clients   aigw-client   direct access grants, audience mapper -> aigw-api
            aigw-short    same, but access tokens live 1 second (expiry leg)
  users     alice  tenant-a, model:llama-70b
            bob    tenant-b, model:mistral-7b
            carol  NO tenant_id attribute (unattributable token)
            dave   tenant-d, model:llama-70b + padding roles (large token)
"""
import json
import sys

# Every name below derives from REALM. The realm name appears in the default
# roles composite as well as in the realm block, and a rename that updated
# only one of them would refuse every password grant with "Account is not
# fully set up" — an error that reads like a bad credential and is not one.
REALM = "aigw"
DEFAULT_ROLES = "default-roles-" + REALM

PAD_ROLES = ["model:padding-role-%02d" % i for i in range(50)]


def mapper_tenant():
    return {
        "name": "tenant-id",
        "protocol": "openid-connect",
        "protocolMapper": "oidc-usermodel-attribute-mapper",
        "consentRequired": False,
        "config": {
            "user.attribute": "tenant_id",
            "claim.name": "tenant_id",
            "jsonType.label": "String",
            "id.token.claim": "true",
            "access.token.claim": "true",
            "userinfo.token.claim": "true",
        },
    }


def mapper_audience():
    return {
        "name": REALM + "-audience",
        "protocol": "openid-connect",
        "protocolMapper": "oidc-audience-mapper",
        "consentRequired": False,
        "config": {
            "included.custom.audience": REALM + "-api",
            "id.token.claim": "false",
            "access.token.claim": "true",
        },
    }


def client(client_id, attributes=None):
    return {
        "clientId": client_id,
        "enabled": True,
        "publicClient": True,
        "directAccessGrantsEnabled": True,
        "standardFlowEnabled": False,
        "serviceAccountsEnabled": False,
        "attributes": attributes or {},
        "protocolMappers": [mapper_tenant(), mapper_audience()],
    }


def user(username, password, roles, tenant=None):
    u = {
        "username": username,
        "enabled": True,
        "emailVerified": True,
        # Keycloak runs VERIFY_PROFILE as a default required action and the
        # declarative user profile wants these three. A user missing them is
        # refused every password grant as "Account is not fully set up",
        # which reads like a bad credential and is not one.
        "email": "%s@%s.test" % (username, REALM),
        "firstName": username.capitalize(),
        "lastName": "Tester",
        "credentials": [{"type": "password", "value": password, "temporary": False}],
        # An imported user gets exactly the roles named here, so the realm's
        # default-roles composite has to be one of them: without it every
        # password grant is refused "Account is not fully set up", which
        # looks like a credential problem and is not one.
        "realmRoles": [DEFAULT_ROLES] + list(roles),
        # Nothing may stand between the grant and a token.
        "requiredActions": [],
    }
    if tenant is not None:
        u["attributes"] = {"tenant_id": [tenant]}
    return u


realm = {
    "realm": REALM,
    "enabled": True,
    "sslRequired": "none",
    "accessTokenLifespan": 300,
    "roles": {
        "realm": [
            {"name": r}
            for r in ["model:llama-70b", "model:mistral-7b"] + PAD_ROLES
        ]
    },
    "clients": [
        client(REALM + "-client"),
        client(REALM + "-short", {"access.token.lifespan": "1"}),
    ],
    "users": [
        user("alice", "alicepw", ["model:llama-70b"], "tenant-a"),
        user("bob", "bobpw", ["model:mistral-7b"], "tenant-b"),
        # No tenant_id attribute: the profile leaves default_tenant empty, so
        # this token verifies but cannot be attributed and must be refused.
        user("carol", "carolpw", ["model:llama-70b"]),
        user("dave", "davepw", ["model:llama-70b"] + PAD_ROLES, "tenant-d"),
    ]
    # The QoS ladder's runtime arm. Every rung is a per-(tenant, user) token
    # bucket, so two cases that share a user share a bucket and the second
    # one scores whatever spend the first left behind. One user per case is
    # what makes the block re-runnable and order-independent — and it is why
    # these are separate identities rather than reuses of alice and bob,
    # whose buckets the rest of the suite is already spending.
    + [user("q%d" % i, "q%dpw" % i, ["model:llama-70b"], "tenant-q")
       for i in range(1, 10)]
    # The tenant-aggregate rung needs two users who share a tenant and are
    # used by nothing else: the claim is that the TENANT bucket caps the sum
    # of its users, and it is only decisive if no per-user bucket could have
    # produced the same denial.
    + [user("t%d" % i, "t%dpw" % i, ["model:llama-70b"], "tenant-qt")
       for i in range(1, 3)]
    # The token rungs that distinguish one model from another need an
    # identity authorized for BOTH: "only that pair is denied" is a claim
    # about a second model still being served, and a user whose roles allow
    # one model would be refused on the other by authorization instead --
    # the same 403-shaped outcome for an entirely different reason.
    + [user("q10", "q10pw", ["model:llama-70b", "model:mistral-7b"], "tenant-q"),
       user("m1", "m1pw", ["model:llama-70b"], "tenant-qm"),
       user("m2", "m2pw", ["model:llama-70b"], "tenant-qm"),
       # The tenant|model rung needs a tenant whose AGGREGATE bucket is not
       # already in debt from the aggregate case -- the two rungs answer with
       # the same error code, so a tenant carrying both cannot say which one
       # refused. Hence its own tenant rather than another user in tenant-qm.
       user("n1", "n1pw", ["model:llama-70b", "model:mistral-7b"], "tenant-qn")]
    # The fault-injection arms (QOS-RES / QOS-OUT / QOS-ID). The outage arms
    # turn on whether the store has EVER answered for an identity, so theirs
    # cannot be reuses of anything above: a user some earlier case drove is a
    # user whose rows are cached, and "cached" versus "never read" is the
    # entire distinction those cases measure.
    + [user("f%d" % i, "f%dpw" % i, ["model:llama-70b"], "tenant-qf")
       for i in range(1, 5)]
    # The reservation arms hold a claim across a slow backend and then abort
    # it. A leaked claim is only visible as a denial of the NEXT request
    # against the same bucket, so a bucket anything else spends would
    # attribute someone else's traffic to the leak. Both models, because
    # QOS-RES-001 needs a second model to show the FIRST bucket's claim came
    # back.
    + [user("r%d" % i, "r%dpw" % i, ["model:llama-70b", "model:mistral-7b"], "tenant-qr")
       for i in range(1, 3)]
    + [
        # Identity safety, from the IdP side. Both tenant values are ordinary
        # directory attributes -- which is the point: an IdP mints what its
        # directory holds, and self-service registration fills directories.
        # "tenant-x|llama-70b" IS the composite bucket key of tenant
        # "tenant-x" and model "llama-70b"; "uq:tenant-q|q1" IS q1's
        # user-scope quota key on the sync wire. Neither can be carried
        # without one identity spending another's quota.
        user("x1", "x1pw", ["model:llama-70b"], "tenant-x|llama-70b"),
        # No delimiter in this one, on purpose: it must be refused by the
        # reserved-prefix guard alone. With a pipe in it as well, a build
        # that had lost the prefix check entirely would still refuse it and
        # the case would report a guard that is not there.
        user("x2", "x2pw", ["model:llama-70b"], "v:tenant-x"),
        # Neighbour identities inside one tenant: the no-aliasing control.
        # "z" is a prefix of "zz", so a bucket key built by concatenation
        # without a delimiter would put them in one bucket.
        user("z", "zpw", ["model:llama-70b"], "tenant-qi"),
        user("zz", "zzpw", ["model:llama-70b"], "tenant-qi"),
    ],
}

with open(sys.argv[1], "w") as f:
    json.dump(realm, f, indent=2)
print("realm written to %s (%d padding roles)" % (sys.argv[1], len(PAD_ROLES)))
