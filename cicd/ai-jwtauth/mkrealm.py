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
    ],
}

with open(sys.argv[1], "w") as f:
    json.dump(realm, f, indent=2)
print("realm written to %s (%d padding roles)" % (sys.argv[1], len(PAD_ROLES)))
