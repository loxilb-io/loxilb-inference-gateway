# The identity provider this scenario tests against, with the aigw realm
# already inside it.
#
# Built rather than pulled-and-imported at test time for three reasons that
# all matter once the suite is run repeatedly:
#   - a re-run months from now must exercise the SAME identity provider, so
#     the upstream version is pinned here instead of floating;
#   - a CI run should not depend on an external registry being reachable, or
#     on a bind-mounted realm file surviving whatever runs the job;
#   - importing the realm at image-build time keeps container start fast, so
#     the scenario waits on a boot rather than on a database import.
#
# Rebuild it whenever mkrealm.py changes: keycloak/build.sh regenerates the
# realm and rebuilds in one step.

ARG KEYCLOAK_VERSION=26.0

FROM quay.io/keycloak/keycloak:${KEYCLOAK_VERSION} AS realm-import

COPY aigw-realm.json /opt/keycloak/data/import/aigw-realm.json

# Populates the embedded database that the final stage carries forward.
RUN /opt/keycloak/bin/kc.sh import \
      --file /opt/keycloak/data/import/aigw-realm.json

FROM quay.io/keycloak/keycloak:${KEYCLOAK_VERSION}

# The imported realm lives in the embedded H2 store; carry it over so the
# runtime stage starts with the realm already present.
COPY --from=realm-import --chown=keycloak:root /opt/keycloak/data/h2 /opt/keycloak/data/h2

# Kept for reference and for a rebuild that wants to re-import explicitly.
COPY --chown=keycloak:root aigw-realm.json /opt/keycloak/data/import/aigw-realm.json

ENV KC_HTTP_ENABLED=true \
    KC_HOSTNAME_STRICT=false \
    KC_HEALTH_ENABLED=true

EXPOSE 8080

ENTRYPOINT ["/opt/keycloak/bin/kc.sh"]
CMD ["start-dev"]
