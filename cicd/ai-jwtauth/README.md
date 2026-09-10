# ai-jwtauth

Data-plane bearer-token (JWT) admission, end to end, against a real
Keycloak realm.

## Why a real identity provider

The verifier's defaults are Keycloak-shaped: roles at `realm_access.roles`,
the subject at `sub`, the tenant at a `tenant_id` claim fed from a user
attribute. A hand-minted token proves the verifier accepts what the test
author signed. Importing a realm and asking Keycloak for tokens over the
password grant proves those defaults match what an identity provider
actually emits — including the parts nobody writes down, like which
audiences land in an access token and how large one gets once a user
carries real roles.

## Layout

| file | role |
|---|---|
| `mkrealm.py` | emits the imported realm (users, roles, mappers, clients) |
| `hdr_echo.py` | backend that reports the headers that reached it, in its response body |
| `segmented_send.py` | sends one request in small TCP writes so header values arrive fragmented |
| `config.sh` | Keycloak + key store + topology + profiles + rules + tokens |
| `validation.sh` | the matrix |
| `rmconfig.sh` | teardown (leaves the Keycloak image cached) |
| `keycloak/` | Dockerfile + `build.sh` for the pinned realm-baked Keycloak image |

## The Keycloak image

The scenario runs against `loxilb-aigw-keycloak:26.0-aigw` — a pinned
Keycloak with the `aigw` realm already imported into it.

```
cd cicd/ai-jwtauth/keycloak && ./build.sh
```

`config.sh` builds it automatically the first time and reuses it after
that; `rmconfig.sh` leaves it in place. Override the tag with
`AIGW_KEYCLOAK_IMAGE`, and pass a different upstream version as
`./build.sh <tag> <keycloak-version>`.

Baking the image rather than pulling upstream and importing a realm on
every run is what makes repeat runs meaningful: a run months from now meets
the same identity provider as the first one, a CI job needs no external
registry at test time, and `build.sh` regenerates the realm from
`mkrealm.py` so the image cannot drift from the users and roles the
assertions assume. Rebuild after any change to `mkrealm.py`.

## Services

One profile per VIP port, so a profile field is the only variable between a
refusal and its control.

| port | mode | profile | what it isolates |
|---|---|---|---|
| 2040 | `jwt` | `kc` | the bearer arm and upstream-hygiene defaults |
| 2041 | `apikey-or-jwt` | `kc` | credential precedence |
| 2042 | `jwt` | `kc-wrongaud` | audience mismatch |
| 2043 | `jwt` | `kc-wrongiss` | issuer mismatch (same keys) |
| 2044 | `jwt` | `kc-blackhole` | JWKS endpoint that never answers |
| 2045 | `jwt` | `kc-fwd` | `forward_identity=true` |
| 2046 | `jwt` | `kc-pass` | `authorization_passthrough=true` |
| 2047 | `jwt` | `kc-outage` | an IdP that goes away after its keys were fetched (`refresh_sec` 10) |

Realm users: `alice` (tenant-a, llama-70b), `bob` (tenant-b, mistral-7b),
`carol` (no tenant attribute), `dave` (tenant-d, llama-70b plus padding
roles so the token spans several parser reads).

## The two legs that are born red

**E2 — segmented send.** llhttp is fed per socket read and keeps parser
state between calls, so one header *value* arrives as several fragments
whenever it crosses a read boundary. A capture that requires the `Bearer`
prefix on the fragment it happens to see, and overwrites instead of
appending, keeps one fragment of a multi-kilobyte access token and then
fails verification as an ordinary bad-signature 401 — intermittently, and
only under segmentation. E2 forces the segmentation; E1 is the same token
sent normally, so a failure cannot be blamed on the token.

**C4 — failed key, valid token.** In `apikey-or-jwt` a present API key
decides alone and its rejection is final. A build that falls back to the
bearer arm after rejecting a key lets a caller test one credential per
request behind a single 401. C5 is the control: the same token alone *is*
admitted on that port.

Do not soften either assertion to make a run pass.

## The IdP outage pair

Groups G and I differ in exactly one variable — whether a keyset was ever
fetched — and must not be collapsed into one.

**G (port 2044)** is an IdP that never answered: the verifier holds no keys,
so it cannot check anything and refuses **503**.

**I (port 2047)** is the operational case: keys were fetched, then Keycloak
went away. Admission must keep working on the last-known-good keyset, so
**200** — and specifically *not* the 503 that G returns. A gateway that
answered 503 whenever its IdP restarted would turn a survivable blip into a
total outage of the inference plane. That both verdicts appear in one run,
from the same assertion helpers, is what makes each of them mean something.

The realm is **paused**, not stopped: `kc-aigw` runs with `--rm`, so
stopping it destroys the container and there is nothing to bring back. A
pause keeps the same container and IP, so the profile's `jwks_url` stays
valid and the outage is exactly "the endpoint stopped answering". An `EXIT`
trap unpauses it, so a failure mid-group cannot leave the realm frozen for
whatever runs next on the host.

`I1` is the group's vacuity guard: it proves no new token can be minted
while the realm is paused. Without it, `I2` passing would say nothing — a
Keycloak that never went down also admits traffic.

## Running

```
cd cicd/ai-jwtauth
LOXILB_DOCKER_IMAGE=<tag> ./config.sh && ./validation.sh && ./rmconfig.sh
```

The image pin is required, not optional: the JWT bearer arm is not in a
released image, so the auto-detected default answers 404 to every profile
create. `config.sh` probes the profile route before configuring anything
and refuses by name if the image cannot serve it.

One gateway at a time on a shared host. Teardown stops `kc-aigw` and
`pg-jwtauth`, both of which run with `--rm`.
