# Networking contract audit

## Checkpoint status

Exploration is paused. **No files were edited or created; no tests, builds, SSH, or subagents were used.**

Checkout HEAD was verified as `f8e6ace22f0f2262d56829e781a83e4b7075fef7`, with existing WIP preserved. Swagger changed during the review. The last inventory pass read a stable Swagger SHA-256:

`1c2a6a7cc660a18933c7ec883f74596353719996e3c67474ced00bb06be956eb`

This is a **static-source checkpoint**, not runtime qualification or a claim that all gaps are closed.

## 1. Reviewed inventory

All **70 assigned Swagger operations** were inventoried and their handlers inspected. Relevant domain validation, conversion, readback, and selected datapath consumers were traced. The deeper-consumer limitations are explicitly listed at the end.

Below, paths follow `/netlox/v1/config`. `G/P/D/U` mean GET/POST/DELETE/PUT. Numbers refer to the last-read [Swagger file](../../api/swagger.yml).

| Family | Operations reviewed; Swagger method lines |
|---|---|
| Conntrack / port | G `conntrack/all` 2465; G `port/all` 2497 |
| Route | G `route/all` 2529; P `route` 2571; D `route/destinationIPNet/{ip_address}/{mask}` 2616 |
| Session | G `session/all` 2669; P `session` 2698; D `session/ident/{ident}` 2743 |
| Session ULCL | G `sessionulcl/all` 2787; P `sessionulcl` 2816; D `sessionulcl/ident/{ident}/ulclAddress/{ip_address}` 2861 |
| Policy | G `policy/all` 2915; P `policy` 2944; D `policy/ident/{ident}` 2989 |
| Mirror | G `mirror/all` 3037; P `mirror` 3065; D `mirror/ident/{ident}` 3110 |
| IPv4 address | G `ipv4address/all` 3158; P `ipv4address` 3187; D `ipv4address/{ip_address}/{mask}/dev/{if_name}` 3232 |
| IPv6 address | G `ipv6address/all` 3286; P `ipv6address` 3315; D `ipv6address/{ip_address}/{mask}/dev/{if_name}` 3360 |
| Neighbor | G `neighbor/all` 3418; P `neighbor` 3447; D `neighbor/{ip_address}/dev/{if_name}` 3492 |
| FDB | G `fdb/all` 3545; P `fdb` 3573; D `fdb/{mac_address}/dev/{if_name}` 3618 |
| VLAN | G `vlan/all` 3670; P `vlan` 3699; D `vlan/{vlan_id}` 3744; P `vlan/{vlan_id}/member` 3789; D `vlan/{vlan_id}/member/{if_name}/tagged/{tagged}` 3839 |
| VXLAN | G `tunnel/vxlan/all` 3891; P `tunnel/vxlan` 3919; D `tunnel/vxlan/{vxlanID}` 3953; P `tunnel/vxlan/{vxlanID}/peer` 3985; D `tunnel/vxlan/{vxlanID}/peer/{PeerIP}` 4022 |
| Cluster state | G `cistate/all` 4062; P `cistate` 4091 |
| Endpoint | G `endpoint/all` 4138; P `endpoint` 4167; P `endpointhoststate` 4212; D `endpoint/epipaddress/{ip_address}` 4257 |
| Firewall | G `firewall/all` 4319; P `firewall` 4348; D `firewall` 4392 |
| IP filter | G `ipfilter/all` 4471; P `ipfilter` 4498; D `ipfilter` 4530 |
| Security rate | P `securityrate` 4581; D `securityrate` 4613; G `securityrate/all` 4643; U `securityrate/reset` 4670 |
| BGP neighbors | G `bgp/neigh/all` 5596; P `bgp/neigh` 5640; D `bgp/neigh/{ip_address}` 5685 |
| BGP defined sets | G/D `bgp/policy/definedsets/{defineset_type}/{type_name}` 5736/5791; P `bgp/policy/definedsets/{defineset_type}` 5840 |
| BGP policy definitions | G `bgp/policy/definitions/all` 5889; P `bgp/policy/definitions` 5918; D `bgp/policy/definitions/{policy_name}` 5963 |
| BGP assignments/global | P/D `bgp/policy/apply` 6008/6051; P `bgp/global` 6096 |
| BFD | G `bfd/all` 6764; P `bfd` 6793; D `bfd/remoteIP/{remote_ip}` 6837 |

**Definitions reviewed:** the following 44 networking definitions, including their inline properties, plus shared `OperationResult` and `Error`. Review does not imply that every field has a satisfactory implementation.

| Definitions | Swagger definition lines |
|---|---|
| RouteEntry; RouteGetEntry | 9603; 9619 |
| K8sConntrackEntry; ConntrackEntry; PortEntry | 9652; 9710; 9769 |
| SessionEntry; SessionUlClEntry | 9879; 9909 |
| PolicyEntry; MirrorEntry; MirrorGetEntry | 9927; 9972; 10017 |
| VlanBridgeEntry; VlanGetEntry; VlanMemberEntry | 10059; 10068; 10092 |
| IPv4AddressEntry; IPv4AddressGetEntry; IPv6AddressEntry; IPv6AddressGetEntry | 10102; 10116; 10134; 10148 |
| NeighborEntry; FDBEntry | 10166; 10183 |
| VxlanEntry; VxlanBridgeEntry; VxlanPeerEntry | 10286; 10305; 10316 |
| CIStatusEntry; CIStatusGetEntry | 10324; 10338 |
| EndPointGetEntry; EndPoint; EndPointHostState | 10356; 10396; 10442 |
| FirewallOptionEntry; FirewallRuleEntry; FirewallEntry | 10458; 10499; 10542 |
| IPFilterEntry; SecurityRateConfigMod; SecurityRateEntry | 10553; 10590; 10642 |
| BGPNeigh; BGPNeighGetEntry; BGPGlobalConfig | 11311; 11527; 11550 |
| BGPPolicyDefinedSetGetEntry; BGPPolicyDefinedSetsMod; BGPPolicyPrefix | 11330; 11347; 11364 |
| BGPPolicyDefinitionsMod; BGPPolicyDefinitionsStatement; BGPApplyPolicyToNeighborMod | 11374; 11385; 11506 |
| BfdGetEntry; BfdEntry | 11569; 11610 |
| Shared OperationResult; Error | 8348; 8355 |

`K8sConntrackEntry` is not referenced by the assigned conntrack operation; its Kubernetes enrichment must not be advertised as that operation’s output.

## 2. Findings and actionable description replacements

Labels distinguish **doc-defect**, **implementation-gap**, and **policy-needed**. Proposed descriptions below describe supported source behavior or explicitly disclose a limitation; they do not legitimize unsafe behavior.

### A. Shared responses and authorization

**A1 — implementation-gap: unsuccessful mutations can return HTTP 200.**
IPv4/IPv6 address and VXLAN handlers return `ResultResponse{Result:"fail"}`. That responder never writes an error status. Consequently, documented 400/404/409 responses do not describe those backend failures. VXLAN helpers even return numeric 403/404/409 values which handlers collapse into `"fail"`.

Evidence: [common.go:45](../../api/restapi/handler/common.go:45), [vxlan.go:26](../../api/restapi/handler/vxlan.go:26).

Replacement:

> “Returns an operation-result object. In the current implementation, some unsuccessful address and VXLAN mutations return HTTP 200 with `result: "fail"`; HTTP status alone does not establish success.”

Fix status propagation separately; do not redefine failure-as-200 as the desired contract.

**A2 — doc-defect / implementation-gap: error descriptions are broader or narrower than actual classification.**
Classification is substring-based. For example, `pol-info error`, `mirr-info error`, `host-parse error`, `ep-host-state args error`, `no-ulcl error`, and `ulcl-exists error` miss their expected validation/not-found/conflict classes and fall through to 500. BGP-disabled errors become 403 labelled “Capacity insufficient.”

Evidence: [common.go:95](../../api/restapi/handler/common.go:95).

Replacement:

> “Errors may indicate malformed input, missing resources, conflicting configuration, disabled operating modes, unavailable dependencies, or internal failures. The current implementation does not consistently classify every domain error.”

Do not retain unrelated VLAN/VRF conflict descriptions on networking operations.

**A3 — doc-defect: networking authorization needs deployment context.**
The authenticator selects user-service, OAuth, or manual-token validation; otherwise it returns an unrestricted principal. With role-based principals, viewers may GET but not perform these mutations. Invalid credentials produce 401; recognized credential-store unavailability produces 503.

Evidence: [auth.go:47](../../api/restapi/handler/auth.go:47), [authz.go:112](../../pkg/authz/authz.go:112).

Replacement:

> “Management authentication follows the configured authentication mode. With role-based authorization enabled, viewer access is read-only and administrator access permits mutations. Credential rejection and credential-store unavailability are distinct failures.”

This is not a full auth audit.

### B. Route, session and ULCL

**B1 — doc-defect / implementation-gap: route protocol write/read semantics differ.**
POST recognizes only exact `"static"`; other strings leave the netlink protocol unset. GET can return `unspec`, `redirect`, `kernel`, `boot`, `static`, or numeric strings. POST uses `RouteAdd`, not replace, and does not locally reject an invalid/nil gateway or mismatched address families.

Evidence: [nlp.go:1358](../../api/loxinlp/nlp.go:1358), [route.go:51](../../api/restapi/handler/route.go:51).

Replacements:

> `destinationIPNet`: “Destination network in CIDR notation.”
> `gateway`: “Next-hop IP address; not CIDR notation.”
> `protocol`: “The create path explicitly selects the static route protocol only for `static`; returned protocol values are not a supported create-time enumeration.”
> DELETE: “Delete a route identified by destination address and prefix length.”

GET gateway can be a comma-separated next-hop list; route statistics are **bytes and packets**, not ingress/egress byte counters. Evidence: [route.go:149](../../pkg/loxinet/route.go:149).

**B2 — implementation-gap: optional session objects are dereferenced; integers narrow unchecked.**
Session POST dereferences both optional tunnel objects. ULCL POST dereferences optional `ulclArgument`. TEIDs narrow to `uint32`; QFI narrows to `uint8`; IP parsing is not followed by adequate rejection.

Evidence: [session.go:38](../../api/restapi/handler/session.go:38), [session.go:80](../../api/restapi/handler/session.go:80).

UI guidance: explicitly supply both tunnel objects and the ULCL argument; reject negative/out-of-representation values before submission. The intended legal QFI range still requires policy disposition.

**B3 — implementation-gap: session replacement comparison is wrong.**
The condition tests `AN differs OR CN equals`. An identical submission can delete/recreate the session, removing its ULCL classifiers; a CN-only change can instead conflict.

Evidence: [session.go:142](../../pkg/loxinet/session.go:142).

Safe replacement:

> “Sessions are identified by `ident`. ULCL classifiers require an existing session and are identified by session identifier plus classifier IP. Deleting a session also removes its classifiers. Existing-session POST behavior currently requires correction and must not be treated as an idempotent update.”

### C. Policy and mirror

**C1 — doc-defect: policy target is not an arbitrary rule name.**
Rule attachment requires `VIP:PORT:PROTO`, or `[VIP]:PORT:PROTO` for IPv6; port is 1–65535 and protocol TCP/UDP/SCTP. Attachment 2 requires `--egr-hooks`. Missing target objects can remain pending.

Evidence: [qospol.go:126](../../pkg/loxinet/qospol.go:126), [qos_rule_key.go:38](../../pkg/loxinet/qos_rule_key.go:38).

Replacement:

> “Attachment 0 identifies an exact load-balancing rule using `VIP:PORT:PROTO` or `[VIP]:PORT:PROTO`; attachments 1 and 2 identify ingress and egress ports. Egress attachment requires enabled egress hooks. Acceptance may precede target availability.”

**C2 — implementation-gap / policy-needed: policer values do not faithfully reach the datapath.**

- Signed rates/sizes become unsigned before validation.
- CIR must be at least 8 Mbps; PIR accepts zero or at least 8, without checking `PIR ≥ CIR`.
- CBS zero becomes 30,000,000 bytes; EBS is always overwritten with twice CBS.
- `PolType` is retained for GET but not copied to datapath `Srt`; the inspected eBPF path therefore selects trTCM.
- eBPF rate conversion truncates to 8-Mbps increments; burst sizes narrow to 32 bits.
- Fullproxy attachment instead configures a byte shaper; identical behavior across targets is not established.

Evidence: [qospol.go:99](../../pkg/loxinet/qospol.go:99), [qospol.go:487](../../pkg/loxinet/qospol.go:487), [dpebpf_linux.go:3019](../../pkg/loxinet/dpebpf_linux.go:3019), [rules.go:1716](../../pkg/loxinet/rules.go:1716).

Replacement:

> “Rates are expressed in megabits per second and burst sizes in bytes. Effective behavior depends on the attachment datapath. Current implementation limitations affect single-rate mode, supplied excess burst size, and numerical precision.”

**C3 — implementation-gap: policy/mirror POST is not a general update.**
Only changed information triggers delete/recreate; target-only changes conflict. Replacement is not atomic.

Evidence: [qospol.go:197](../../pkg/loxinet/qospol.go:197), [mirror.go:173](../../pkg/loxinet/mirror.go:173).

**C4 — implementation-gap: advertised mirror modes exceed implementation.**
Swagger attachment 0 means rule, but the handler directly casts it to internal constants where port=1 and rule=2. Rule attachment is unsupported by the consumer; ERSPAN immediately fails datapath programming, and its failure is ignored by creation. RSPAN rejects nonzero VLAN IDs.

Evidence: [mirror.go:52](../../api/restapi/handler/mirror.go:52), [mirror.go:94](../../pkg/loxinet/mirror.go:94), [mirror.go:282](../../pkg/loxinet/mirror.go:282).

Replacement:

> “The inspected implementation provides a port-attached SPAN programming path. Rule attachment and ERSPAN are not implemented end-to-end; RSPAN VLAN validation requires correction. Successful object creation does not prove mirroring is active.”

### D. Addresses, neighbor, FDB, VLAN and VXLAN

**D1 — implementation-gap / policy-needed: address endpoint names do not enforce family.**
Both mutation families call shared helpers. Missing Linux interfaces fall back to internal address objects instead of necessarily returning not-found. Internal IPv6 self-route construction also hardcodes `/32`.

Evidence: [nlp.go:1053](../../api/loxinlp/nlp.go:1053), [layer3.go:115](../../pkg/loxinet/layer3.go:115).

Replacement:

> “Supply an interface name and an address with prefix length. GET filters the gateway’s address inventory by family. Mutation-time family enforcement and missing-interface behavior currently require contract reconciliation.”

**D2 — implementation-gap, high impact: neighbor deletion can escape interface scope.**
If interface lookup fails, deletion lists neighbors across interfaces and deletes matching IPs, ignoring individual deletion failures.

Evidence: [nlp.go:459](../../api/loxinlp/nlp.go:459).

Desired description—**requires implementation fix**:

> “Delete the neighbor entry matching both IP address and interface. A missing interface must not cause deletion on other interfaces.”

Neighbor creation requests a permanent entry; IP is literal and MAC is parsed. FDB uses bridge-family entries, while GET enumerates interfaces with a bridge master and does not expose the full kernel FDB key.

Evidence: [nlp.go:374](../../api/loxinlp/nlp.go:374), [nlp.go:716](../../api/loxinlp/nlp.go:716).

**D3 — implementation-gap: VLAN promises are not enforced on the REST path.**
The handlers use netlink helpers, bypassing internal VLAN validation. The helpers do not enforce the documented ID range or existing-master relationship. Member deletion verifies that the requested bridge exists but never verifies that it owns the member before unmastering it. Tagged-member creation can leave partial state after failure.

Evidence: [vlan.go:26](../../api/restapi/handler/vlan.go:26), [nlp.go:534](../../api/loxinlp/nlp.go:534), [nlp.go:576](../../api/loxinlp/nlp.go:576).

Replacement:

> “Creates bridge `vlan<ID>`. Untagged membership attaches the named interface; tagged membership creates and attaches `<interface>.<ID>`. Omitted `tagged` means false. Ownership checks, range enforcement, and rollback are not consistently implemented.”

**D4 — doc-defect / implementation-gap: VXLAN responses and prerequisites are wrong or incomplete.**
Peer POST/DELETE declare resource schemas but return `OperationResult`. Mutation summaries say “list.” Creation selects the endpoint interface’s first IPv4 address, UDP port 8472, MTU 9000, and learning enabled. Deletion continues after failed link lookup.

Evidence: [vxlan.go:44](../../api/restapi/handler/vxlan.go:44), [nlp.go:614](../../api/loxinlp/nlp.go:614), [nlp.go:668](../../api/loxinlp/nlp.go:668).

Replacement:

> “Create VXLAN interface `vxlan<ID>` using the first IPv4 address on `epIntf`, UDP port 8472, and MTU 9000. Peer mutations return an operation-result object, not a VXLAN resource.”

### E. Cluster state and BFD

**E1 — implementation-gap: cluster-state mutation has validation, update, and command-execution hazards.**
It creates an instance before validating state; identical state ignores a changed VIP; invalid VIP parsing is unchecked. User-controlled instance text is concatenated into a `bash -c` command when the hook exists. GET does not populate required `sync`.

Evidence: [cluster.go:520](../../pkg/loxinet/cluster.go:520), [cluster.go:554](../../pkg/loxinet/cluster.go:554), [handler/cluster.go:37](../../api/restapi/handler/cluster.go:37).

Replacement:

> “Set the named cluster instance’s state. Recognized states are `MASTER`, `BACKUP`, `FAULT`, `STOP`, and `NOT_DEFINED`. State changes initiate asynchronous dependent updates; response success does not establish their completion.”

Do not publish unrestricted instance strings as safe until command argument handling is fixed.

**E2 — implementation-gap / doc-defect: BFD create/update/zero semantics differ.**
Interval is exposed as uint64 but narrowed to uint32. New sessions require interval ≥100,000 microseconds and nonzero retry count. Existing-session zero interval/retry means preserve; unchanged submissions conflict. First-session setup is asynchronous and can fail after HTTP success. Source-IP changes are not applied as an existing-session update.

Evidence: [cluster.go:616](../../pkg/loxinet/cluster.go:616), [bfd.go:119](../../pkg/proto/bfd.go:119).

Replacement:

> “Interval is in microseconds. Creating a session requires an existing cluster instance, a valid remote address, interval at least 100,000, and retry count greater than zero. Zero interval or retry count preserves that value only when updating an existing session.”

**E3 — implementation-gap: BFD deletion does not enforce ownership.**
The supplied instance need only exist; deletion selects by remote IP alone. It then clears the global running flag even if other sessions remain. GET splits `host:port` on every colon, making IPv6 readback unsafe.

Evidence: [cluster.go:669](../../pkg/loxinet/cluster.go:669), [bfd.go:195](../../pkg/proto/bfd.go:195).

Also retain exact wire casing: POST `sourceIp`, GET `sourceIP`.

### F. Endpoint and host state

**F1 — doc-defect / implementation-gap: endpoint admission and replacement need explicit rules.**

- `hostName` is a literal IP, not hostname/CIDR.
- Optional `probeType` is semantically required.
- TCP/UDP/SCTP require nonzero probe port.
- Duration and port narrow before domain validation; negative retries are not rejected.
- POST replaces options, not a partial patch.
- Reusing a custom name with a different host leaves the original host.
- GET omits all structured HTTP-monitor fields.

Evidence: [endpoint.go:60](../../api/restapi/handler/endpoint.go:60), [rules.go:5376](../../pkg/loxinet/rules.go:5376), [rules.go:5453](../../pkg/loxinet/rules.go:5453).

Replacement:

> “Configure a monitor for a literal endpoint IP. `name`, when supplied, identifies the monitor; otherwise identity is derived from host, probe type, and port. Existing-monitor POST replaces monitor options. GET is not a complete configuration round-trip.”

DELETE uses `name` preferentially; otherwise supply the original host/type/port tuple. Its `probe_port` query is a number converted to uint16, requiring fractional/range rejection.

**F2 — implementation-gap: HTTP settings are not validated or implemented as advertised.**
`httpMethod` is actively consumed, not control-plane-only. `httpVersion` does not select HTTP/1.0 versus HTTP/1.1. Expected-status parsing ignores conversion errors and narrows to uint16. Structured HTTPS status matching bypasses legacy `probeResp` matching. IPv6 URL/dial construction lacks brackets. TLS-hello intentionally skips certificate verification.

Evidence: [rules.go:457](../../pkg/loxinet/rules.go:457), [rules.go:5810](../../pkg/loxinet/rules.go:5810), [rules.go:5896](../../pkg/loxinet/rules.go:5896).

Replacements:

> “Empty `httpMethod` uses GET. Empty `urlPath` falls back to `probeReq`, then `/`.”
> “`expectedCodes` accepts a status, comma-separated statuses, or inclusive ranges; empty uses 200 on the structured status-checking path.”
> “`tls-hello` checks handshake completion, not certificate trust.”

**F3 — doc-defect / implementation-gap: host-state targeting is relational.**
Port and protocol must both be specified or both omitted/zero. Specific targeting uses the generated monitor key, not custom names. Host-wide updates can succeed without matches. GET `currState` is `ok`/`nok`/`red`, not a round-trip of green/yellow/red.

Evidence: [rules.go:5533](../../pkg/loxinet/rules.go:5533), [rules.go:5346](../../pkg/loxinet/rules.go:5346).

### G. BGP

**G1 — implementation-gap: optional inputs can reach nil dereferences.**
Neighbor DELETE dereferences optional `remoteAs`; generated binding leaves it nil when omitted. The eventual GoBGP delete ignores ASN. Policy POST similarly dereferences optional statement `conditions` and `actions`.

Evidence: [gobgp.go:86](../../api/restapi/handler/gobgp.go:86), [delete parameters:96](../../api/restapi/operations/delete_config_bgp_neigh_ip_address_parameters.go:96), [gobgp.go:217](../../api/restapi/handler/gobgp.go:217).

Desired replacement after correction:

> “Delete the neighbor identified by IP address. Remote ASN is not part of the deletion key.”

Do not merely make the unused ASN mandatory to conceal the dereference.

**G2 — implementation-gap: unchecked narrowing and silent fallback affect policy meaning.**
ASNs become uint32; ports become uint16; path length, prepend ASN/count, and local preference narrow without bounds. Invalid prepend ASN and mask-range numbers ignore parse errors. Unknown defined-set type defaults to prefix on add/delete, although GET rejects it. GET accepts `Prefix` internally but the handler only emits prefix entries for lowercase `prefix`.

Evidence: [gobgp.go:61](../../api/restapi/handler/gobgp.go:61), [gobgpclient.go:1089](../../pkg/loxinet/gobgpclient.go:1089), [gobgpclient.go:1322](../../pkg/loxinet/gobgpclient.go:1322), [gobgpclient.go:1499](../../pkg/loxinet/gobgpclient.go:1499).

**G3 — doc-defect / policy-needed: document exact vocabulary and destructive omissions.**

Replacement text:

> “For prefix sets, supply `prefixList`; for other set types, supply `List` with that exact capitalization. GET returns lowercase `list`.”
> “`masklengthRange` is an inclusive `minimum..maximum` prefix-length range.”
> “Statement `routeDisposition` uses `accept-route` or `reject-route`; assignment `routeAction` uses `accept` or `reject`.”
> “Assignment DELETE with omitted or empty `policies` removes all assignments for the selected neighbor and direction. Its required `routeAction` is ignored on deletion.”

Other UI vocabulary: match options `any/all/invert`; community actions `add/remove/replace`; path-length operators `eq/ge/le`. Invalid strings currently fall back silently. Preserve the wire typo `setLocalPerf`; zero means no local-preference action. MED parsing is signed 32-bit decimal; `setNextHop:"self"` is not specially translated to GoBGP’s self flag.

Evidence: [gobgpclient.go:1578](../../pkg/loxinet/gobgpclient.go:1578), [gobgpclient.go:1660](../../pkg/loxinet/gobgpclient.go:1660).

Global POST starts BGP and performs additional policy creation; it is not a general atomic configuration replacement. Omitted/zero ports select 179. Neighbor GET normalizes configured 179 to zero/absent. List handlers return 200 arrays, not their stale documented 204 alternatives.

### H. Firewall, IP filter and security rate

**H1 — doc-defect: firewall cross-field constraints are missing.**
Ports/preference are 0–65535; protocol is 0–255. Missing CIDRs become family-appropriate wildcard networks. Both ports zero mean wildcard; otherwise minimum must not exceed maximum. SNAT `toIP` is literal, not CIDR; SNAT requires zero explicit mark.

**H2 — implementation-gap / policy-needed:** conflicting action booleans use precedence `allow > drop > redirect > trap > snat`, but `doSnat` also independently creates an implicit rule. Duplicate POST can change the mark and then return 409. DELETE silently turns reversed ranges into wildcard tuples.

Evidence: [rules.go:5110](../../pkg/loxinet/rules.go:5110), [rules.go:5143](../../pkg/loxinet/rules.go:5143), [rules.go:5260](../../pkg/loxinet/rules.go:5260).

Replacement:

> “Provide one terminal action. `record` is an independent logging option. Deletion identifies an exact match tuple, including preference; it is not a search filter.”

“One terminal action” requires server-side enforcement. Mark narrowing/reserved bits and missing `hwOffload` readback also require correction. Hardware admission rejects IPv6, non-/32 IPv4 prefixes, port ranges, TCP-specific and UDP-specific matches; admission is not proof of hardware installation. Evidence: [rules.go:175](../../pkg/loxinet/rules.go:175).

**H3 — doc-defect / implementation-gap: IP-filter semantics need precision.**
POST permits only zone zero; priority omission means 100 while explicit zero remains zero. Only whitelist+allow and blacklist+drop are accepted. DELETE narrows zone without validation and does not use it in the key.

Replacement:

> “Source-prefix filter evaluated at XDP. Zone must be zero or omitted. Each list performs longest-prefix matching; when both lists match, higher priority wins and whitelist wins ties. Reposting the same list/prefix replaces its map entry and resets its counters.”

Evidence: [ipfilter.go:30](../../api/restapi/handler/ipfilter.go:30), [llb_kern_ipfilter.c:54](../../loxilb-ebpf/kernel/llb_kern_ipfilter.c:54), [loxilb_libdp.c:2759](../../loxilb-ebpf/kernel/loxilb_libdp.c:2759).

**H4 — doc-defect: security-rate inputs are full replacement, not default-filled PATCH.**

Replacement:

> “Supply all enable flags and thresholds. Thresholds must be within 0–16,777,216; UDP bandwidth within 0–4095 MiB/s. Enabled protections require positive applicable thresholds; enabled SYN protection additionally requires `cookieThreshold < synThreshold`. At least one protection must be enabled. Supply at most 1024 whitelist CIDRs. Omitted whitelist replaces the previous list with an empty list.”

Evidence: [securityrate.go:49](../../api/restapi/handler/securityrate.go:49).

**H5 — implementation-gap: effective configuration and security claims can diverge.**

- Explicit cookie threshold zero passes admission but becomes 50 in the datapath.
- Configuration is programmed before whitelist replacement; later failure leaves partial changes.
- Security-rate whitelist and IP-filter whitelist share maps without independent ownership.
- The inspected cookie branch only increments telemetry; it does not generate or validate SYN cookies.
- Connection rate counts SYN packets, not established connections.
- Tracking-map insertion failure passes traffic.

Evidence: [dpebpf_linux.go:3695](../../pkg/loxinet/dpebpf_linux.go:3695), [dpebpf_linux.go:3792](../../pkg/loxinet/dpebpf_linux.go:3792), [llb_kern_synflood.c:345](../../loxilb-ebpf/kernel/llb_kern_synflood.c:345), [llb_kern_synflood.c:552](../../loxilb-ebpf/kernel/llb_kern_synflood.c:552).

Replace “Enable SYN cookies” with:

> “Threshold for SYN-cookie-related telemetry; the inspected implementation increments a counter but does not implement a SYN-cookie exchange.”

**H6 — implementation-gap / doc-defect: reset and GET are not proof of clean state.**
DELETE does not clear tracking maps. Reset writes counters individually, logs failed writes, and still returns success. `uniqueIps` is calculated from tracking-map occupancy, not reset with counters; stats-fetch failures can yield zero statistics.

Evidence: [dpebpf_linux.go:4006](../../pkg/loxinet/dpebpf_linux.go:4006), [dpebpf_linux.go:4118](../../pkg/loxinet/dpebpf_linux.go:4118).

### I. Conntrack and port readback

**I1 — doc-defect / implementation-gap:** conntrack totals combine eBPF and reported hardware counters; `ageMs` is never populated by this handler. Backend table-read errors can become an empty successful result. Signed counter conversion can lose unsigned range.

Evidence: [conntrack.go:47](../../api/restapi/handler/conntrack.go:47), [dpbroker.go:1094](../../pkg/loxinet/dpbroker.go:1094).

Replacement:

> “Returns gateway datapath connection records, not the host’s complete operating-system conntrack table. Hardware fields are optional; `ageMs` is currently unavailable from this operation.”

**I2 — doc-defect / implementation-gap:** `portProp` is a property bitmask, not priority, but `PortsToGet` does not populate it. Address arrays contain at most the first formatted address with a `(P)/(S)` marker, or an empty string—not all raw addresses. Link and administrative state must remain distinct.

Evidence: [port.go:650](../../pkg/loxinet/port.go:650), [layer3.go:468](../../pkg/loxinet/layer3.go:468).

## 3. Explicit UNREVIEWED / incomplete items

- **No assigned Swagger operation remains un-inventoried.** However, this checkpoint is not exhaustive verification of every transitive consumer.
- Linux/netlink library and kernel admission rules, actual interface mutations, synchronization timing, and rollback behavior were not executed or exhaustively inspected.
- Remote GoBGP server validation, all AFI/SAFI/community grammars, and remote error-to-HTTP outcomes remain unreviewed.
- Complete DOCA SDK/plugin enforcement, hardware counter accuracy, mirror/policer packet processing, and all feature-flag combinations remain unreviewed.
- Full health-probe utility implementations, certificate-store behavior, scheduler edge cases, and concurrent endpoint changes remain incomplete.
- Generated middleware’s complete validation-status/envelope behavior and every generated validator were not exhaustively traced.
- IPsec, LB implementation beyond direct networking dependencies, auth internals, and operational endpoints remain outside this ownership scope.
- Concurrent WIP prevents treating these observations as one immutable, atomic source snapshot. Re-anchor references against the final documentation-edit snapshot.

**Parent handoff:** documentation-only corrections can proceed from the replacements above when authorized. Keep implementation-gap and policy-needed items visibly open; do not mark Swagger/implementation parity or runtime readiness complete.
