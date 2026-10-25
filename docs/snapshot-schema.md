# Network snapshots and verification

Snapshots are local evidence documents. They contain no executable instructions,
and loading or comparing a snapshot does not apply settings, invoke PowerShell or
start a repair. The examples in this repository are synthetic.

## Schema version 1

The root contains `format: "winnetdiff.snapshot"`, integer `schema_version: 1`,
application version, locale, creation and observation timestamps, a user label,
`privacy` (`redacted` or `full`), `cancelled`, `collection_errors`, `completeness`
and `categories`.

Each category is an array of `{ "id": "24 lowercase hex characters", "value": {} }`.
In 2.2.0a3, an ID is a 24-hex HMAC-SHA256 prefix over the category-specific identity,
keyed with the installation's local pseudonym key (`identity_scheme: hmac-sha256-v1`).
It prevents raw interface GUIDs, IP addresses or paths from appearing as lookup keys
while enabling comparison **within the same installation/key only**. This is
pseudonymization, not cryptographic anonymization: inventories can still identify
a machine, and compromise of the local key permits dictionary attacks. Older
unkeyed SHA-256 IDs are described separately below; keyed and unkeyed snapshots
must not be compared.

| Category | Data retained | Stable identity |
|---|---|---|
| `adapters` | Name, description, index, status, physical/virtual evidence | Interface GUID when available; otherwise name/index |
| `routes` | Prefix, next hop, interface, metrics, state | Family, prefix, interface, next hop, policy store |
| `default_routes` | IPv4 and IPv6 defaults, including metrics | Same route identity |
| `dns` | Configured server addresses per interface/family | Interface and address family |
| `proxy` | User/machine/effective WinINET, WinHTTP and policy settings | Configuration scope |
| `environment` | Process, user and machine proxy/Node options | Environment scope |
| `services` | Registry start/type/path and WMI runtime state | Case-insensitive service name; sources retained separately |
| `drivers` | WMI and driverquery state, type, startup and path | Case-insensitive driver name; sources retained separately |
| `bindings` | Adapter, ComponentID, display name, Enabled | Case-insensitive adapter name and ComponentID |
| `security_providers` | Product name, signed product/reporting paths and state | Case-insensitive provider name |
| `installed_apps` | Product/version/publisher/install location and scope | Scope and uninstall registration key; documented identity fallback |

Missing data is different from an empty completed inventory. Each category has an
explicit boolean in `completeness`. A category whose query failed is not compared
for additions/removals. Cancelling a scan marks all categories incomplete, so a
partially collected snapshot cannot imply that an adapter or driver disappeared.

Timestamps and labels are metadata, not configuration changes. Transient memory
counters and command transcripts are excluded from the snapshot state. Full raw
reports remain a separate export.

## Import checks

The loader accepts UTF-8 JSON with an optional BOM. It rejects unsupported schema
versions, duplicate JSON keys, duplicate entry IDs, wrong category/type shapes,
NaN/Infinity, nesting beyond 40 levels, files over 25 MiB, text fields over 2 MiB,
and lists over 20,000 entries. Future schema versions require an explicit migration
instead of silently interpreting unknown fields. A snapshot filename is never
used as a shell command or a repair object.

Default exports apply report redaction, remove secret/credential fields and
pseudonymize common device identifiers. Full exports must be selected explicitly
by the calling CLI/GUI privacy confirmation. Comparing full and redacted snapshots
is refused because masking could otherwise create misleading changes. The caller
must use the same privacy mode for both observations. Saving a snapshot refuses
to overwrite an existing file.

## Differences

`compare_snapshots` returns `format: "winnetdiff.snapshot-diff"`, version 1,
observation labels/timestamps, privacy mode, `changes`, `counts` and
`unavailable_categories`. Each change contains `kind`, `category`, `id`, `before`,
`after` and dotted `changed_fields`.

The five kinds are `added`, `removed`, `enabled`, `disabled` and `changed`.
Enabled/disabled applies to explicit binding flags, scoped manual-proxy flags
and service startup state. A stopped service is not automatically described as a
disabled service. A metric change is a configuration change; it is not a removal.

These differences describe what changed. They do not prove that Windows Update,
a VPN installer or a particular driver caused the failure. A Windows update
relationship needs independent, user-confirmed timing or event evidence.

## Evidence grades and repair verification

Scenario hypotheses contain observed evidence, layer, reasoning, alternatives,
falsifiable verification steps, applicability conditions and repair risk.

- **E1, observed:** a measured state or individual attempt; cause unconfirmed.
- **E2, repeated:** the phase difference repeats across attempts or targets.
- **E3, corroborated:** repeated multi-target differential failures coexist with
  independent relevant configuration evidence; causality is still unproven.

These are evidence grades, not estimated probabilities. The regression fixture
`orphaned_endpoint_security_filter` raises the investigation priority when TCP
succeeds before repeated TLS failures and independent orphan evidence is present.
The same filter names with working probes and an installed owner do not produce
that conclusion. The historical fixture includes synthetic ICMP context. The current release also
supports a separate, consented auxiliary IPv4 DF/PMTU probe, whose results alone
do not prove a path-MTU black hole.

`compare_verification` requires the same domains, captured scan options and
matching host/family observations. Cancelled scans, missing parameters, duplicate
observations or changed targets produce `incomparable`. Protocol progress or a
higher HTTP-response rate can produce `improved`; any protocol regression produces
`regressed`. An unchanged failure or merely faster timing produces `not_verified`.
Resolved-IP changes are stated as an alternative explanation. Configuration
changes alone never verify that network access improved, and a successful API
return never by itself becomes a successful-repair claim.

### 2.1.0b2 evidence context

E2/E3 measurement paths require explicit host, family, destination IP, port, SNI, method, request path and TCP/TLS/HTTP budgets. Missing context stays E1. Independent-target comparisons require matching family/request/budgets; SNI may follow each target. Persistent failures are computed per concrete path, and unrelated IPv6 intermittence does not cancel IPv4 evidence. Historical 2.1.0b2 E3 required an enabled-binding Service link. The 2.2.0a2 contract also accepts independently observed running WFP/service orphan candidates without NDIS bindings, with complete installed-app/registration inventories, owner checks and shared-host safeguards. Names, classification status, priority zero and overall-budget exhaustion cannot supply that corroboration.

### Keyed entry identities (2.2.0a2 candidate)

Snapshots written by this version add two top-level fields. `identity_scheme` is `hmac-sha256-v1`: entry `id` values are 24 hexadecimal characters of HMAC-SHA256 under the installation's pseudonym key (see PRIVACY.md), so a published redacted snapshot no longer lets anyone enumerate private next hops, interface indexes or prefixes back from its IDs. `identity_key_id` is a 16-hex fingerprint derived from that key; it reveals nothing about the key and exists only to detect mismatches. Comparison requires equal schemes and key fingerprints. Files without these fields are earlier unkeyed snapshots: they still load and compare with each other, but not with keyed snapshots, so a baseline taken before this change must be recreated. `schema_version` stays 1 because entry structure and categories are unchanged.
