# Tenable Plugin Specification

**A read-only collector for Tenable Security Center (on-prem first) that on a schedule reads vulnerability findings and the plugin metadata behind them and writes them to the grid as Tenable-owned nodes holding Tenable's data as Tenable returns it, with a per-plugin parser step that extracts, from each finding's plugin output, whatever ties the finding to a package, software or application, so a vulnerability detection and response implementation can read what Tenable knows without going to Tenable.**

## Plugin Identity

| Field | Value |
| --- | --- |
| Slug | `tenable` |
| Display name | TAP Tenable |
| Description | A read-only collector for Tenable Security Center that lands vulnerability findings, the plugin metadata behind them and per-plugin package observations on the grid. |
| Kind | Leaf plugin: links to `compliance_core` (the shared vulnerability, by edge, never written) and `computing_core` (the package, by edge, only when a parser's result is unambiguous); read by VDR plugins through the grid, with no import. |

**Default dimensions.**

| Key | Value | Why |
| --- | --- | --- |
| `tenable.area` | `run` on scanner and scan-run nodes; `finding` on finding nodes; `plugin` on plugin nodes | Lets a page or Search group the Tenable-specific nodes without listing types. The key is namespaced by this vocabulary, which only this plugin gives meaning. The `compliance_core` and `computing_core` nodes this plugin links to keep their owners' dimensions and receive none from here. |

## Philosophy

Tenable already does the hard part: it scans, matches plugins and scores what it finds. A vulnerability detection and response implementation needs those answers on the grid, next to everything else the grid knows, with their provenance. This plugin carries them across. It does not scan, does not decide what a finding means for any compliance factor, and never changes Tenable. It carries Tenable's data as Tenable returns it and does not interpret, consolidate or judge it: no severity scale, risk model or mapping is applied. How an organisation reads Tenable beside its other scanners is a later layer.

Seven consequences shape v0:

1. **Never mutates Tenable.** Security Center's only read path for findings is `POST /analysis`, so "GET only" cannot be the rule. The rule is that the transport permits an enumerated list of method-and-path pairs (the analysis query and plain GET reads) and refuses everything else, so the credential can be a read-only role and a bug here cannot change Tenable.
2. **Tenable's data in Tenable's shape; link, never merge.** Scanner, scan run, finding and plugin are Tenable-owned nodes. The shared vulnerability and the package are other plugins' nodes, reached by edge. Nothing Tenable says is written into a record another producer shares.
3. **Three states, never two.** A scope that could not be read, a scope the instance does not offer, a plugin with no parser, and a parser that failed are each recorded as such and never as clean or as "no package". A fact nothing observed is `null`. A run resolves only what that run read.
4. **A filter changes what "read" means.** Every run records the exact filter it applied. A finding resolves only when a read that included it in scope no longer reports it; a window filter (a recency window) excludes findings that are still open, so a run using one never resolves anything.
5. **The package is a per-plugin fact.** Security Center gives a CPE that belongs to the plugin and free-text plugin output that belongs to the finding; the installed package, version and path live only in that text, in a shape that differs by plugin. So extraction is one parser per plugin, as an explicit, countable, testable list, and a plugin without one is recorded as having none, never as having no package.
6. **There is no vendor contract file.** Security Center publishes no OpenAPI file, so the extract-and-drift machinery of sibling collectors has nothing to reduce from. Responses are validated against schemas written from the vendor's documented examples, marked *documented* until a recorded response replaces them.
7. **The supported versions are data.** Which upstream versions the plugin is known to work with, and on what evidence, is a committed file the probe reads, not prose.

**Prior art, and what it changed.** Surveyed 2026-11-06 from documentation and package metadata, not by running against an instance. `pyTenable`'s `tenable.sc.analysis` (documented in its source and docs) supplied the read path (one analysis endpoint, a `tool` per view, offset paging, filters per tool) and the client we build on; it defaults `ssl_verify` to false and its session login is a POST to `/token`, so we always pass verification explicitly and reach only the key-auth path. Tenable's own API reference supplied the request body, the example finding fields, the separate `/plugin` objects and the `x-apikey` header (keys need Security Center 5.13 or later). Tenable VM's findings export (a POST job with polled status and chunks) shows the cloud transport is a different wire behind the same vocabulary, which is why cloud is a Backlog requirement. `anchore-tap` (this organisation) supplied the structure this plugin inherits: findings keyed by what they assert, resolve only what was read, three states, operator settings never read from user-editable nodes, a per-run probe, and provenance markers. On supported-version declaration, Grafana's `grafanaDependency` and Elastic's `conditions.kibana.version` showed a declared range checked by tooling (and Grafana's plugin that shipped an open-ended range and failed to load on a newer release showed why a range must not hard-enforce); Home Assistant keeps upstream firmware requirements in documentation and warns, which we adopt as the posture. No source declares evidence level beside a range; that is ours.

**Provenance markers.** *Documented* (read from Tenable's API reference pages, pyTenable's source and docs and PyPI metadata, 2026-11-06): every endpoint, field and header named below. *Designed* (this document): every node, edge, key, filter, parser rule and verdict. *Observed*: nothing. No Security Center has been called. Every parser, field mapping, filter value format and "works on version X" claim is provisional until a recorded response from a real instance replaces it, and no requirement below reaches `Implemented` on a documented claim alone.

## Goals

| # | Name | Description |
| --- | --- | --- |
| 1 | Everything Tenable Knows About A Finding | Findings and the plugin metadata behind them reach the grid with Tenable's fields as returned. |
| 2 | Never Mutates Tenable | Only an enumerated list of read operations can leave the client; a read-only credential is enough. |
| 3 | Never Clean By Omission | A scope not read, a plugin with no parser and a parser that failed are recorded as such; unobserved facts are `null`. |
| 4 | Package Association Per Plugin | Whatever ties a finding to a package, software or application is extracted by one parser per plugin and kept beside the raw text. |
| 5 | Down-Select At The Source | Filters narrow what is read, with the filter recorded and resolution made safe by construction. |
| 6 | Know What Is Supported | The upstream versions and the evidence for each are a committed file the run checks and reports against. |
| 7 | Tenable's Shape, Linked | Tenable's data is stored as Tenable returns it in Tenable-owned nodes, linked to the shared nodes it concerns; no interpretation is applied. |
| 8 | Backend Only | No page or panel ships; the outputs are nodes and edges other surfaces read. |

## Requirements

| RID | Name | Status | Notes |
| --- | --- | --- | --- |
| req-tenable-connection | [Connection And Credential](#connection-and-credential) | Proposed | One operator-owned secret envelope per Security Center instance; TLS verification on unless the operator turns it off, and every run that does says so |
| req-tenable-transport | [The Guarded Transport](#the-guarded-transport) | Proposed | pyTenable's `TenableSC` over a session whose `send` permits only an enumerated list of operations; API keys only |
| req-tenable-probe | [Probe And Provenance](#probe-and-provenance) | Proposed | Version, status and repositories read first and recorded on the run |
| req-tenable-upstream-versions | [Supported Upstream Versions](#supported-upstream-versions) | Proposed | A committed file of supported ranges with an evidence level each; the probe's verdict is warn, or error below a hard floor |
| req-tenable-response-contract | [Response Contract](#response-contract) | Proposed | Hand-written schemas from documented examples, validated before any node is written |
| req-tenable-states | [Three States And Resolution](#three-states-and-resolution) | Proposed | Not read is never clean; null is unobserved; a run resolves only what it read |
| req-tenable-scope | [Scope Filters](#scope-filters) | Proposed | Server-side filters in the envelope; scope filters versus window filters; the filter recorded on the run |
| req-tenable-scanner-run | [Scanner And Scan Run](#scanner-and-scan-run) | Proposed | The instance and each collection, with the probe, filter, TLS and parse counts |
| req-tenable-plugin | [Plugin Metadata](#plugin-metadata) | Proposed | A Tenable-owned node per plugin from `GET /plugin/{id}` |
| req-tenable-findings | [Findings](#findings) | Proposed | A node per assertion, keyed by what it asserts, with Tenable's fields as returned |
| req-tenable-vulnerability-link | [Shared Vulnerability Link](#shared-vulnerability-link) | Proposed | One edge per CVE, only to an existing `compliance_core` vulnerability with that exact id |
| req-tenable-parsers | [Per-Plugin Package Parsers](#per-plugin-package-parsers) | Proposed | One parser module per plugin, a registry, four parse states, a fixture and a test each |
| req-tenable-package-link | [Package Link](#package-link) | Proposed | An edge to a `computing_core` package only when a parser's result is unambiguous |
| req-tenable-observe | [The Observation Command](#the-observation-command) | Proposed | A read-only command that records what an instance returns so shapes are observed before they are parsed |
| req-tenable-fips | [FIPS Posture](#fips-posture) | Proposed | Declared from what the validator reports; no `cryptography` extra |
| req-tenable-software-enumeration | Host Software Enumeration | Backlog | The `listsoftware` tool parsed into `computing_core` host-package data, as another per-plugin-style parser |
| req-tenable-host-enrichment | Host, Address And Port Enrichment | Backlog | Create or enrich `computing_core` hosts, addresses and ports from findings |
| req-tenable-cloud | Tenable VM Transport | Backlog | The cloud findings export (a POST job, a status poll, chunk downloads) as a second transport behind the same vocabulary |
| req-tenable-scopes-list | Named Scopes Per Envelope | Backlog | A list of named filter sets per instance, each read and resolved independently |
| req-tenable-drift | Vendor Contract Drift Check | Backlog | A scheduled comparison against a vendor contract file, if Tenable publishes one for Security Center |
| req-tenable-nongoals | [v0 Non-Goals](#v0-non-goals) | Proposed | What this plugin deliberately does not do, and who owns it |

### Connection And Credential
----
RID: `req-tenable-connection`

Status: `Proposed`

How the collector knows which Security Center to read and how to authenticate. The base URL, the keys, the TLS settings and the scope filter live together in one operator-owned secret envelope per instance, never in a field on a grid node: whoever can edit a node must not be able to point a credential at another host or quietly narrow what a compliance view sees.

#### Implementation

The secret is a plugin secret: its consumer is the Tenable collector, so the envelope's scope is `tenable`, its key is chosen by the operator to name the instance, and the file is `<key>.secret.json` under the secrets root, never in a repository. Its kind is `tenable_sc_credential`, a kind this plugin owns: the collector validates `data` against `tap_plugin/tenable/schemas/tenable_sc_credential.schema.json` (strict, a `description` on the top level and every field) with `require_secret_kind` before any request. `data` holds:

- `base_url`: the Security Center root, such as `https://sc.example:443`. `http://` or `https://` exactly as written, and the client never changes it. Required. An `http://` URL sends the API keys and every response across the network unencrypted, so each run that uses one records a `PLAINTEXT_TRANSPORT` warning on the scan run and the observation command prints one; the scheme is part of the scanner key, so the two are different scanners.
- `access_key`, `secret_key`: the API keys of a Security Center user with API-key authentication enabled. Required.
- `ssl_verify`: boolean, optional, default `true`. `false` is honoured, because the operator knows the network, and every run it applies to records a `TLS_VERIFICATION_DISABLED` warning on the scan run and the observation command prints one.
- `ca_bundle`: the absolute path of a PEM file on the host, never its contents. Optional.
- `scope`: the filter object of `req-tenable-scope`. Optional.

The envelope's description states the least-privilege shape: a read-only role whose reach is limited to the repositories to be read. The collector reads every envelope in scope `tenable`; each yields one scanner whose key is derived from the canonical root of `base_url` (`req-tenable-scanner-run-2`). An envelope that fails validation fails only its own run, naming `tenable:<key>`. These credentials have no scannable shape, so no `CredentialPattern` and no entropy rule is added; protection rests on the envelope layer, the leak guard, `.gitignore` and redaction: the keys reach pyTenable as constructor arguments, no object holding them shows them in its `__repr__`, and no log line, scan-run field or exception carries a value.

#### Acceptance Criteria

| ACID | Title | Status | Description | Notes |
| --- | --- | --- | --- | --- |
| req-tenable-connection-1 | Settings Are Not Nodes | Proposed | No node type declares a base URL, key, TLS setting or filter field, and the collector reads none from the grid. | |
| req-tenable-connection-2 | Secret Never Echoed | Proposed | The keys are absent from logs, scan-run properties and exception text, including when a request fails, and from every `__repr__`. | A test fails a request and searches all of them. |
| req-tenable-connection-3 | Verification On By Default | Proposed | `ssl_verify` defaults to `true` and the client always passes it explicitly; an absent field never reaches pyTenable's own default of false. | |
| req-tenable-connection-4 | Disabled Verification Is Recorded | Proposed | A run with `ssl_verify: false` records `TLS_VERIFICATION_DISABLED` on its scan run. | The operator's choice, stated and warned. |
| req-tenable-connection-9 | Plaintext Is Recorded | Proposed | A run whose `base_url` is `http://` records `PLAINTEXT_TRANSPORT` on its scan run, the observation command prints it, and any other scheme is refused before any request. | An HTTP-only instance on an isolated network is the operator's call; it is stated and warned, never silent. |
| req-tenable-connection-5 | Strict Base URL | Proposed | A `base_url` with userinfo, a query or a fragment is refused before any request; host and scheme are lower-cased and the path is preserved, so one instance has one key however its URL is spelled. | |
| req-tenable-connection-6 | One Envelope Per Instance | Proposed | Two envelopes yielding the same scanner key refuse the run before any request, naming both. | |
| req-tenable-connection-7 | Strict Credential Schema | Proposed | The `tenable_sc_credential` schema is strict, with no field missing and every field described; a wrong kind or shape fails that instance's run before any request, naming `tenable:<key>` and never a value. | |
| req-tenable-connection-8 | Undetectability Is Recorded | Proposed | The spec states these credentials have no scannable shape; a test asserts no `CredentialPattern` was added. | Silence would look like coverage. |

### The Guarded Transport
----
RID: `req-tenable-transport`

Status: `Proposed`

How requests leave the plugin. pyTenable's `TenableSC` is the client; every request it makes passes through a `requests.Session` subclass the plugin supplies, and that subclass decides what may be sent.

#### Implementation

The dependency is `pytenable==X.Y.Z` pinned exactly in `pyproject.toml` (a range is a defect), with no extra: the `pkcs12` and `all` extras pull in `cryptography`, whose wheels bundle their own OpenSSL (`req-tenable-fips`). `TenableSC(url=…, access_key=…, secret_key=…, ssl_verify=…, session=<guarded session>)` is the only construction. The guard is in `Session.send`, so remounting an adapter does not bypass it, and the client does not expose its session. `send` refuses before anything is sent: any URL outside the configured root; any redirect; any override of verification, client certificate or proxies; and any method-and-path pair not on the allowlist:

- `POST /rest/analysis`, whose body has `type: "vuln"` and no other type, and never `/rest/analysis/download`;
- `GET /rest/plugin` and `GET /rest/plugin/{id}`;
- the system and status reads pyTenable and the probe make (`GET /rest/system`, `GET /rest/status`, `GET /rest/repository`), each listed by name.

Authentication is by API keys only (`X-APIKey: accessKey=…; secretKey=…`, Security Center 5.13 or later). pyTenable's session login is `POST /token`, which is not on the allowlist, so that path is unreachable; a Security Center older than 5.13 is not supported (`req-tenable-upstream-versions`). The allowlist is the plugin's one definition of "read", and a change to it is a spec change.

#### Acceptance Criteria

| ACID | Title | Status | Description | Notes |
| --- | --- | --- | --- | --- |
| req-tenable-transport-1 | Allowlist At The Transport | Proposed | Every request passes through one `send` that refuses any method-and-path pair not on the list; `POST /token`, `DELETE`, `PATCH`, an aliased method and a request from another module are each refused. | Negative tests for each; a source scan is only secondary. |
| req-tenable-transport-2 | Analysis Is Query-Only | Proposed | A `POST /rest/analysis` with a body type other than `vuln` is refused, and `/rest/analysis/download` is never reachable. | |
| req-tenable-transport-3 | Bound To The Root | Proposed | A request to any other host, port, scheme or path root is refused, and so is any redirect, before a second request. | The session holds the keys. |
| req-tenable-transport-4 | Bounded Retries | Proposed | Retries are limited in count and total time and honour `Retry-After`; exhaustion is a recorded failure, never an empty result. | Ties to `req-tenable-states`. |
| req-tenable-transport-5 | Exact Pin, No Crypto Extra | Proposed | `pyproject.toml` pins `pytenable` with `==` and names no extra; a test asserts both. | |
| req-tenable-transport-6 | Verification Cannot Be Overridden | Proposed | A per-request `verify`, `cert` or `proxies` override is refused by `send`; the CA bundle is applied on the session by the plugin only. | Whether pyTenable honours a session-level `verify` is unobserved; a test settles it. |

### Probe And Provenance
----
RID: `req-tenable-probe`

Status: `Proposed`

Before reading data, the collector asks the instance what it is and which repositories its credential can see, and records the answer on the scan run, so a finding can be judged against the data behind it.

#### Implementation

Reads the system and status endpoints and the repository list (`req-tenable-transport`), each optional except the repository list the scope walk needs. Recorded on the scan run: the base URL host, the reported Security Center version, the repositories (id, name, `dataFormat`) and the verdict of `req-tenable-upstream-versions`, each `null` when the instance did not answer. An unreadable version is `null` and never a pass. A repository whose `dataFormat` is not one of the two documented values (`IPv4`, `universal`) is recorded as read-with-unknown-format and its findings are not stored (`req-tenable-findings-3`).

#### Acceptance Criteria

| ACID | Title | Status | Description | Notes |
| --- | --- | --- | --- | --- |
| req-tenable-probe-1 | Probe Before Data | Proposed | The probe completes before any finding is read, and its results are on the scan run. | |
| req-tenable-probe-2 | A Refused Probe Is Null | Proposed | An optional probe read the instance refuses leaves its field `null` and the run continues. | |
| req-tenable-probe-3 | Repository List Is Required | Proposed | A run that cannot read the repository list ends before any scope is read, recorded as an error. | |

### Supported Upstream Versions
----
RID: `req-tenable-upstream-versions`

Status: `Proposed`

Which upstream versions this plugin is known to work with, and on what evidence, as a committed data file. The manifest has no field for this (it rejects unknown keys, and its only compatibility field is `requires_tap`), so the plugin carries it; a core manifest field is a separate proposal, and this file is shaped so it can move there unchanged.

#### Implementation

`tap_plugin/tenable/compat/upstream.json`, with a JSON Schema and a `description` on the top level and every entry. Each entry has `product` (`tenable_security_center`, `pytenable`), `supported` (a bounded version specifier, never open-ended), `evidence` (`documented`, `designed` or `observed`), `note`, and for `observed` the date and the recorded response it rests on. The seed entries are Security Center `>=5.13,<N` with evidence `documented` (API keys need 5.13, per pyTenable's own version check and Tenable's API-key page; the upper bound is the highest version the documentation describes) and `pytenable` at the exact pinned version. After the probe reads the instance version, the collector records one verdict on the scan run:

- **observed**: inside a range whose evidence is `observed`;
- **documented-only**: inside a range whose evidence is `documented` or `designed`, never seen;
- **outside**: above or between ranges, or below the soft bound; a warning, and the run continues, because every response is still validated (`req-tenable-response-contract`);
- **unreadable**: no version obtained; recorded as such and never a pass.

A version below the hard floor (no API-key authentication, so the credential cannot work at all) is an error that ends the run. The README table and any version text in this spec are generated from the file, never hand-copied.

#### Acceptance Criteria

| ACID | Title | Status | Description | Notes |
| --- | --- | --- | --- | --- |
| req-tenable-upstream-versions-1 | Data, Schema-Validated | Proposed | The file validates against its schema, every entry has a `description`, and a specifier with no upper bound is rejected. | Grafana's open-ended range failed on a newer release. |
| req-tenable-upstream-versions-2 | Evidence Cannot Be Claimed | Proposed | An entry with evidence `observed` names a date and a recorded response; a test rejects one that does not. | We are blind; nothing starts observed. |
| req-tenable-upstream-versions-3 | Four-State Verdict | Proposed | The scan run carries exactly one of observed, documented-only, outside, unreadable. | Three states, never two. |
| req-tenable-upstream-versions-4 | Warn, Do Not Refuse | Proposed | An outside version is a recorded warning and the run continues; only a version below the hard floor is an error. | |
| req-tenable-upstream-versions-5 | Derived Once | Proposed | The README table is generated from the file, and a test fails when they differ. | |

### Response Contract
----
RID: `req-tenable-response-contract`

Status: `Proposed`

Security Center publishes no contract file, so there is no extract to generate and no vendor file to drift against. In its place, schemas written by hand from the documented examples, and a rule that no response becomes a node without passing them.

#### Implementation

`tap_plugin/tenable/contract/analysis.schema.json` and `plugin.schema.json`, with a `description` on the top level and every entry. They describe the documented envelope (`type`, `response.results`, `totalRecords`, `returnedRecords`, `error_code`, `error_msg`) and the documented finding and plugin fields. Most scalar values are JSON strings, including ports and epoch timestamps, and the schemas say so. A field the schemas do not name is tolerated and not stored; a missing required key field fails that repository's scope (`req-tenable-findings-3`). Paging does not trust `totalRecords`, which pyTenable notes is not always returned: a page shorter than the requested size ends the walk, a page equal to the cap is recorded as possibly truncated, and the record ceiling of `req-tenable-scope` is a recorded stop. Recorded responses from a real instance, once they exist, are committed (trimmed and reviewed) beside the schemas as fixtures and replace the assumed shapes.

#### Acceptance Criteria

| ACID | Title | Status | Description | Notes |
| --- | --- | --- | --- | --- |
| req-tenable-response-contract-1 | Validate Before Write | Proposed | Every analysis and plugin response is validated before any node is written; a required scope that fails is an error and an optional one is recorded as not read. | |
| req-tenable-response-contract-2 | Strings Stay Strings | Proposed | Values documented as strings are stored as strings and never coerced. | A coercion would be interpretation. |
| req-tenable-response-contract-3 | Paging Does Not Trust The Total | Proposed | The walk ends on a short page, never on `totalRecords` alone, and a full-cap page at the ceiling is recorded as possibly truncated. | |
| req-tenable-response-contract-4 | No Network In The Suite | Proposed | The plugin's tests open no socket; the client is exercised against fixtures. | The `ci` record excludes network access. |
| req-tenable-response-contract-5 | Documented, Not Observed | Proposed | The schemas and fixtures carry a provenance note stating they derive from documented examples, until replaced by recordings. | |

### Three States And Resolution
----
RID: `req-tenable-states`

Status: `Proposed`

How the collector records absence. Every place absence can occur has three outcomes, and the plugin keeps them apart.

#### Implementation

A repository the credential cannot read, a call that failed after its retries, a page that failed validation and a scope the filter made incomplete are each recorded as *not read* on the scan run with the reason, never as zero findings. A field nothing observed is `null`; an observed-empty list is `[]`; an observed empty string stays `""`. The unit of reading, and so of resolution, is one repository: each is read with its own query, so "read successfully" has a precise meaning. A finding resolves only when its repository was read successfully by the same scanner in a run whose filter put it in scope, and it no longer appears; a repository not read keeps whatever it had (`req-tenable-scope`). Nothing is deleted: a finding no longer reported is `resolved`, and a returning one is reopened. The plugin node carries no `state`, because Tenable plugins are metadata and not assertions.

#### Acceptance Criteria

| ACID | Title | Status | Description | Notes |
| --- | --- | --- | --- | --- |
| req-tenable-states-1 | Not Read Is Not Clean | Proposed | A repository not read in a run produces no resolved findings and is listed as not read on the run. | |
| req-tenable-states-2 | Null Is Unobserved | Proposed | A field the response did not carry is `null`, never `""`, `0` or `false`. | |
| req-tenable-states-3 | Resolve Only What Was Read | Proposed | A finding resolves only when its repository was read successfully by the same scanner in a run whose scope included it, and it is no longer reported. | |
| req-tenable-states-4 | Truncation Blocks Resolution | Proposed | A repository read that ended at the record ceiling or on a validation failure resolves nothing. | |
| req-tenable-states-5 | Nothing Is Deleted | Proposed | A finding no longer reported is rewritten as `resolved`, with every other field as it was; a returning one is reopened. | |

### Scope Filters
----
RID: `req-tenable-scope`

Status: `Proposed`

Down-selecting what a run gathers. A filter changes what "read" means, so it can never turn "filtered out" into "fixed": every run records the exact filter it applied, and the options are divided into scope filters, which resolution can reason about, and window filters, which it cannot.

#### Implementation

The `scope` object in the envelope (`req-tenable-connection`). Every option is applied server-side in the analysis `query.filters`, so a narrow filter bounds the read as well as the stored data. The kind column is what resolution may rely on: a **scope** filter is checkable against a column the finding stores, a **non-resolving** filter narrows the read but names a fact the finding does not store (asset-list membership lives in Security Center, and a `patched` read is a different set from the current one), and a **window** filter excludes findings that are still open. The filter names and value formats are documented only and are probed by the observation command (a bad filter name returns the valid list, per pyTenable).

| Option | Security Center filter | Kind |
| --- | --- | --- |
| `repository_ids` | `repositoryIDs` | scope |
| `asset_ids` | `asset` | non-resolving |
| `min_severity` | `severity` (0 informational to 4 critical) | scope |
| `plugin_ids`, `plugin_families` | `pluginID`, `familyID` | scope |
| `exclude_plugin_ids` | not confirmed; client-side unless Security Center supports exclusion | scope |
| `ports`, `protocols` | `port`, `protocol` | scope |
| `exploit_available` | `exploitAvailable` | scope |
| `has_cve` | `cveID` | scope |
| `risk_status` | `acceptRiskStatus`, `recastRiskStatus` | scope |
| `source` | `sourceType`: `cumulative` or `patched` | non-resolving |
| `last_seen_within` | `lastSeen` | **window** |
| `max_records` | a ceiling per repository | safety |

A scope filter can be checked against a column the finding stores (repository, severity, plugin, family, port, protocol, exploit, risk status, CVE), so the collector knows whether a stored finding was in scope and resolves only those. A run that applies a window filter or a non-resolving filter is **incremental**, is recorded as such with the filter that made it so, and resolves nothing; only a run with scope filters alone, or none, resolves. Fail closed: a filter whose kind is not stated in this table is treated as non-resolving. An unknown option, an invalid value or a filter Security Center rejects refuses the run before any read and never widens it to everything. Saved Security Center queries (`query_id`) are not supported: their contents are not visible to the plugin, so it could not record the scope or say what is safe to resolve.

#### Acceptance Criteria

| ACID | Title | Status | Description | Notes |
| --- | --- | --- | --- | --- |
| req-tenable-scope-1 | Filter In The Envelope | Proposed | The filter is read only from the operator-owned envelope and never from a node. | |
| req-tenable-scope-2 | Filter Recorded On The Run | Proposed | The scan run records the canonical filter exactly as applied and whether the run was incremental. | |
| req-tenable-scope-3 | Window And Non-Resolving Never Resolve | Proposed | A run using `last_seen_within`, `asset_ids` or `source` resolves no finding, and is recorded as incremental with the filter responsible. | A filter of unknown kind is non-resolving. |
| req-tenable-scope-4 | Scope Resolves Only In Scope | Proposed | With scope filters alone, a finding resolves only if its stored columns satisfy every filter; a filter whose predicate the finding does not store cannot be a scope filter. | A finding outside the filter keeps what it had. |
| req-tenable-scope-5 | Invalid Filter Refuses | Proposed | An unknown option, a bad value or a rejected filter ends the run before any read; it never falls back to an unfiltered read. | |
| req-tenable-scope-6 | Ceiling Is A Recorded Stop | Proposed | Reaching `max_records` records the repository as possibly truncated and resolves nothing in it. | Ties to `req-tenable-states-4`. |
| req-tenable-scope-7 | No Saved Queries | Proposed | A `query_id` option is refused as unsupported. | The scope would be invisible. |

### Scanner And Scan Run
----
RID: `req-tenable-scanner-run`

Status: `Proposed`

The record of which instance was read and what each collection did.

#### Implementation

- `tenable_scanner` (`tenable.area: run`): one per Security Center instance, with `scanner_key` derived from the canonical root of `base_url` (lower-cased scheme and host, the port, the path as configured). `platform` is `security_center` (`vulnerability_management` is reserved for `req-tenable-cloud`). The reported version and the repositories are facts on the scanner, not part of its key. The previous-run facts the probe needs are properties of the scanner.
- `tenable_scan_run` (`tenable.area: run`): one per collection, `KEYLESS` with the reason that it records something this plugin did. It carries the probe results, the version verdict, the TLS and plaintext warnings, the applied filter and incremental flag, the repositories not read with reasons, and the counts of findings by parse state.
- `RUN_OF_SCANNER__tenable`: scan run to scanner.

#### Acceptance Criteria

| ACID | Title | Status | Description | Notes |
| --- | --- | --- | --- | --- |
| req-tenable-scanner-run-1 | Run Names What It Read | Proposed | The scan run carries the instance host, reported version, repositories, filter, verdict and warnings. | |
| req-tenable-scanner-run-2 | Distinct Roots Are Distinct Scanners | Proposed | The same host on a different port or path root yields a different scanner key; a test asserts it and asserts the key carries no credential. | |
| req-tenable-scanner-run-3 | Counts By Parse State | Proposed | The scan run records how many findings were parsed, had no parser, failed to parse or were not applicable. | The visible measure of parser coverage. |

### Plugin Metadata
----
RID: `req-tenable-plugin`

Status: `Proposed`

What Tenable says about the plugin that produced a finding, held once and linked from every finding it produced.

#### Implementation

`tenable_plugin` (`tenable.area: plugin`), natural key `(scanner_key, plugin_id)`, so two instances' feeds never share a node. Read from `GET /rest/plugin/{id}` for each distinct `pluginID` the run saw, with the fields named in the documented list: name, family (id, name, type), `cpe`, `xrefs`, `dependencies`, `requiredPorts`, `requiredUDPPorts`, `riskFactor`, `solution`, `seeAlso`, `synopsis`, `checkType`, the exploit fields, the CVSS, VPR and EPSS scores, and the publication and modification dates, each as returned. A plugin node is rewritten when its `pluginModDate` changes; the earlier version is kept as the grid keeps history. `ABOUT_PLUGIN__tenable`: finding to plugin. A plugin whose read failed leaves its finding with no plugin edge and is listed as not read.

#### Acceptance Criteria

| ACID | Title | Status | Description | Notes |
| --- | --- | --- | --- | --- |
| req-tenable-plugin-1 | One Node Per Plugin Per Scanner | Proposed | Two findings from one plugin on one scanner share one plugin node; the same plugin on two scanners is two nodes. | |
| req-tenable-plugin-2 | Fields As Returned | Proposed | Plugin fields are stored as Tenable returns them, with no scale, mapping or selection. | |
| req-tenable-plugin-3 | Revised On Modification | Proposed | A changed `pluginModDate` revises the node; an unchanged plugin is not rewritten. | |
| req-tenable-plugin-4 | Unread Plugin Is Visible | Proposed | A plugin that could not be read is listed as not read, and its findings are still written. | |

### Findings
----
RID: `req-tenable-findings`

Status: `Proposed`

How Security Center's vulnerability results become Tenable-owned nodes, each holding what Tenable returned in the form it returned it. This plugin writes no `compliance_core` node and changes no shared record.

#### Implementation

`tenable_finding` (`tenable.area: finding`): one per assertion. Its natural key is `(scanner_key, repository_id, host_key, plugin_id, port, protocol)`, every part a non-empty-or-observed-empty string and never null, because a null part is an unobserved hole and would mint a new node every run. `host_key` is derived by one function from three stored columns, as Anchore derives its package key: `uuid:<hostUUID>` when the repository is `universal` format and the host UUID is present, otherwise `ipdns:<ip>|<dnsName>` for `IPv4` format, and the model validates `host_key` against `host_uuid`, `ip` and `dns_name`. The reported `ip`, `dns_name`, `netbios_name`, `mac_address` and `operating_system` are stored beside it as returned. `port` and `protocol` are the strings Tenable returns, so `"0"` and `"TCP"` are observed values. The finding carries Tenable's fields as returned: `severity` (id, name), `risk_factor`, the base, temporal, VPR, CVSS v3 and v4 and EPSS scores, `exploit_available` and the exploit fields, the plugin family (`family_id`, `family_name`) so a family filter can be checked, `first_seen` and `last_seen` as the epoch strings returned, `accept_risk`, `recast_risk`, `has_been_mitigated`, the raw `cve` string, the plugin's `cpe` as it appears on the finding, and the raw `plugin_text`. It also carries `state` (`current` or `resolved`, null when never observed), `last_seen_run_id`, and the parse result of `req-tenable-parsers`.

#### Acceptance Criteria

| ACID | Title | Status | Description | Notes |
| --- | --- | --- | --- | --- |
| req-tenable-findings-1 | Keyed By Assertion | Proposed | A finding's key names the scanner, repository, host, plugin, port and protocol and never the run; two runs reporting the same assertion are one finding. | |
| req-tenable-findings-2 | Key Rests On Carried Facts | Proposed | Every key part is a column the model stores; `host_key` is validated against the columns it derives from. | `req-grid-entity-natural-key`: nothing computed in the collector. |
| req-tenable-findings-3 | An Unkeyable Entry Is Counted | Proposed | A result missing a required key field, or with neither a host UUID nor an IP, is not stored and is counted on the run; a read in which any entry was not stored resolves nothing in that repository. | Null is a hole, not an observed empty. |
| req-tenable-findings-4 | Fields As Returned | Proposed | Severity, scores, dates and flags are stored as Tenable returns them, with no enum, mapping, selection or coercion. | |
| req-tenable-findings-5 | Raw Evidence Kept | Proposed | The raw `plugin_text` and `cve` are stored unmodified beside any parse result. | A parser fix means re-parse, not re-collect. |
| req-tenable-findings-6 | Scanner In The Key | Proposed | The same assertion from two instances is two findings, and resolution is scoped to one scanner. | |

### Shared Vulnerability Link
----
RID: `req-tenable-vulnerability-link`

Status: `Proposed`

A finding names CVEs; the grid has a shared vulnerability node. This plugin links to it and never writes it.

#### Implementation

`ABOUT_VULNERABILITY__tenable`: finding to `compliance_core__compliance_vulnerability`, one per CVE in the finding's `cve` string (comma-separated, split exactly on the delimiter, no other normalisation), written only when a vulnerability with exactly that `vuln_id` already exists, compared exactly and case-sensitively. None is created or changed, and no alias is resolved. A finding with no CVE has no vulnerability edge and is stored all the same. `compliance_core` is a vocabulary dependency in `depends_on`, with a note.

#### Acceptance Criteria

| ACID | Title | Status | Description | Notes |
| --- | --- | --- | --- | --- |
| req-tenable-vulnerability-link-1 | Linked, Never Written | Proposed | The edge is written only against an existing exact-id vulnerability; the plugin never creates or patches `compliance_core` nodes. | |
| req-tenable-vulnerability-link-2 | One Edge Per CVE | Proposed | A finding with three CVEs and three matching nodes has three edges; an unmatched CVE has none and is still on the finding's raw `cve`. | |
| req-tenable-vulnerability-link-3 | No Interpretation | Proposed | No alias, case fold or format change is applied to a CVE id. | |

### Per-Plugin Package Parsers
----
RID: `req-tenable-parsers`

Status: `Proposed`

What ties a finding to a package, software or application is not a structured field in Security Center: the plugin's CPE names the product the plugin targets, and the installed package, version and path appear only in the free-text plugin output, in a shape that differs by plugin. So the package association is one parser per plugin.

#### Implementation

`tap_plugin/tenable/parsers/` holds one module per plugin, `plugin_<id>.py`. A parser is a pure function `parse(finding) -> list[PackageObservation]` with no I/O, where `finding` is the validated finding fields (`plugin_text`, `cpe`, `port`, `protocol` and the plugin id). A `PackageObservation` has `product`, `name`, `version`, `installed_path`, `fixed_version` and `evidence`, each nullable; `evidence` is the exact segment of the plugin output the values were read from. A parser registers itself by plugin id in a registry. The collector records, per finding, exactly one parse state:

- `parsed`: the plugin has a parser and it returned observations (an empty list is a recorded, observed result);
- `no_parser`: the plugin has none; **never "no package"**;
- `parser_failed`: the output did not match the parser; the raw text is kept and the failure is counted on the run;
- `not_applicable`: the plugin is known to carry no package information, by an explicit entry in the registry.

The observations, the state, the parser's id and its version are stored on the finding beside the raw text; parsing edits no stored Tenable field, so a parser improvement re-parses stored findings without re-collecting. Every parser ships with a fixture of real plugin output at `tests/fixtures/plugin_<id>.txt` and a test; because v0 is built blind, the first fixtures come from public plugin descriptions and examples and are marked *documented*, and a parser does not reach `Implemented` until a recorded response from a real instance replaces its fixture. The first parsers are written for the highest-volume plugins an instance returns, chosen from the observation command's report rather than guessed. Host software enumeration (`req-tenable-software-enumeration`) is a later parser of the same contract.

#### Acceptance Criteria

| ACID | Title | Status | Description | Notes |
| --- | --- | --- | --- | --- |
| req-tenable-parsers-1 | One Module Per Plugin | Proposed | A plugin's parser is `parsers/plugin_<id>.py` and registered by plugin id; a test fails when a module exists that is not registered, or the reverse. | Which plugins can be read is an explicit, countable list. |
| req-tenable-parsers-2 | Four Parse States | Proposed | Every finding carries exactly one of `parsed`, `no_parser`, `parser_failed`, `not_applicable`; a test asserts no finding is left without one. | |
| req-tenable-parsers-3 | No Parser Is Not No Package | Proposed | A finding whose plugin has no parser is recorded `no_parser`, with no observations and no claim about packages. | Three states. |
| req-tenable-parsers-4 | Pure And Fixtured | Proposed | A parser performs no I/O and has a fixture and a test; a parser without either fails the suite. | |
| req-tenable-parsers-5 | Raw Text Unchanged | Proposed | Parsing leaves `plugin_text` and every Tenable field as received. | |
| req-tenable-parsers-6 | Evidence Quoted | Proposed | Each observation carries the exact output segment it came from. | A reviewer can check a parse by eye. |
| req-tenable-parsers-7 | Failure Is Counted | Proposed | A parser that does not match is `parser_failed`, counted on the scan run, and never raises past the finding. | One bad plugin output must not stop a run. |
| req-tenable-parsers-8 | Fixtures Are Marked | Proposed | A fixture states whether it is documented or observed; a parser with a documented fixture is not `Implemented`. | |

### Package Link
----
RID: `req-tenable-package-link`

Status: `Proposed`

Connecting an observation to the grid's package node, but only when that connection is a fact and not a guess.

#### Implementation

`FOUND_IN_PACKAGE__tenable`: finding to `computing_core__package`, written only when a parser's observation supplies exactly the ecosystem, name and version that `computing_core` keys a package by, and the parser declares that mapping unambiguous. Otherwise the observation stays on the finding and no edge is written. Mapping a vendor product name onto an ecosystem is interpretation, so each parser states its own mapping, and the edge is never inferred from the plugin's CPE alone. `computing_core` is a vocabulary dependency in `depends_on`, with a note.

#### Acceptance Criteria

| ACID | Title | Status | Description | Notes |
| --- | --- | --- | --- | --- |
| req-tenable-package-link-1 | Unambiguous Or Not At All | Proposed | An edge is written only when ecosystem, name and version are all supplied by the parser and the parser declares the mapping unambiguous. | |
| req-tenable-package-link-2 | Never From The CPE Alone | Proposed | A plugin's CPE alone never produces a package edge. | The CPE names the plugin's target, not an installed version. |
| req-tenable-package-link-3 | Observation Stays On The Finding | Proposed | A finding with an observation and no edge still carries the observation. | |

### The Observation Command
----
RID: `req-tenable-observe`

Status: `Proposed`

An instrument for the first sessions against a real instance, and for any later one: it reads an instance through the guarded transport in a fixed order, records every raw response locally, and reports which assumptions the responses settled. It is not the collector and writes nothing to the grid. It exists so shapes are observed before they are parsed.

#### Implementation

`tap_plugin/tenable/observe.py`, run as `python -m tap_plugin.tenable.observe --list` to see the envelopes and `--key <key>` to observe one (`--dry-run` prints the plan and sends nothing). It reads, through the allowlist only: the probe reads, the repository list, a first page of findings per repository, a sampled plugin's `GET /plugin/{id}`, the valid filter names (by sending a known-bad filter, which the allowlist permits as an ordinary analysis query), and a ranked count of findings by plugin id so the first parsers are chosen from data. A response is saved as one JSON file with its status, the header names that cannot carry a credential, and the body, under a private directory outside any repository; the report prints shapes, counts and statuses, never a body, a key, or a host or asset name. A step with a missing prerequisite is recorded as *not read* with the reason. Recordings are never committed; a fixture is committed only after the operator has reviewed a trimmed copy.

#### Acceptance Criteria

| ACID | Title | Status | Description | Notes |
| --- | --- | --- | --- | --- |
| req-tenable-observe-1 | Only The Allowlist | Proposed | Every request passes the transport's allowlist; a path outside it is refused before any request. | |
| req-tenable-observe-2 | Local And Private | Proposed | Recordings are written outside any repository with owner-only permissions, and nothing is written to the grid. | The repository is public. |
| req-tenable-observe-3 | Nothing Sensitive Printed Or Saved | Proposed | The report and recordings contain no key in any form, and the report contains no body, hostname, IP or asset name; text from an instance is stripped of non-printable characters and bounded before printing. | |
| req-tenable-observe-4 | Not Read Is Recorded | Proposed | A step that cannot run is recorded as not read with the reason, never as empty. | |
| req-tenable-observe-5 | Dry Run Sends Nothing | Proposed | `--dry-run` and `--list` send no request. | |
| req-tenable-observe-6 | Ranks Plugins For Parsers | Proposed | The report ranks plugin ids by finding count so parsers are written for what the instance actually returns. | |

### FIPS Posture
----
RID: `req-tenable-fips`

Status: `Proposed`

The plugin is built to be usable in a FIPS-mode deployment, so its crypto posture is checked and not assumed.

#### Implementation

The runtime dependencies are `pytenable` and its base requirements, which at the surveyed version (26.10.1) are pure Python or reach TLS through `requests` and the system OpenSSL; the `pkcs12` and `all` extras, which add `cryptography` and its bundled OpenSSL, are never installed. `[fips]` in the manifest declares what `validate_plugin --strict`'s `crypto-providers` check reports, which this spec does not predict; whether `pydantic`'s compiled core or any other transitive dependency is reported is unobserved. The plugin runs no third-party binary.

#### Acceptance Criteria

| ACID | Title | Status | Description | Notes |
| --- | --- | --- | --- | --- |
| req-tenable-fips-1 | Declared From The Validator | Proposed | The `[fips]` table matches what `crypto-providers` reports at strict level, with a `reason` when `uses-nonvalidated`. | |
| req-tenable-fips-2 | No Bundled-OpenSSL Extra | Proposed | No dependency or extra that bundles its own OpenSSL is declared. | Ties to `req-tenable-transport-5`. |

### v0 Non-Goals
----
RID: `req-tenable-nongoals`

Status: `Proposed`

What this plugin deliberately does not do, and who owns it.

#### Implementation

- **No severity or risk mapping, and no cross-scanner consolidation.** A later layer, after Tenable's data is on the grid.
- **No mapping to compliance or VDR factors.** The VDR plugins own that.
- **No writes to Security Center**: no launching or editing scans, accepting or recasting risk, asset edits or user management. The transport refuses them.
- **No session or token login, and no Security Center older than 5.13.**
- **No saved queries and no CSV download.** `req-tenable-scope-7`; the JSON path carries structure.
- **No pages or panels.** Backend only; a page would be its own requirement.
- **No scheduling or credential minting.** The grid's collector scheduling and the operator own them.
- **No Tenable users, roles, scanners or scan definitions as nodes.**
- **The `dcom` axis is not adopted in v0.** No type is stamped and the plugin does not depend on `dcom`; sibling collectors do not either. Adopting it later is a manifest dependency and a stamping change, and it is the operator's call, not this plugin's default.
- **Backlog, not non-goals:** host software enumeration, host and address enrichment, the cloud transport, named scopes and a vendor drift check.

#### Acceptance Criteria

| ACID | Title | Status | Description | Notes |
| --- | --- | --- | --- | --- |
| req-tenable-nongoals-1 | No Write Path Exists | Proposed | A test asserts that no allowlist entry sends a mutating operation. | |
| req-tenable-nongoals-2 | No Page Ships | Proposed | The manifest declares no page or panel type. | |

## Model catalog

Design-time. Superseded by the manifest when the owning requirement is `Implemented`.

| Model | Entity type | Category | Rationale |
| --- | --- | --- | --- |
| Tenable Scanner | `tenable__tenable_scanner` | run | One per instance; the reported version and repositories are facts on it, not in its key. |
| Tenable Scan Run | `tenable__tenable_scan_run` | run | `KEYLESS`: records something this plugin did. |
| Tenable Plugin | `tenable__tenable_plugin` | plugin | Its own node, because many findings share one plugin and the plugin changes on its own schedule. |
| Tenable Finding | `tenable__tenable_finding` | finding | One per assertion; a package is never copied from here into a shared record. |

## Edge types

Design-time. Superseded by the manifest when the owning requirement is `Implemented`.

| Edge | From → To | Properties | Rationale |
| --- | --- | --- | --- |
| `RUN_OF_SCANNER__tenable` | scan run → scanner | none | Which instance a run read. |
| `ABOUT_PLUGIN__tenable` | finding → plugin | none | The plugin behind a finding. A plugin reaches its scanner through its key, so no plugin-to-scanner edge in v0. |
| `ABOUT_VULNERABILITY__tenable` | finding → `compliance_core__compliance_vulnerability` | none | Written only against an existing node; vocabulary dependency. |
| `FOUND_IN_PACKAGE__tenable` | finding → `computing_core__package` | none | Written only when a parser's result is unambiguous; vocabulary dependency. |
