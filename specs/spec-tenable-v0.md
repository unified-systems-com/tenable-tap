# Tenable Plugin Specification

**A read-only collector for Tenable Security Center (on-prem first) that on a schedule reads every plugin result Tenable holds (vulnerability findings, configuration audit results and informational results), the plugin metadata behind them, the hosts and services Tenable observed, the scans it ran, its repositories, its accept-risk and recast-risk rules and its own record of what it mitigated. It writes them to the grid as Tenable-owned nodes in Tenable's own shape, with per-plugin parsers that extract what ties a result to a host, service or package, and it links them to the shared `computing_core` nodes for what it can state as fact (an address on a network, a port on that address, a DNS name, an interface's MAC), so a vulnerability detection and response implementation can read what Tenable knows without going to Tenable.**

## Plugin Identity

| Field | Value |
| --- | --- |
| Slug | `tenable` |
| Display name | TAP Tenable |
| Description | A read-only collector for Tenable Security Center that lands every plugin result, the plugins behind them, Tenable's observed hosts and services, scans, repositories, risk rules and mitigation record on the grid, linked to shared addresses, ports, DNS names and interfaces. |
| Kind | Leaf plugin: links to `compliance_core` (the shared vulnerability, by edge, never written) and writes or links `computing_core` facts (IP address, port, DNS name, network interface) and the package (by edge, only when a parser's result is unambiguous); read by VDR plugins through the grid, with no import. |

**Default dimensions.**

| Key | Value | Why |
| --- | --- | --- |
| `tenable.area` | `run` on Security Center, scanner, scan-zone, scan-run, scan-result and repository nodes; `finding` on finding and compliance-result nodes; `plugin` on plugin and plugin-family nodes; `observation` on observed-host and observed-program nodes; `risk` on accept-risk rule, recast-risk rule and asset-list nodes | Lets a page or Search group the Tenable-specific nodes without listing types. The key is namespaced by this vocabulary, which only this plugin gives meaning. |
| `tenable.instance` | The console's instance key, the canonical root (`identity.canonical_root`), on every Tenable-owned node | Says which Security Center a node came from without a traversal. It is the key itself, not a shortened form: scheme, port and path all tell consoles apart, and a short host-only form would merge two consoles on one host (found by the automated review on tenable-tap PR 6, PR comment 6833981907). Its value differs per console, so it cannot be a type default: the collector stamps it on every write from the node's `instance_key`, and the collector's tests assert it on all fifteen types. Stamped only on types this plugin owns. The `compliance_core` and `computing_core` nodes this plugin links to keep their owners' dimensions and receive none from here. |
| `tenable.scan_result` | The newest scan result whose `individual` view returned the node, on findings, compliance results, observed hosts and observed programs; open values, declared and seeded by this plugin | Which scan last saw a result, without an edge per result onto one scan-result node (`req-tenable-scan-result-5`). Not a default: stamped per node by the run, and absent until a scan in the window has returned the node. |

## Philosophy

Tenable already does the hard part: it scans, matches plugins and scores what it finds. A vulnerability detection and response implementation needs those answers on the grid, next to everything else the grid knows, with their provenance. This plugin carries them across. It does not scan, does not decide what a finding means for any compliance factor, and never changes Tenable. It carries Tenable's data as Tenable returns it and does not interpret, consolidate or judge it: no severity scale, risk model or mapping is applied. How an organisation reads Tenable beside its other scanners is a later layer.

Nine consequences shape v0:

1. **Never mutates Tenable.** Security Center's only read path for findings is `POST /analysis`, so "GET only" cannot be the rule. The rule is that the transport permits an enumerated list of method-and-path pairs (the analysis query and plain GET reads) and refuses everything else, so the credential can be a read-only role and a bug here cannot change Tenable.
2. **Tenable's data in Tenable's shape; link, never merge.** The Security Center, its scanners and zones, scan run, finding and plugin are Tenable-owned nodes. The shared vulnerability and the package are other plugins' nodes, reached by edge. Nothing Tenable says is written into a record another producer shares.
3. **Three states, never two.** A scope that could not be read, a scope the instance does not offer, a plugin with no parser, and a parser that failed are each recorded as such and never as clean or as "no package". A fact nothing observed is `null`. A run resolves only what that run read.
4. **A filter changes what "read" means.** Every run records the exact filter it applied. A finding resolves only when a read that included it in scope no longer reports it; a window filter (a recency window) excludes findings that are still open, so a run using one never resolves anything.
5. **The package is a per-plugin fact.** Security Center gives a CPE that belongs to the plugin and free-text plugin output that belongs to the finding; the installed package, version and path live only in that text, in a shape that differs by plugin. So extraction is one parser per plugin, as an explicit, countable, testable list, and a plugin without one is recorded as having none, never as having no package.
6. **There is no vendor contract file.** Security Center publishes no OpenAPI file, so the extract-and-drift machinery of sibling collectors has nothing to reduce from. Responses are validated against schemas written from the vendor's documented examples, marked *documented* until a recorded response replaces them.
7. **The supported versions are data.** Which upstream versions the plugin is known to work with, and on what evidence, is a committed file the probe reads, not prose.
8. **Facts on shared nodes, observations on Tenable's.** What a result establishes as fact (this address on the configured network answered, this port on it was open, this host carries this DNS name or this MAC) is written to or linked with the shared `computing_core` node, from any result that reports it, network or on-board. What Tenable infers or records about it (the service behind a port, an OS guess, a host as Tenable tracks it) is an observation on a Tenable-owned node: `tenable__observed_host`, `tenable__observed_program`. Observations link to facts and never pretend to be them. Matching Tenable's view to other sources' (an EC2 instance, an agent's process list) is a reconciler's job, outside this collector.
9. **Everything Tenable returns, in its own types.** A plugin result is a finding unless it is a configuration audit check, which is a compliance result. Repositories, scan results and risk rules are nodes of their own, because each is a record Tenable keeps and a reader asks about directly ("which hosts had an authenticated scan", "which findings sit under an accepted risk"). Severity is never a collection filter by default; informational results are collected like any other.

**Prior art, and what it changed.** Surveyed 2026-11-06 from documentation and package metadata, not by running against an instance. `pyTenable`'s `tenable.sc.analysis` (documented in its source and docs) supplied the read path (one analysis endpoint, a `tool` per view, offset paging, filters per tool) and the client we build on; it defaults `ssl_verify` to false and its session login is a POST to `/token`, so we always pass verification explicitly and reach only the key-auth path. Tenable's own API reference supplied the request body, the example finding fields, the separate `/plugin` objects and the `x-apikey` header (keys need Security Center 5.13 or later). Tenable VM's findings export (a POST job with polled status and chunks) shows the cloud transport is a different wire behind the same vocabulary, which is why cloud is a Backlog requirement. `anchore-tap` (this organisation) supplied the structure this plugin inherits: findings keyed by what they assert, resolve only what was read, three states, operator settings never read from user-editable nodes, a per-run probe, and provenance markers. On supported-version declaration, Grafana's `grafanaDependency` and Elastic's `conditions.kibana.version` showed a declared range checked by tooling (and Grafana's plugin that shipped an open-ended range and failed to load on a newer release showed why a range must not hard-enforce); Home Assistant keeps upstream firmware requirements in documentation and warns, which we adopt as the posture. No source declares evidence level beside a range; that is ours. Cartography's Tenable module (read 2026-11-06; it targets Tenable VM, not Security Center) supplied one structural lesson: it links CVEs from plugins, not findings, after a plugin naming hundreds of CVEs reported per host multiplied edges and made a graph index reject the write.

**Prior art, second survey (2026-11-12), and what it changed.** Read from each project's source and Tenable's documentation, not run. Tenable's integration guide for Security Center (developer.tenable.com, `sc-integrations`) recommends `vulndetails` for results and `sumip` for hosts, pages of 2,000 to 10,000, incremental pulls on `lastSeen` and `lastMitigated`, and gives the finding identity as the record's host-uniqueness fields plus plugin, port and protocol; the Elastic `tenable_sc` integration and the Splunk add-on both build identity from the record's own `uniqueness` lists, which is why `host_key` now follows `hostUniqueness`. The Splunk add-on reads the patched view on every run and marks those results fixed, while Elastic reads only the cumulative view and is still building a latest-state view, which is why this plugin reads both and puts Tenable's mitigation first. DefectDojo put plugin output into its de-duplication hash and had to remove it (issues 8417, 11994), and the Splunk add-on replaces oversized plugin output with a stub; plugin output stays out of every key here and is stored whole. Tenable's audit-file documentation says Security Center gives each audit check its own plugin id above 1,000,000, while Nessus reports checks under shared per-audit plugins, which is why compliance results have their own type keyed like findings. pyTenable's `analysis.vulns()` adds a filter valid only from Security Center 6.2 (pyTenable issue 828), which is why the collector builds analysis bodies itself. No maintained library parses Tenable plugin output (pyTenable, nessus-file-reader, faraday-plugins, DefectDojo's parsers, python-libnessus and go-nessus were checked); MITRE's `nessus-to-hdf` is the reference for audit elements.

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
| 9 | Facts Apart From Observations | Shared `computing_core` nodes receive only facts; Tenable's inferences live on Tenable-owned observation nodes linked to them. |
| 10 | Everything Tenable Holds | Every plugin result, the scans, repositories, risk rules and mitigation record reach the grid, each in a type that fits it. |

## Requirements

| RID | Name | Status | Notes |
| --- | --- | --- | --- |
| req-tenable-connection | [Connection And Credential](#connection-and-credential) | In Development | One operator-owned secret envelope per Security Center instance; TLS verification on unless the operator turns it off, and every run that does says so |
| req-tenable-transport | [The Guarded Transport](#the-guarded-transport) | In Development | pyTenable's `TenableSC` over a session whose `send` permits only an enumerated list of operations; API keys only |
| req-tenable-probe | [Probe And Provenance](#probe-and-provenance) | In Development | Version, status and repositories read first and recorded on the run |
| req-tenable-upstream-versions | [Supported Upstream Versions](#supported-upstream-versions) | In Development | A committed file of supported ranges with an evidence level each; the probe's verdict is warn, or error below a hard floor |
| req-tenable-response-contract | [Response Contract](#response-contract) | Proposed | Hand-written schemas from documented examples, validated before any node is written |
| req-tenable-states | [Three States And Resolution](#three-states-and-resolution) | Proposed | Not read is never clean; null is unobserved; a run resolves only what it read; aged-out, view changes and identity changes never look like fixes; statements are withdrawn |
| req-tenable-scope | [Scope Filters](#scope-filters) | Proposed | Server-side filters in the envelope; scope filters versus window filters; the filter recorded on the run |
| req-tenable-scanner-run | [Security Center And Scan Run](#security-center-and-scan-run) | Proposed | The console and each collection, with the probe, filter, TLS, credential identity, counters and warnings |
| req-tenable-scanners-zones | [Scanners And Scan Zones](#scanners-and-scan-zones) | Proposed | The scan engines a console manages and their zones, read as optional inventory, with an optional admin envelope |
| req-tenable-plugin | [Plugin Metadata](#plugin-metadata) | Proposed | A Tenable-owned node per plugin from `GET /plugin/{id}` |
| req-tenable-plugin-family | [Plugin Families](#plugin-families) | Proposed | A node per plugin family, linked from its plugins |
| req-tenable-findings | [Findings](#findings) | Proposed | A node per non-audit plugin result, keyed by what it asserts, with Tenable's fields and full plugin output as returned |
| req-tenable-compliance-results | [Compliance Results](#compliance-results) | Proposed | A node per configuration audit check result, with the `cm:` elements parsed out of the plugin output beside the raw text |
| req-tenable-mitigation | [Tenable's Mitigation Record](#tenables-mitigation-record) | Proposed | The patched view read every run; Tenable's mitigation is the primary resolved signal, not-reported-in-a-clean-read the fallback |
| req-tenable-repository | [Repositories](#repositories) | Proposed | A node per repository, carrying the data format that marks agent data |
| req-tenable-scan-result | [Scan Results](#scan-results) | Proposed | A node per scan Tenable ran, from the scan-result list |
| req-tenable-observed-host | [Observed Hosts](#observed-hosts) | Proposed | A node per host as Tenable tracks it, keyed by the record's own host-uniqueness fields, with Tenable's per-host scan facts |
| req-tenable-observed-program | [Observed Programs](#observed-programs) | Proposed | A node per service Tenable detected on a host's port, from a service-detection parser |
| req-tenable-risk-rules | [Risk Rules](#risk-rules) | Proposed | A node per accept-risk and recast-risk rule, linked to the plugin and repository it covers |
| req-tenable-asset-lists | [Asset Lists](#asset-lists) | Proposed | A node per asset list with its definition as returned; membership is backlog |
| req-tenable-shared-facts | [Shared Facts](#shared-facts) | Proposed | Addresses, ports, DNS names and interfaces written to or linked in `computing_core`, from any result that reports them |
| req-tenable-run-links | [Last Seen In Run](#last-seen-in-run) | Proposed | One edge per observation to the run that last read it, moved each run |
| req-tenable-vulnerability-link | [Shared Vulnerability Link](#shared-vulnerability-link) | Proposed | One edge per CVE from the plugin, never from the finding, only to an existing `compliance_core` vulnerability with that exact id |
| req-tenable-parsers | [Per-Plugin Package Parsers](#per-plugin-package-parsers) | Proposed | One parser module per plugin, a registry, four parse states, a fixture and a test each |
| req-tenable-package-link | [Package Link](#package-link) | Proposed | An edge to a `computing_core` package only when a parser's result is unambiguous |
| req-tenable-observe | [The Observation Command](#the-observation-command) | In Development | A read-only command that records what an instance returns so shapes are observed before they are parsed |
| req-tenable-fips | [FIPS Posture](#fips-posture) | Proposed | Declared from what the validator reports; no `cryptography` extra |
| req-tenable-finding-cve-narrowing | Finding-Level CVE Narrowing | Backlog | Only if a recording shows Security Center reports a host-specific subset of a plugin's CVEs, or a plugin's CVE list differs by host or by configuration, write `ABOUT_VULNERABILITY__tenable` from the finding for just those CVEs; not built unless a need is found |
| req-tenable-software-enumeration | Host Software Enumeration | Backlog | The `listsoftware` tool parsed into `computing_core` host-package data, as another per-plugin-style parser |
| req-tenable-cloud | Tenable VM Transport | Backlog | The cloud findings export (a POST job, a status poll, chunk downloads) as a second transport behind the same vocabulary |
| req-tenable-scopes-list | Named Scopes Per Envelope | Backlog | A list of named filter sets per instance, each read and resolved independently |
| req-tenable-drift | Vendor Contract Drift Check | Backlog | A scheduled comparison against a vendor contract file, if Tenable publishes one for Security Center |
| req-tenable-nessus-download | Per-Scan `.nessus` Enrichment | Backlog | Download each new scan result as `.nessus` (`POST /rest/scanResult/{id}/download`, `downloadType` `v2`), read with pyTenable's `NessusReportv2`, for the service name per port, each plugin's remote or local type and host properties; possibly a separate collector; links observations to the scan results that saw them |
| req-tenable-host-assets | Console-Wide Host Assets | Backlog | Read `/rest/hosts` (5.20 and later) once a recording shows whether its UUID equals the analysis `hostUUID`; it would be the console-wide host that per-repository observed hosts point at, never merged with them |
| req-tenable-reconciler | Cross-Source Reconciliation | Backlog | Linking Tenable's observations to other sources' nodes (an EC2 instance, an agent-reported program) by evidence-carrying edges, never merges; a separate library collectors pull in; absorbs mapping cloud ids Tenable reports to `aws_core` nodes |
| req-tenable-product-parsers | Product And Version Parsers | Backlog | Parsers for the banner plugins (web server, SSH server and similar) that fill an observed program's product, version and CPE |
| req-tenable-asset-list-membership | Asset-List Membership | Backlog | Which hosts an asset list holds, per run, by a filtered query per list; membership is recomputed by Security Center, so edges would move each run |
| req-tenable-multi-org | Several Organisations Per Console | Backlog | One main envelope per organisation on one console, each with its own resolution scope, sharing the console's node |
| req-tenable-nongoals | [v0 Non-Goals](#v0-non-goals) | Proposed | What this plugin deliberately does not do, and who owns it |

### Connection And Credential
----
RID: `req-tenable-connection`

Status: `In Development`

How the collector knows which Security Center to read and how to authenticate. The base URL, the keys, the TLS settings and the scope filter live together in one operator-owned secret envelope per instance, never in a field on a grid node: whoever can edit a node must not be able to point a credential at another host or quietly narrow what a compliance view sees.

#### Implementation

The secret is a plugin secret: its consumer is the Tenable collector, so the envelope's scope is `tenable`, its key is chosen by the operator to name the instance, and the file is `<key>.secret.json` under the secrets root, never in a repository. Its kind is `tenable_sc_credential`, a kind this plugin owns: the collector validates `data` against `tap_plugin/tenable/schemas/tenable_sc_credential.schema.json` (strict, a `description` on the top level and every field) with `require_secret_kind` before any request. `data` holds:

- `base_url`: the Security Center root, such as `https://sc.example:443`. `http://` or `https://` exactly as written, and the client never changes it. Required. An `http://` URL sends the API keys and every response across the network unencrypted, so each run that uses one records a `PLAINTEXT_TRANSPORT` warning on the scan run and the observation command prints one; the scheme is part of the instance key, so the two are different scanners.
- `access_key`, `secret_key`: the API keys of a Security Center user with API-key authentication enabled. Required.
- `ssl_verify`: boolean, optional, default `true`. `false` is honoured, because the operator knows the network, and every run it applies to records a `TLS_VERIFICATION_DISABLED` warning on the scan run and the observation command prints one.
- `ca_bundle`: the absolute path of a PEM file on the host, never its contents. Optional.
- `network_name`: the network the instance's results come from, as a value of `computing_core`'s `tap.computing.network_name` dimension (for example `corp`, or `Internet` for public addresses). Required. It is the network every address and port fact from this instance is written on (`req-tenable-shared-facts`), whether the result came from a network scan or an agent, because it names where the results were gathered, not where the scanner sits. An instance whose results span several networks is not supported in v0, and the plugin cannot detect one: the operator's declaration is trusted, and a wrong one would place overlapping private addresses from another network on this one. That risk is accepted for v0 by the plugin owner (2026-11-12); per-collector (per-repository) network configuration is the later answer, and the envelope description states the constraint.
- `scope`: the filter object of `req-tenable-scope`. Optional.
- `scan_result_window_days`: how far back the scan-result list is read (`req-tenable-scan-result`), a positive integer, default `30`. Optional.
- `feed_stale_days`: how old the active or passive plugin feed may be before the run records `FEED_STALE` (`req-tenable-probe-5`), an integer from 1 to 365, default `7`. Optional.
- An optional second envelope per console, kind `tenable_sc_admin_credential` (schema `tap_plugin/tenable/schemas/tenable_sc_admin_credential.schema.json`, strict, every field described), holds an administrator's API keys with the same `base_url`, `ssl_verify` and `ca_bundle` fields and names the main envelope's key in `for_key`. It is used only for the inventory reads an organisation user cannot make in full (`GET /rest/scanner`, `/rest/passivescanner`, `/rest/zone`, `/rest/organization`; documented: an organisation user sees only its organisation's agent-capable scanners, with five fields, and `/organization` is admin-only). It never sends an analysis query or any read the main envelope makes. The one shared path is pyTenable's construction-time version check, `GET /rest/system`, which carries no key; the transport admits it for the administrator client only when it carries none, and refuses an authenticated one. Both envelopes must yield the same `instance_key`, or the admin envelope is refused. Absent, those reads fall back to what the main credential can see, recorded as not visible to this credential (`req-tenable-scanners-zones`). Ruled 2026-11-12 (Q51). Whether an administrator can run analysis at all is undocumented (inferred not); the separation holds either way.

The envelope's description states the least-privilege shape: a read-only role whose reach is limited to the repositories to be read. The collector reads every envelope in scope `tenable`; each yields one Security Center node whose key is derived from the canonical root of `base_url` (`req-tenable-scanner-run-2`). An envelope that fails validation fails only its own run, naming `tenable:<key>`. These credentials have no scannable shape, so no `CredentialPattern` and no entropy rule is added; protection rests on the envelope layer, the leak guard, `.gitignore` and redaction: the keys reach pyTenable as constructor arguments, no object holding them shows them in its `__repr__`, and no log line, scan-run field or exception carries a value.

#### Acceptance Criteria

| ACID | Title | Status | Description | Notes |
| --- | --- | --- | --- | --- |
| req-tenable-connection-1 | Settings Are Not Nodes | In Development | No node type declares an API key, TLS setting or filter field, and the collector reads no connection setting from the grid. The instance's key holds the canonical root as identity (`req-tenable-scanner-run-2`); it is written from the envelope and never read back to decide where to connect. | Ruled 2026-11-12 (Q47c): a key may hold the root. |
| req-tenable-connection-2 | Secret Never Echoed | In Development | The keys are absent from logs, scan-run properties and exception text, including when a request fails, and from every `__repr__`. | A test fails a request and searches all of them. |
| req-tenable-connection-3 | Verification On By Default | In Development | `ssl_verify` defaults to `true` and the client always passes it explicitly; an absent field never reaches pyTenable's own default of false. | |
| req-tenable-connection-4 | Disabled Verification Is Recorded | In Development | A run with `ssl_verify: false` records `TLS_VERIFICATION_DISABLED` on its scan run. | The operator's choice, stated and warned. |
| req-tenable-connection-5 | Strict Base URL | In Development | A `base_url` with userinfo, a query or a fragment, port 0, a host with a trailing dot, or a path with empty, `.`, `..` or percent-encoded segments is refused before any request; host and scheme are lower-cased, the port is written explicitly and the path is preserved without a trailing slash, so one instance has one key however its URL is spelled. | Ruled 2026-11-12 (Q47a, Q48a). |
| req-tenable-connection-6 | One Envelope Per Instance | In Development | Two main envelopes yielding the same instance key refuse the run before any request, naming both. One organisation's credential per console is a v0 limit; reading several organisations on one console is `req-tenable-multi-org`. | Admin envelopes are counted separately (`-11`). |
| req-tenable-connection-7 | Strict Credential Schema | In Development | The `tenable_sc_credential` schema is strict, with no field missing and every field described; a wrong kind or shape fails that instance's run before any request, naming `tenable:<key>` and never a value. | |
| req-tenable-connection-8 | Undetectability Is Recorded | In Development | The spec states these credentials have no scannable shape; a test asserts no `CredentialPattern` was added. | Silence would look like coverage. |
| req-tenable-connection-9 | Plaintext Is Recorded | In Development | A run whose `base_url` is `http://` records `PLAINTEXT_TRANSPORT` on its scan run, the observation command prints it, and any other scheme is refused before any request. | An HTTP-only instance on an isolated network is the operator's call; it is stated and warned, never silent. |
| req-tenable-connection-10 | Network Is Declared | In Development | `network_name` is required and non-empty; an envelope without it fails that instance's run before any request. Its value is recorded on the Security Center node. | Facts from an instance with no declared network would land on a guessed one. |
| req-tenable-connection-11 | Admin Envelope Is Inventory Only | In Development | An admin envelope is used only for the scanner, passive-scanner, zone and organization reads, never for analysis or any read the main envelope makes; one whose `instance_key` differs from its `for_key` envelope's is refused, naming both keys and no value. A test sends an analysis query through the admin client and expects a refusal. | Ruled 2026-11-12 (Q51a). |

### The Guarded Transport
----
RID: `req-tenable-transport`

Status: `In Development`

How requests leave the plugin. pyTenable's `TenableSC` is the client; every request it makes passes through a `requests.Session` subclass the plugin supplies, and that subclass decides what may be sent.

#### Implementation

The dependency is `pytenable==X.Y.Z` pinned exactly in `pyproject.toml` (a range is a defect), with no extra: the `pkcs12` and `all` extras pull in `cryptography`, whose wheels bundle their own OpenSSL (`req-tenable-fips`). `TenableSC(url=…, access_key=…, secret_key=…, ssl_verify=…, session=<guarded session>)` is the only construction. The guard is in `Session.send`, so remounting an adapter does not bypass it, and the client does not expose its session. `send` refuses before anything is sent: any URL outside the configured root; any redirect; any override of verification, client certificate or proxies; and any method-and-path pair not on the allowlist:

- `POST /rest/analysis`, whose body has `type: "vuln"` and no other type, and never `/rest/analysis/download`;
- `GET /rest/plugin` and `GET /rest/plugin/{id}`;
- `GET /rest/scanResult` (the list, with `fields`), and never `/rest/scanResult/{id}/download` in v0 (`req-tenable-nessus-download` is Backlog and would add it by a spec change);
- `GET /rest/acceptRiskRule` and `GET /rest/recastRiskRule` (the lists, with `fields`);
- the system and status reads pyTenable and the probe make (`GET /rest/system`, `GET /rest/status`, `GET /rest/repository`), each listed by name;
- for the administrator envelope only (`req-tenable-connection-11`): `GET /rest/organization`, and the scanner, passive-scanner and zone reads above; each operation names the roles that may send it, and `send` refuses one sent under another;
- the identity and freshness reads of the probe: `GET /rest/currentUser`, `GET /rest/currentOrganization`, `GET /rest/feed`;
- the inventory reads: `GET /rest/scanner`, `GET /rest/passivescanner`, `GET /rest/zone` (`req-tenable-scanners-zones`), `GET /rest/pluginFamily` (`req-tenable-plugin-family`), `GET /rest/asset` (`req-tenable-asset-lists`), and `GET /rest/scanResult/{id}` for the scanners that ran a scan (`req-tenable-scan-result`).

Every GET on the list that accepts `fields` pins one exact value, written in the allowlist beside its path, and `send` refuses a GET to that path whose `fields` parameter is absent or differs. `GET /rest/system`, `GET /rest/status` and `GET /rest/feed` take no `fields` parameter, and `send` refuses one sent to them. Any other parameter is refused unless the allowlist names it, as a pinned value or as a free digits-only value (paging offsets, scan-result times). Documented: `scanner` and `passivescanner` return `username`, `password`, `cert`, `accessKey` and `secretKey`, and `currentUser` returns `password` and `fingerprint`, when `fields` is omitted or broad; pinning keeps a code change from widening a read into secret fields. The pinned lists never name those fields. Every analysis body carries `acceptRiskStatus=all` in its filters: documented, a query with no `acceptRiskStatus` filter excludes accepted results, which would hide every accepted finding and make accepting a risk in Tenable look like a fix (ruled 2026-11-12, Q49a). The scan-result list is read with `timeCompareField=finishTime` so the window is on finish time (documented default: `createdTime`). Responses are bounded before parsing: a response larger than 64 MiB, JSON nested deeper than 64 levels, or a body containing `NaN` or `Infinity` is refused and recorded as not read, and each read has a total time ceiling beside the retry bound.

Analysis bodies are built by the collector and sent through the client's request method, not through pyTenable's `analysis.vulns()`: that helper adds an implicit `wasVuln=excludeWas` filter to every cumulative query, a filter Security Center accepts only from 6.2, which would make every read fail on 5.13 to 6.1. The collector adds `wasVuln=excludeWas` itself, and only when the probed version is 6.2 or later, so web-application findings stay out of v0 without breaking older instances.

Authentication is by API keys only (`X-APIKey: accessKey=…; secretKey=…`, Security Center 5.13 or later). pyTenable's session login is `POST /token`, which is not on the allowlist, so that path is unreachable; a Security Center older than 5.13 is not supported (`req-tenable-upstream-versions`). The allowlist is the plugin's one definition of "read", and a change to it is a spec change.

Retries are the plugin's, not pyTenable's: the client is built with `retries=0`, pyTenable's retry and error maps are emptied so it never sleeps on `Retry-After` itself, and its error hook is replaced so it never logs a response body. A refusal is a 401, or a 403 whose `error_code` is not `146`; Security Center answers 403 with `146` for an invalid parameter or filter, which is a bad request and is never recorded as "not visible to this credential". The error message Security Center returns is kept on the failure with both keys replaced and its length bounded, and is never part of a printed message.

#### Acceptance Criteria

| ACID | Title | Status | Description | Notes |
| --- | --- | --- | --- | --- |
| req-tenable-transport-1 | Allowlist At The Transport | In Development | Every request passes through one `send` that refuses any method-and-path pair not on the list; `POST /token`, `DELETE`, `PATCH`, an aliased method and a request from another module are each refused. | Negative tests for each; a source scan is only secondary. |
| req-tenable-transport-2 | Analysis Is Query-Only | In Development | A `POST /rest/analysis` with a body type other than `vuln` is refused, and `/rest/analysis/download` is never reachable. | |
| req-tenable-transport-3 | Bound To The Root | In Development | A request to any other host, port, scheme or path root is refused, and so is any redirect, before a second request. | The session holds the keys. |
| req-tenable-transport-4 | Bounded Retries | In Development | Retries are limited in count and total time and honour `Retry-After`; exhaustion is a recorded failure, never an empty result. | Ties to `req-tenable-states`. |
| req-tenable-transport-5 | Exact Pin, No Crypto Extra | In Development | `pyproject.toml` pins `pytenable` with `==` and names no extra; a test asserts both. | |
| req-tenable-transport-6 | Verification Cannot Be Overridden | In Development | A per-request `verify`, `cert` or `proxies` override is refused by `send`; the CA bundle is applied on the session by the plugin only. | Whether pyTenable honours a session-level `verify` is unobserved; a test settles it. |
| req-tenable-transport-7 | No Implicit Filters | In Development | Analysis bodies are built by the plugin; `wasVuln=excludeWas` is sent only to Security Center 6.2 or later, and a test asserts no pyTenable helper adds a filter the plugin did not set. | pyTenable issue 828. |
| req-tenable-transport-8 | Fields Pinned Per Read | In Development | Every allowlisted GET that accepts `fields` carries exactly its pinned value, and one that does not accept it carries none; a request without it, with another value or with an unlisted parameter is refused before it is sent; a test asserts no pinned list names `password`, `username`, `cert`, `accessKey`, `secretKey`, `fingerprint` or `encryptionPassword`. | Ruled 2026-11-12 (C15). |
| req-tenable-transport-9 | Accepted Results Always Read | In Development | Every analysis body carries `acceptRiskStatus=all`; a test fails a body without it. Whether the default excludes accepted results through the API is confirmed by the observation command. | Ruled 2026-11-12 (Q49a). Documented for the query UI. |
| req-tenable-transport-10 | Bounded Input | In Development | A response over the size ceiling, over the depth ceiling or carrying `NaN`/`Infinity` is refused and recorded as not read, never partly stored; a read past its time ceiling is a recorded failure. | Anchore's input limits. |

### Probe And Provenance
----
RID: `req-tenable-probe`

Status: `In Development`

Before reading data, the collector asks the instance what it is and which repositories its credential can see, and records the answer on the scan run, so a finding can be judged against the data behind it.

#### Implementation

Reads the system and status endpoints and the repository list (`req-tenable-transport`), each optional except the repository list the scope walk needs. It also reads `GET /rest/currentUser` (pinned to the user's id, role, organisation and group, never a name or contact detail), `GET /rest/currentOrganization` (the organisation's id and its zones, readable without admin) and `GET /rest/feed` (the plugin feed's update times; an active or passive feed older than the envelope's `feed_stale_days`, or one Security Center itself flags stale, records `FEED_STALE`). The credential's identity and the set of repositories it can see are recorded on the run; when either differs from the previous run's, nothing resolves by absence in that run (`req-tenable-states`). A Security Center managed by Tenable Director, or a Tenable Enclave Security deployment, whose identity reads take another shape (documented: `/mgmt/*` and `/tes/*`), is detected by the probe and the run ends before any data read, recorded as unsupported in v0. Recorded on the scan run: the base URL host, the reported Security Center version, the repositories (id, name, `dataFormat`) and the verdict of `req-tenable-upstream-versions`, each `null` when the instance did not answer. An unreadable version is `null` and never a pass. Each repository becomes a node (`req-tenable-repository`). Repositories whose `dataFormat` is `IPv4`, `IPv6`, `agent` or `universal` are read; `mobile` repositories are not read in v0 and are listed as not read with that reason. A repository with any other `dataFormat` is recorded as read-with-unknown-format and its results are not stored (`req-tenable-probe-6`).

#### Acceptance Criteria

| ACID | Title | Status | Description | Notes |
| --- | --- | --- | --- | --- |
| req-tenable-probe-1 | Probe Before Data | In Development | The probe completes before any finding is read, and its results are on the scan run. | |
| req-tenable-probe-2 | A Refused Probe Is Null | In Development | An optional probe read the instance refuses leaves its field `null` and the run continues. | |
| req-tenable-probe-3 | Repository List Is Required | In Development | A run that cannot read the repository list ends before any scope is read, recorded as an error. | |
| req-tenable-probe-4 | Credential Identity Recorded | In Development | The run records the credential's user id, role, organisation id and group id and the repositories it can see, and never a user name or contact detail; a change from the previous run is recorded and blocks resolution by absence. | Ruled 2026-11-12 (Q49c). An admin narrowing the group would otherwise look like a fix. |
| req-tenable-probe-5 | Feed Freshness | In Development | The plugin feed's update times are recorded on the run, and a feed older than the configured threshold records `FEED_STALE`; a feed read refused is `null`, never fresh. | Anchore's `FEED_STALE`. |
| req-tenable-probe-6 | Unknown Data Format | In Development | A repository whose `dataFormat` is not `IPv4`, `IPv6`, `agent`, `universal` or `mobile` is recorded as read-with-unknown-format; its results are not stored and nothing in it resolves. | Separate from unkeyable entries (`req-tenable-findings-3`). |
| req-tenable-probe-7 | Unsupported Deployments Refused | Proposed | A Director-managed or Enclave Security deployment detected by the probe ends the run before any data read, recorded as unsupported. | v0 targets a plain Security Center. Not built: no documented signal in the probe's reads tells such a deployment apart, so detection waits on a recording from one (observation ledger `director-detection`). |

### Supported Upstream Versions
----
RID: `req-tenable-upstream-versions`

Status: `In Development`

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
| req-tenable-upstream-versions-1 | Data, Schema-Validated | In Development | The file validates against its schema, every entry has a `description`, and a specifier with no upper bound is rejected. | Grafana's open-ended range failed on a newer release. |
| req-tenable-upstream-versions-2 | Evidence Cannot Be Claimed | In Development | An entry with evidence `observed` names a date and a recorded response; a test rejects one that does not. | We are blind; nothing starts observed. |
| req-tenable-upstream-versions-3 | Four-State Verdict | In Development | The scan run carries exactly one of observed, documented-only, outside, unreadable. | Three states, never two. |
| req-tenable-upstream-versions-4 | Warn, Do Not Refuse | In Development | An outside version is a recorded warning and the run continues; only a version below the hard floor is an error. | |
| req-tenable-upstream-versions-5 | Derived Once | In Development | The README table is generated from the file, and a test fails when they differ. | |

### Response Contract
----
RID: `req-tenable-response-contract`

Status: `Proposed`

Security Center publishes no contract file, so there is no extract to generate and no vendor file to drift against. In its place, schemas written by hand from the documented examples, and a rule that no response becomes a node without passing them.

#### Implementation

`tap_plugin/tenable/contract/analysis.schema.json` and `plugin.schema.json`, with a `description` on the top level and every entry. They describe the documented envelope (`type`, `response.results`, `totalRecords`, `returnedRecords`, `error_code`, `error_msg`) and the documented finding and plugin fields. Most scalar values are JSON strings, including ports and epoch timestamps, and the schemas say so. A field the schemas do not name is tolerated and not stored; a missing required key field fails that repository's scope (`req-tenable-findings-3`). Paging does not trust `totalRecords`, which pyTenable notes is not always returned: a page shorter than the requested size ends the walk, a page equal to the cap is recorded as possibly truncated, and the record ceiling of `req-tenable-scope` is a recorded stop. Recorded responses from a real instance, once they exist, are committed (trimmed and reviewed) beside the schemas as fixtures and replace the assumed shapes.

The schemas tolerate the documented changes across the supported range (Tenable's release notes):

| Version | Change the schemas tolerate |
| --- | --- |
| 5.13 | `uniqueness` renamed `hostUniqueness`; read either |
| 5.14 | both `uniqueness` and `hostUniqueness` returned; `hostUniqueness` wins |
| 5.21 | `uuid` and `type` added inside nested repository, plugin, user and organization objects; never required below 5.21 |
| 5.22 | `/system` `version` shown only when authenticated |
| 6.0 | `repository.dataFormat` added inside scan and scan-result objects |
| 6.7 | every repository behaves as universal, so `hostUniqueness` becomes `repositoryID,hostUUID` and `vulnUniqueness` becomes `repositoryID,vulnUUID` (`req-tenable-states-8`) |
| 6.8 | `vpr2Score` added |
| 6.9 | licence fields leave `/system` |

Four request shapes disagree between Tenable's documentation and pyTenable, and the collector trusts neither until the observation command has settled each on the instance: where analysis paging offsets go (request root in the documentation, inside `query` in pyTenable); whether `wasVuln` is a root parameter (documentation, which says the default includes web-application results) or a filter (pyTenable, valid from 6.2); the `lastSeen` value format (`<minDaysBack>:<maxDaysBack>` in the documentation, epoch ranges in Elastic's integration); and the paging flag for `/hosts` (not read in v0). The documented form is built first and the observed one replaces it.

Values are stored on Tenable-owned nodes as returned. The one conversion this plugin makes is when it writes or links a shared `computing_core` fact (`req-tenable-shared-facts`): the port becomes the integer `port_number` and the protocol the lower-case `transport` that `computing_core` keys by, and an address is written in canonical form; the value as returned stays on Tenable's own node beside it.

#### Acceptance Criteria

| ACID | Title | Status | Description | Notes |
| --- | --- | --- | --- | --- |
| req-tenable-response-contract-1 | Validate Before Write | Proposed | Every analysis and plugin response is validated before any node is written; a required scope that fails is an error and an optional one is recorded as not read. | |
| req-tenable-response-contract-2 | Strings Stay Strings | Proposed | Values documented as strings are stored on Tenable-owned nodes as strings and never coerced; the only conversion is the one stated for shared facts, and the raw value stays beside it. A test writes port `"443"` and protocol `"TCP"` and finds them unchanged on the finding and as `443`/`tcp` on the shared port. | A coercion would be interpretation. |
| req-tenable-response-contract-3 | Paging Does Not Trust The Total | Proposed | The walk ends on a short page, never on `totalRecords` alone, and a full-cap page at the ceiling is recorded as possibly truncated. | |
| req-tenable-response-contract-4 | No Network In The Suite | Proposed | The plugin's tests open no socket; the client is exercised against fixtures. | The `ci` record excludes network access. |
| req-tenable-response-contract-5 | Documented, Not Observed | Proposed | The schemas and fixtures carry a provenance note stating they derive from documented examples, until replaced by recordings. | |
| req-tenable-response-contract-6 | Version Drift Tolerated | Proposed | A fixture per row of the version table validates: a 5.13 response with `uniqueness` only, one with nested objects lacking `uuid`, one without `vpr2Score`. | Documented changes; no instance observed. |
| req-tenable-response-contract-7 | Disputed Shapes Settled By Observation | Proposed | The paging offset placement, `wasVuln` form, `lastSeen` format and `/hosts` paging flag are each listed as open in the observation command's assumptions ledger until a recording settles them. | Documentation and pyTenable disagree. |

### Three States And Resolution
----
RID: `req-tenable-states`

Status: `Proposed`

How the collector records absence. Every place absence can occur has three outcomes, and the plugin keeps them apart.

#### Implementation

A repository the credential cannot read, a call that failed after its retries, a page that failed validation and a scope the filter made incomplete are each recorded as *not read* on the scan run with the reason, never as zero findings. A field nothing observed is `null`; an observed-empty list is `[]`; an observed empty string stays `""`. The unit of reading, and so of resolution, is one repository: each is read with its own query, so "read successfully" has a precise meaning. A finding or compliance result resolves in one of two ways, and records which. Primarily, when Tenable's own patched view reports it mitigated (`req-tenable-mitigation`): Tenable counts a result mitigated only when its host, plugin and port were in a scan's scope and absent from the result, and a local check only when authentication succeeded, which is a better test than ours. As a fallback, when its repository was read successfully by the same instance in a run whose filter put it in scope, it no longer appears in the cumulative view, and the patched view of the same repository was also read successfully; a repository not read keeps whatever it had (`req-tenable-scope`). Nothing is deleted: a result no longer reported is `resolved`, and a returning one is reopened. Three more rules keep disappearance from looking like a fix (ruled 2026-11-12, Q49 and Q50):

- **Aged out.** Each repository keeps data only for its lifetimes (`activeVulnsLifetime`, `passiveVulnsLifetime`, `complianceVulnsLifetime`, `mitigatedVulnsLifetime`, documented), which the repository node stores. A result that would resolve by absence but whose `last_seen` is older than now minus its applicable lifetime resolves with `resolution_source: aged_out`, never `not_reported`: Tenable dropped it, nobody showed it fixed.
- **The credential's view changed.** A run in which the credential's role, organisation, group or visible repositories differ from the previous run's resolves nothing by absence (`req-tenable-probe-4`).
- **Identity changed.** A repository whose `hostUniqueness` list changed resolves nothing by absence in that run (`req-tenable-findings-12`). On the first clean run after the change, the findings and compliance results still stored under the old list resolve with `resolution_source: identity_changed`, because the new keys now carry them. Documented: from Security Center 6.7 every repository behaves as universal, so every IPv4 repository changes its list once on upgrade.

Non-result records carry `state` too. Accept-risk and recast-risk rules, repositories, scanners, scan zones and asset lists are `current` while a successful read reports them and become `withdrawn` when a successful, complete read of their list no longer does; a withdrawn rule is not an assertion a consumer may rely on. Observed hosts and observed programs carry no `state`: like Anchore's runtime nodes, they keep only when they were last seen (`req-tenable-run-links`). Scan results outside the window are never withdrawn, because the window is a filter, not a statement that the scan is gone. The plugin node carries no `state`, because Tenable plugins are metadata and not assertions.

#### Acceptance Criteria

| ACID | Title | Status | Description | Notes |
| --- | --- | --- | --- | --- |
| req-tenable-states-1 | Not Read Is Not Clean | Proposed | A repository not read in a run produces no resolved findings and is listed as not read on the run. | |
| req-tenable-states-2 | Null Is Unobserved | Proposed | A field the response did not carry is `null`, never `""`, `0` or `false`. | |
| req-tenable-states-3 | Resolve Only What Was Read | Proposed | A result resolves only when Tenable's patched view reports it mitigated, or when its repository's cumulative and patched views were both read successfully by the same instance in a run whose scope included it and it is no longer reported; `resolution_source` records `tenable_mitigated`, `not_reported`, `aged_out` or `identity_changed`. | Tenable's record first, ours as fallback. |
| req-tenable-states-4 | Truncation Blocks Resolution | Proposed | A repository read that ended at the record ceiling or on a validation failure resolves nothing. | |
| req-tenable-states-5 | Nothing Is Deleted | Proposed | A finding no longer reported is rewritten as `resolved`, with every other field as it was; a returning one is reopened. | |
| req-tenable-states-6 | Aged Out Is Not Fixed | Proposed | A result absent from both views whose `last_seen` is older than its repository's applicable lifetime resolves as `aged_out`, never `not_reported`; a test covers one just inside and one just outside the lifetime. | Ruled 2026-11-12 (Q49b). |
| req-tenable-states-7 | Withdrawn Statements | Proposed | A risk rule, repository, scanner, scan zone or asset list a successful complete read no longer reports becomes `withdrawn`, and one that returns becomes `current`; a failed or partial read withdraws nothing. Observed hosts and programs carry no `state`. | Ruled 2026-11-12 (Q49d). Anchore's `withdrawn`. |
| req-tenable-states-8 | Identity Change Resolves The Old Keys | Proposed | After a repository's `hostUniqueness` list changes, the change run resolves nothing by absence there, and the next clean run resolves every result still stored under the old list with `identity_changed`; a test simulates the 6.7 switch from `repositoryID,ip,dnsName` to `repositoryID,hostUUID`. | Ruled 2026-11-12 (Q50a). |

### Scope Filters
----
RID: `req-tenable-scope`

Status: `Proposed`

Down-selecting what a run gathers. A filter changes what "read" means, so it can never turn "filtered out" into "fixed": every run records the exact filter it applied, and the options are divided into scope filters, which resolution can reason about, and window filters, which it cannot.

#### Implementation

The `scope` object in the envelope (`req-tenable-connection`). Every option is applied server-side in the analysis `query.filters`, so a narrow filter bounds the read as well as the stored data. The kind column is what resolution may rely on. A **scope** filter names a component of the finding's key (repository, plugin, port, protocol), which cannot change without being a different finding, so a stored finding can be tested against it without error. A **non-resolving** filter narrows the read but names either a fact the finding does not store (asset-list membership lives in Security Center, and a `patched` read is a different set from the current one) or a mutable attribute (severity, exploit availability, risk status, CVE, plugin family): upstream can change such a value while the key stays the same, so a finding that dropped out of the filter would be compared with its stale stored value and wrongly marked resolved. A **window** filter excludes findings that are still open. The filter names and value formats are documented only and are probed by the observation command (a bad filter name returns the valid list, per pyTenable).

| Option | Security Center filter | Kind |
| --- | --- | --- |
| `repository_ids` | `repositoryIDs` | scope |
| `asset_ids` | `asset` | non-resolving |
| `min_severity` | `severity` (0 informational to 4 critical); unset by default, so informational results are collected | non-resolving |
| `plugin_ids` | `pluginID` | scope |
| `plugin_families` | `familyID` | non-resolving |
| `exclude_plugin_ids` | not confirmed; client-side unless Security Center supports exclusion | scope |
| `ports`, `protocols` | `port`, `protocol` | scope |
| `exploit_available` | `exploitAvailable` | non-resolving |
| `has_cve` | `cveID` | non-resolving |
| `recast_risk_status` | `recastRiskStatus` (`recast` or `notRecast`); `acceptRiskStatus` is not an option, because every query carries `acceptRiskStatus=all` (`req-tenable-transport-9`) | non-resolving |
| `last_seen_within` | `lastSeen` | **window** |
| `max_records` | a ceiling per repository | safety |

Every run reads both the cumulative and the patched view of each repository with the same filter (`req-tenable-mitigation`), so `source` is not an option. A scope filter is checked against the key components the finding stores (repository, plugin, port, protocol), so the collector knows whether a stored finding was in scope and resolves only those. A filtered run that uses a mutable-attribute filter adds and updates findings but resolves none; the way to resolve is a run without such a filter, which an operator can schedule less often. A run that applies a window filter or a non-resolving filter is **incremental**, is recorded as such with the filter that made it so, and resolves nothing; only a run with scope filters alone, or none, resolves. Fail closed: a filter whose kind is not stated in this table is treated as non-resolving. An unknown option, an invalid value or a filter Security Center rejects refuses the run before any read and never widens it to everything. Saved Security Center queries (`query_id`) are not supported: their contents are not visible to the plugin, so it could not record the scope or say what is safe to resolve.

#### Acceptance Criteria

| ACID | Title | Status | Description | Notes |
| --- | --- | --- | --- | --- |
| req-tenable-scope-1 | Filter In The Envelope | Proposed | The filter is read only from the operator-owned envelope and never from a node. | |
| req-tenable-scope-2 | Filter Recorded On The Run | Proposed | The scan run records the canonical filter exactly as applied and whether the run was incremental. | |
| req-tenable-scope-3 | Window And Non-Resolving Never Infer | Proposed | A run using `last_seen_within`, `asset_ids`, `min_severity`, `exploit_available`, `has_cve`, `recast_risk_status` or `plugin_families` resolves no result by absence (`not_reported`), and is recorded as incremental with the filter responsible; Tenable's own mitigation statements still apply (`req-tenable-mitigation-5`). | A filter of unknown kind is non-resolving. |
| req-tenable-scope-4 | Scope Resolves Only In Scope | Proposed | With scope filters alone, a finding resolves only if its stored key components satisfy every filter; a filter over a mutable attribute or an unstored fact cannot be a scope filter. | A finding outside the filter keeps what it had. |
| req-tenable-scope-5 | Invalid Filter Refuses | Proposed | An unknown option, a bad value or a rejected filter ends the run before any read; it never falls back to an unfiltered read. | |
| req-tenable-scope-6 | Ceiling Is A Recorded Stop | Proposed | Reaching `max_records` records the repository as possibly truncated and resolves nothing in it. | Ties to `req-tenable-states-4`. |
| req-tenable-scope-7 | No Saved Queries | Proposed | A `query_id` option is refused as unsupported. | The scope would be invisible. |

### Security Center And Scan Run
----
RID: `req-tenable-scanner-run`

Status: `Proposed`

The record of which instance was read and what each collection did.

#### Implementation

- `tenable_security_center` (`tenable.area: run`): one per Security Center instance (the console; the scan engines it manages are `tenable_scanner`, `req-tenable-scanners-zones`), with `instance_key` derived from the canonical root of `base_url` (lower-cased scheme and host, the port, the path as configured). `platform` is `security_center` (`vulnerability_management` is reserved for `req-tenable-cloud`). The reported version and the envelope's `network_name` are facts on the Security Center node, not part of its key; repositories are their own nodes (`req-tenable-repository`). Facts the probe needs from the previous run are added with the collector, which names them (ruled 2026-11-12, Q47b).
- `tenable_scan_run` (`tenable.area: run`): one per collection, keyed `(instance_key, run_id)` with a `run_id` the collector mints once per run, as Anchore's run is, so every edge a run's batch writes resolves to the one run node (decided while building the models, 2026-11-12; `KEYLESS` would mint a node per reference). It carries the probe results, the version verdict, the credential identity, the applied filter and incremental flag, `scopes_read` and `scopes_not_read` (each repository and view, with the reason for each not read), and the counters and warning codes below, the one place they are defined:

| Counter or warning | Meaning | Blocks resolution | Source |
| --- | --- | --- | --- |
| `PLAINTEXT_TRANSPORT` | `base_url` is `http://` | no | `req-tenable-connection-9` |
| `TLS_VERIFICATION_DISABLED` | `ssl_verify: false` | no | `req-tenable-connection-4` |
| `VERSION_OUTSIDE` / `VERSION_UNREADABLE` | the version verdict | no | `req-tenable-upstream-versions-3` |
| `FEED_STALE` | the plugin feed is older than the threshold | no | `req-tenable-probe-5` |
| `CREDENTIAL_VIEW_CHANGED` | role, organisation, group or visible repositories changed | yes, all repositories | `req-tenable-probe-4` |
| `HOST_UNIQUENESS_CHANGED` | a repository's list changed | yes, that repository | `req-tenable-findings-12` |
| `RECONCILE_NOT_ARMED` | the run lacks reconcile authority | no, but moved edges accumulate | `req-tenable-run-links-3` |
| `INVENTORY_NOT_VISIBLE` | a scanner, zone or organisation read was refused or narrowed | no | `req-tenable-scanners-zones-4` |
| parse-state counts | parsed, no parser, failed, not applicable | no | `req-tenable-scanner-run-3` |
| `entries_not_stored` | unkeyable or invalid results | yes, that repository | `req-tenable-findings-3` |
| `duplicate_assertions` | two results in one read with one `assertion_key` | no | `req-tenable-scanner-run-5` |
| `fields_truncated` | free text cut at the ceiling | no | `req-tenable-findings-10` |
| `facts_refused` | addresses `computing_core` refused | no | `req-tenable-shared-facts-3` |
| `cve_disagreements` | one plugin, several `cve` strings | no | `req-tenable-plugin-7` |
| `possibly_truncated` | a page at the cap or the record ceiling | yes, that repository | `req-tenable-states-4` |
| `plugins_not_read` | plugin reads that failed | no | `req-tenable-plugin-4` |
| `unknown_format` | repositories of an unknown `dataFormat` | yes, that repository | `req-tenable-probe-6` |
- `RUN_OF_SECURITY_CENTER__tenable`: scan run to Security Center.
- Every observation the run read points at it by one moved edge (`req-tenable-run-links`); the run itself holds no list of what it saw.

#### Acceptance Criteria

| ACID | Title | Status | Description | Notes |
| --- | --- | --- | --- | --- |
| req-tenable-scanner-run-1 | Run Names What It Read | Proposed | The scan run carries the instance host, reported version, repositories, filter, verdict and warnings. | |
| req-tenable-scanner-run-2 | Distinct Roots Are Distinct Scanners | Proposed | The same host on a different port or path root yields a different instance key; a test asserts it and asserts the key carries no credential. | |
| req-tenable-scanner-run-3 | Counts By Parse State | Proposed | The scan run records how many findings were parsed, had no parser, failed to parse or were not applicable. | The visible measure of parser coverage. |
| req-tenable-scanner-run-4 | One Table Of Counters | Proposed | Every counter and warning the collector emits is in the table above, and a test fails when the code emits one not listed or the table lists one never emitted. | Anchore's run accounting. |
| req-tenable-scanner-run-5 | Duplicates Counted | Proposed | Two results in one read with one `assertion_key` store one finding and count one duplicate. | |
| req-tenable-scanner-run-6 | No Edge Joins Two Consoles | Proposed | Every edge between two Tenable nodes joins nodes with the same `instance_key`; the collector builds each run's edges from one console's nodes only and refuses any other, and a test writes two consoles and asserts no edge crosses them. | The grid constrains edge endpoint types, not values; this plugin is the only writer of its edges, so the collector is where the rule is enforced; the owner ruled 2026-11-12 (Q54a) to keep it there until the grid can declare it. WORKAROUND(unified-systems-com/tap#1187): a grid-level same-scope edge declaration would replace it. |

### Scanners And Scan Zones
----
RID: `req-tenable-scanners-zones`

Status: `Proposed`

The scan engines a Security Center manages, and the zones that group them. One console commonly drives several Nessus scanners, Nessus Managers and passive scanners, so the console and its engines are separate nodes. Ruled 2026-11-12 (Q48).

#### Implementation

- `tenable_scanner` (`tenable.area: run`), key `(instance_key, scanner_kind, scanner_id)`, where `scanner_kind` is `active` for an entry of `GET /rest/scanner` and `passive` for one of `GET /rest/passivescanner`, because the two lists number their ids separately. It carries, as returned under pinned `fields`: `id`, `name`, `description`, `ip`, `port`, `status`, `enabled`, `version`, `type`, `agentCapable`, `loadedPluginSet`, `numScans`, `numHosts`, and Nessus's own `serverUUID`, stored and not keyed (an administrator re-adding a scanner gets a new id, inferred). Never `username`, `password`, `cert`, `accessKey` or `secretKey`. Plus `state` (`req-tenable-states-7`). Edges: `MANAGED_BY_SECURITY_CENTER__tenable` to the console; `IN_SCAN_ZONE__tenable` to each zone it belongs to.
- `tenable_scan_zone` (`tenable.area: run`), key `(instance_key, zone_id)`, from `GET /rest/zone` (or the zones `GET /rest/currentOrganization` returns, when that is all the credential can see): `id`, `uuid` (stored, not keyed), `name`, `description`, `ipList` (the ranges, as returned), `createdTime`, `modifiedTime`, and `state`.
- `RUN_BY_SCANNER__tenable`: scan result to each scanner its detail record names (`req-tenable-scan-result-4`).

These reads are optional probe data. Documented: an organisation user's `GET /rest/scanner` returns only its organisation's agent-capable scanners with five fields, and full scanner and zone data is an administrator's view; the optional admin envelope (`req-tenable-connection`) supplies it. A read that is refused or narrowed records `INVENTORY_NOT_VISIBLE` with the endpoint, and the absence of a scanner from a narrowed list is recorded as not visible to this credential, never as no scanner, and withdraws nothing. A zone's ranges are stored as Tenable returns them; mapping a zone to a `computing_core` network is not done in v0, and per-zone network configuration is the likely answer to consoles whose results span several networks.

#### Acceptance Criteria

| ACID | Title | Status | Description | Notes |
| --- | --- | --- | --- | --- |
| req-tenable-scanners-zones-1 | Console And Engines Apart | Proposed | One console with three scanners yields one `tenable_security_center` and three `tenable_scanner` nodes, each with a `MANAGED_BY_SECURITY_CENTER__tenable` edge. | |
| req-tenable-scanners-zones-2 | Kind In The Key | Proposed | An active and a passive scanner with the same id are two nodes. | The two lists number ids separately (documented). |
| req-tenable-scanners-zones-3 | No Secret Fields | Proposed | No scanner or zone node has a field for a username, password, certificate or API key, and the pinned `fields` names none. | `req-tenable-transport-8`. |
| req-tenable-scanners-zones-4 | Not Visible Is Not None | Proposed | A refused or narrowed inventory read records `INVENTORY_NOT_VISIBLE` and withdraws no scanner or zone; a test runs the organisation-user shape and asserts nothing withdrawn. | Ruled 2026-11-12 (Q51b). |
| req-tenable-scanners-zones-5 | Zone Membership As Edges | Proposed | A scanner's zones are `IN_SCAN_ZONE__tenable` edges, not a stored list alone. | |

### Plugin Metadata
----
RID: `req-tenable-plugin`

Status: `Proposed`

What Tenable says about the plugin that produced a finding, held once and linked from every finding it produced.

#### Implementation

`tenable_plugin` (`tenable.area: plugin`), natural key `(instance_key, plugin_id)`, so two instances' feeds never share a node. Read from `GET /rest/plugin/{id}` for each distinct `pluginID` the run saw, with the fields named in the documented list: name, `description`, family (id, name, type), `cpe`, `xrefs`, `dependencies`, `requiredPorts`, `requiredUDPPorts`, `riskFactor`, `solution`, `seeAlso`, `synopsis`, `checkType`, the exploit fields, the CVSS, VPR and EPSS scores, the publication and modification dates, `modifiedTime`, `agent`, `seolDate`, `stigSeverity`, the CVSS vector strings, and `type` (documented values `active`, `passive`, `lce`, `compliance`, `custom`), each as returned, plus `cve`, the plugin's CVE string exactly as the findings that name the plugin return it. Security Center returns `cve` on each finding, but it describes the plugin, so it is held once here and not copied onto every host's finding: a cumulative operating-system update plugin names hundreds of CVEs and is reported once per affected host. A finding reaches its CVEs through its plugin. Whether Security Center returns a `cve` string on every finding at all, whether it can be switched off or varied by configuration, and whether it is the same for every finding of one plugin are all unobserved (`req-tenable-finding-cve-narrowing` is the Backlog response if a recording shows host-specific sets); if two findings of one plugin in a run disagree, the plugin keeps the first string read, and the scan run records the plugin id, the number of distinct strings seen and up to ten example assertion keys of the findings that differed, so the evidence is recoverable and a recording shows which findings carried which variant. The `cve` string and its vulnerability edges are refreshed whenever a run's findings carry a different string, independently of `pluginModDate`, which governs only the fields `GET /plugin/{id}` supplies. A plugin node is rewritten when its `pluginModDate` changes; the earlier version is kept as the grid keeps history. `ABOUT_PLUGIN__tenable`: finding to plugin. `IN_PLUGIN_FAMILY__tenable`: plugin to its family (`req-tenable-plugin-family`). The `cpe` is held here once, like the `cve` string, and on no finding: it describes the plugin's target, and a finding reaches it through its plugin; when findings of one plugin carry different `cpe` strings, the disagreement is recorded as for `cve`. A plugin whose `GET /plugin/{id}` read failed is still written from the fields its findings carry (`pluginID`, `pluginName`, `family`, `cpe`, `cve`), every field only the plugin read supplies is `null`, and the plugin is listed as not read; the CVE edges and the finding's plugin edge therefore never depend on that read.

#### Acceptance Criteria

| ACID | Title | Status | Description | Notes |
| --- | --- | --- | --- | --- |
| req-tenable-plugin-1 | One Node Per Plugin Per Scanner | Proposed | Two findings from one plugin on one instance share one plugin node; the same plugin on two instances is two nodes. | |
| req-tenable-plugin-2 | Fields As Returned | Proposed | Plugin fields are stored as Tenable returns them, with no scale, mapping or selection. | |
| req-tenable-plugin-3 | Revised On Modification | Proposed | A changed `pluginModDate` revises the node; an unchanged plugin is not rewritten. | |
| req-tenable-plugin-4 | Unread Plugin Is Visible | Proposed | A plugin that could not be read is listed as not read, is still written from its findings' fields with the rest `null`, and its findings and CVE edges are still written. | Three states: unread is not absent. |
| req-tenable-plugin-5 | CVEs Held Once | Proposed | The plugin's `cve` string is stored on the plugin node and on no finding; a test asserts a finding has no CVE field and that two findings of one plugin share one CVE list. | Edge and storage multiplication by host count is the failure to avoid. |
| req-tenable-plugin-6 | CVE Refresh Is Independent | Proposed | A changed `cve` string revises the plugin's CVE list and its vulnerability edges even when `pluginModDate` is unchanged, and an unchanged string rewrites nothing; a test covers both. | The CVE string comes from findings, not from the plugin read. |
| req-tenable-plugin-7 | Disagreement Is Recoverable | Proposed | When findings of one plugin carry different `cve` strings, the scan run records the plugin id, the distinct count and up to ten example assertion keys. | Dropping the variants silently would hide a host-specific CVE set. |
| req-tenable-plugin-8 | CPE Held Once | Proposed | The plugin's `cpe` is stored on the plugin node and on no finding; a test asserts a finding has no CPE field. | Same reasoning as `-5`. |

### Plugin Families
----
RID: `req-tenable-plugin-family`

Status: `Proposed`

Tenable groups plugins into families, and risk rules, scan policies and filters name families. Many plugins share one family, so it is its own node.

#### Implementation

`tenable_plugin_family` (`tenable.area: plugin`), key `(instance_key, family_id)`, from `GET /rest/pluginFamily` with pinned `fields` (`id`, `name`, `type`, `count`), as returned, and `state`. Each plugin links to its family by `IN_PLUGIN_FAMILY__tenable`. A family a plugin names that the list did not return is written from the plugin's own family fields.

#### Acceptance Criteria

| ACID | Title | Status | Description | Notes |
| --- | --- | --- | --- | --- |
| req-tenable-plugin-family-1 | One Node Per Family | Proposed | Two plugins of one family share one family node per instance. | |
| req-tenable-plugin-family-2 | Every Plugin Has Its Family | Proposed | Every plugin node with a family id has exactly one `IN_PLUGIN_FAMILY__tenable` edge. | |

### Findings
----
RID: `req-tenable-findings`

Status: `Proposed`

How Security Center's plugin results, other than configuration audit checks (`req-tenable-compliance-results`), become Tenable-owned nodes, each holding what Tenable returned in the form it returned it: vulnerability results and informational results alike. This plugin writes no `compliance_core` node.

#### Implementation

`tenable_finding` (`tenable.area: finding`): one per assertion, for every result whose plugin is not of type `compliance` (when the plugin read failed, a result whose output carries a `cm:compliance-result` element is treated as a compliance result). Its natural key is `(instance_key, assertion_key)`, both non-null strings, because a null part is an unobserved hole and would mint a new node every run. `assertion_key` is the sha256 of the compact JSON array `[repository_id, host_key, plugin_id, port, protocol]`, a fixed 64 characters whatever the parts hold, as Anchore derives its package key. `host_key` is the observed host's key (`req-tenable-observed-host`), derived by one function from the record's own `hostUniqueness` field list, which is how Security Center itself says a host is told apart in that repository (for example `repositoryID,ip,dnsName` in an IPv4 repository, `repositoryID,hostUUID` in a universal one; Tenable documents the record's `uuid` field as the agent UUID, so an agent repository's list names `uuid`); the Elastic and Splunk integrations build identity the same way. The field list is stored as `host_uniqueness`, and the component columns (`repository_id`, `host_uuid`, `agent_uuid`, `ip`, `dns_name`, `plugin_id`, `port`, `protocol`) are stored and searchable beside the key; the model validates `host_key` and `assertion_key` against them, so no two stored copies can drift and the key rests only on facts the model carries. The function fails closed: the list must be non-empty and name only fields from a known set (`repositoryID`, `ip`, `dnsName`, `netbiosName`, `macAddress`, `uuid`, `hostUUID`); every named field must be present and non-null on the record (`repositoryID` taken from `repository.id`; the stored `agent_uuid` column is the record's `uuid`, and a list naming any other agent field, such as `agentUUID`, is unkeyable until a recording shows it and this set is extended by a spec change); duplicates are removed and the names sorted before hashing, so a reordered list yields the same key; and the repository id is always hashed in, whether or not the list names `repositoryID`, so equal IP, DNS or MAC values in two repositories never become one observed host. A host Security Center tracks in two repositories is therefore two observed hosts, joined, if ever, by the reconciler. Anything else makes the result unkeyable (`req-tenable-findings-3`). Each repository's list is recorded on the repository node, and a run in which a repository's list differs from the last run's records the change and resolves nothing in that repository by absence, because every host key in it moved. Whether Security Center guarantees the list is stable per repository is undocumented; the observation command reports the lists it sees. `macAddress` may appear in the list because it is Tenable's rule for telling its own hosts apart, and it then keys only the Tenable-owned observed host; whether a MAC is trusted as a shared fact is a separate rule (`req-tenable-shared-facts-5`). A result missing any component is not stored (`req-tenable-findings-3`), so no key is ever built over a hole. The reported `ip`, `dns_name`, `netbios_name`, `mac_address` and `operating_system` are stored beside it as returned. `port` and `protocol` are the strings Tenable returns, so `"0"` and `"TCP"` are observed values. The finding carries the fields that belong to the result on this host, as returned: `severity` (id, name; after any recast), `first_seen`, `last_seen` and `last_mitigated` as the epoch strings returned (`last_mitigated` is documented only as a filter name and appears in no documented example, so it is nullable and confirmed by observation), `accept_risk`, `recast_risk`, their rule comments, `has_been_mitigated`, Tenable's own result identifiers `vuln_uuid` and `vuln_uniqueness` (stored, never keyed: only 6.7 and later guarantee them; ruled 2026-11-12, Q50b), `acr_score` and `asset_exposure_score`, and the raw `plugin_text` in full up to the free-text ceiling below. What describes the plugin rather than the result (`risk_factor`, the base, temporal, VPR, CVSS v2, v3 and v4 scores and vector strings, EPSS, the exploit fields, `seol_date`, `stig_severity`, the family) is held once on the plugin node and reached through `ABOUT_PLUGIN__tenable`, for the same reason as the CVE and CPE strings (`req-tenable-plugin-5`, `-8`): it is the same on every host's result, and a copy per host is storage multiplied by host count. It also carries `state` (`current` or `resolved`, null when never observed), `resolution_source` (`req-tenable-states-3`), `observation_path` (`passive` when the plugin's `type` is `passive`, else `on_board` when the repository is `agent` format, else `network`, refined by the plugin's `checkType` once a recording shows what that field holds), and the parse result of `req-tenable-parsers`. The run that last read it is an edge, not a field (`req-tenable-run-links`).

Edges from a finding: `ABOUT_PLUGIN__tenable` to its plugin; `ABOUT_HOST__tenable` to its observed host; `ABOUT_PORT__tenable` to the shared port when the result names a port other than `"0"`, or `ABOUT_ADDRESS__tenable` to the shared address when it names an IP and no port (`req-tenable-shared-facts`).

#### Acceptance Criteria

| ACID | Title | Status | Description | Notes |
| --- | --- | --- | --- | --- |
| req-tenable-findings-1 | Keyed By Assertion | Proposed | A finding's key is the instance and an `assertion_key` derived from the repository, host, plugin, port and protocol, and never the run; two runs reporting the same assertion are one finding. | |
| req-tenable-findings-2 | Key Rests On Carried Facts | Proposed | `assertion_key` is validated against the stored component columns it derives from, and a row whose key disagrees is rejected; no key part is computed outside the model. | `req-grid-entity-natural-key`: nothing computed in the collector. |
| req-tenable-findings-3 | An Unkeyable Entry Is Counted | Proposed | A result whose `hostUniqueness` list is unkeyable under `-12` (empty, naming an unknown field, or naming a field that is absent or null on the record), or that lacks `pluginID`, `port` or `protocol`, is not stored and is counted on the run; a read in which any entry was not stored resolves nothing in that repository. | Null is a hole, not an observed empty. |
| req-tenable-findings-4 | Fields As Returned | Proposed | Severity, scores, dates and flags are stored as Tenable returns them, with no enum, mapping, selection or coercion. | |
| req-tenable-findings-5 | Raw Evidence Kept | Proposed | The raw `plugin_text` is stored unmodified beside any parse result. | A parser fix means re-parse, not re-collect. |
| req-tenable-findings-6 | Scanner In The Key | Proposed | The same assertion from two instances is two findings, and resolution is scoped to one scanner. | |
| req-tenable-findings-7 | Key Is Never Null | Proposed | `instance_key` and `assertion_key` are non-null on every stored finding, and a test builds a finding from each component being absent and expects it not stored. | A null key part would mint a duplicate each run (`find_existing` treats it as a hole). |
| req-tenable-findings-8 | Host Identity Stability Is Open | Proposed | The spec records that a host first seen without a `hostUUID` and later with one would change its `host_key`; the observation command reports whether the same plugin, port and IP appears both ways, and the rule is settled from a recording, not designed around. | Unobserved; documented fields only. |
| req-tenable-findings-9 | Plugin Output Is Sensitive Evidence | Proposed | `plugin_text` is stored as returned, up to the ceiling of `req-tenable-findings-10`, and described in its `help_text` and the README as scanner output that can hold paths, configuration fragments or credentials; the plugin neither scans nor redacts it, and the grid's read authorization is what protects it. The same holds for a parser's `evidence` segment. | The same stance as Anchore's operator-authored VEX text. The grid has no per-field classification this plugin could set. |
| req-tenable-findings-10 | Plugin Output Kept Whole Up To A Recorded Ceiling | Proposed | `plugin_text` is stored in full in a text column with no fixed length, up to a ceiling of 4 MiB (4,194,304 bytes, UTF-8); a longer value is cut at the last whole character within the ceiling, its field is named in the result's `truncated_fields`, the run counts it, and the parse state is `parser_failed`. Tests store a value larger than any fixed column and below the ceiling and read it back unchanged, and store one above the ceiling and find the cut recorded. | Never silently lost (the Splunk add-on replaces large output with a stub), and never unbounded (a broken or hostile instance cannot bloat the grid). Ruled 2026-11-12. |
| req-tenable-findings-11 | Host Part From Host Uniqueness | Proposed | `host_key` is derived from the record's `hostUniqueness` fields and validated against the stored columns; a test covers an IPv4, a universal and an agent record. | Security Center's own identity rule per repository. |
| req-tenable-findings-12 | Host Uniqueness Fails Closed | Proposed | An empty list, an unknown field name or a named field that is absent or null makes the result unkeyable; a reordered or duplicated list yields the same key; a repository whose list changed since the last run resolves nothing by absence in that run; a list without `repositoryID` still yields keys that differ by repository. Tests cover each. | Upstream data controls identity, so the input is checked before it can merge or split hosts. |
| req-tenable-findings-13 | One Ceiling For All Free Text | Proposed | The 4 MiB ceiling applies to every text and JSON column of every Tenable node (plugin output, the compliance result's `cm:` columns, risk-rule comments and host values, plugin descriptions and CVE strings, asset-list definitions, scan-result details, program evidence, the host summary), checked once on save by the shared node base; the collector cuts and records before writing. | One rule, so no text field is the unbounded one. |

### Shared Vulnerability Link
----
RID: `req-tenable-vulnerability-link`

Status: `Proposed`

A plugin names CVEs; the grid has a shared vulnerability node. This plugin links to it and never writes it. The link is from the plugin, not the finding: one plugin is reported once per affected host, so a finding-level edge per CVE would multiply by the size of the fleet (Cartography's Tenable module moved its CVE edges from findings to plugins after a plugin naming hundreds of CVEs did exactly that).

#### Implementation

`ABOUT_VULNERABILITY__tenable`: plugin to `compliance_core__compliance_vulnerability`, one per CVE in the plugin's `cve` string (comma-separated, split exactly on the delimiter, no other normalisation), written only when a vulnerability with exactly that `vuln_id` already exists, compared exactly and case-sensitively. None is created or changed, and no alias is resolved. A plugin with no CVE has no vulnerability edge and is stored all the same, and so are its findings. A finding reaches its vulnerabilities by traversal through `ABOUT_PLUGIN__tenable`; no edge to a vulnerability is ever written from a finding. `compliance_core` is a vocabulary dependency in `depends_on`, with a note.

#### Acceptance Criteria

| ACID | Title | Status | Description | Notes |
| --- | --- | --- | --- | --- |
| req-tenable-vulnerability-link-1 | Linked, Never Written | Proposed | The edge is written only against an existing exact-id vulnerability; the plugin never creates or patches `compliance_core` nodes. | |
| req-tenable-vulnerability-link-2 | One Edge Per CVE | Proposed | A plugin with three CVEs and three matching nodes has three edges; an unmatched CVE has none and is still on the plugin's raw `cve`. | |
| req-tenable-vulnerability-link-3 | No Interpretation | Proposed | No alias, case fold or format change is applied to a CVE id. | |
| req-tenable-vulnerability-link-4 | Not From The Finding | Proposed | No edge to a vulnerability starts at a finding, and the number of vulnerability edges a run writes depends on the number of distinct plugins, not the number of findings. | A test with one plugin and many hosts counts the edges. |

### Per-Plugin Package Parsers
----
RID: `req-tenable-parsers`

Status: `Proposed`

What ties a finding to a package, software or application is not a structured field in Security Center: the plugin's CPE names the product the plugin targets, and the installed package, version and path appear only in the free-text plugin output, in a shape that differs by plugin. So the package association is one parser per plugin.

#### Implementation

`tap_plugin/tenable/parsers/` holds one module per plugin, `plugin_<id>.py`. A parser is a pure function `parse(finding) -> list[PackageObservation]` with no I/O, where `finding` is the validated finding fields (`plugin_text`, `cpe`, `port`, `protocol` and the plugin id). A `PackageObservation` has `ecosystem`, `product`, `name`, `version`, `installed_path`, `fixed_version`, `evidence` and `mapping_unambiguous`, where every field but `mapping_unambiguous` is nullable and `mapping_unambiguous` is a boolean the parser sets true only when its `ecosystem`, `name` and `version` identify exactly one `computing_core` package (`req-tenable-package-link`); `evidence` is the exact segment of the plugin output the values were read from. A parser registers itself by plugin id in a registry. The collector records, per finding, exactly one parse state:

- `parsed`: the plugin has a parser and it returned observations (an empty list is a recorded, observed result);
- `no_parser`: the plugin has none; **never "no package"**;
- `parser_failed`: the output did not match the parser; the raw text is kept and the failure is counted on the run;
- `not_applicable`: the plugin is known to carry no package information, by an explicit entry in the registry.

The observations, the state, the parser's id and its version are stored on the finding beside the raw text; parsing edits no stored Tenable field, so a parser improvement re-parses stored findings without re-collecting. Every parser ships with a fixture of real plugin output at `tests/fixtures/plugin_<id>.txt` and a test; because v0 is built blind, the first fixtures come from public plugin descriptions and examples and are marked *documented*, and a parser does not reach `Implemented` until a recorded response from a real instance replaces its fixture. The first parsers are written for the highest-volume plugins an instance returns, chosen from the observation command's report rather than guessed. Host software enumeration (`req-tenable-software-enumeration`) is a later parser of the same contract. The same registry holds the two non-package parsers v0 needs: the service-detection parser that yields observed programs (`req-tenable-observed-program`) and the shared `cm:` parser for compliance results (`req-tenable-compliance-results`). No third-party parsing library is used: none maintained parses Tenable plugin output (surveyed 2026-11-12), and pyTenable's `NessusReportv2` is reserved for `.nessus` files (`req-tenable-nessus-download`). The plugin text Security Center returns is wrapped in `<plugin_output>` tags (community reports, unobserved here); parsers receive it with the wrapper removed, and the stored text keeps it.

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

### Compliance Results
----
RID: `req-tenable-compliance-results`

Status: `Proposed`

How configuration audit check results (a CIS or DISA benchmark check that passed, failed or warned) become Tenable-owned nodes. They mean something different from a vulnerability, carry different fields, and are read differently, so they have their own type.

#### Implementation

`tenable_compliance_result` (`tenable.area: finding`): one per audit check result, for every result whose plugin is of type `compliance`. Security Center assigns each audit check its own plugin id above 1,000,000, and those ids may differ between instances (documented, Tenable's audit-file pages), so the key is the finding's, `(instance_key, assertion_key)`, over the same components, and the plugin key's scanner part keeps two instances' ids apart. The result, policy value, actual value and the rest are not structured fields in Security Center; they are `cm:` elements inside the plugin output. One shared parser (`parsers/compliance.py`, registered for every compliance plugin) reads the documented elements: `cm:compliance-check-name`, `-check-id`, `-result`, `-actual-value`, `-policy-value`, `-audit-file`, `-benchmark-name`, `-benchmark-version`, `-benchmark-profile`, `-control-id`, `-functional-id`, `-informational-id`, `-full-id`, `-info`, `-reference`, `-see-also`, `-solution`, `-source` and `-error`, each stored as its own column as written, `null` when absent. The raw `plugin_text`, severity as returned (Tenable maps Pass to Info, Warning to Medium, Fail to High), dates, state, resolution and parse state are stored as on a finding. MITRE's `nessus-to-hdf` converter (Apache-2.0) is the reference design for reading these elements, and its `compliance.nessus` fixture is the first documented fixture. Edges: `ABOUT_PLUGIN__tenable` and `ABOUT_HOST__tenable`, as on a finding. Mapping a result to a compliance control is not done here.

#### Acceptance Criteria

| ACID | Title | Status | Description | Notes |
| --- | --- | --- | --- | --- |
| req-tenable-compliance-results-1 | Own Type | Proposed | A result whose plugin is of type `compliance` is a compliance result and never a finding; a test routes one of each. | |
| req-tenable-compliance-results-2 | Elements As Written | Proposed | Each documented `cm:` element is stored in its own column exactly as written, `null` when absent, beside the raw text. | No result vocabulary is imposed. |
| req-tenable-compliance-results-3 | One Check, One Node | Proposed | Two checks on one host are two nodes; a test fails if two checks with distinct plugin ids share a key. | Whether ids are per check is documented, not observed; a recording settles it. |
| req-tenable-compliance-results-4 | No Control Mapping | Proposed | No compliance result is linked to a control or a `compliance_core` node by this plugin. | A later layer. |

### Tenable's Mitigation Record
----
RID: `req-tenable-mitigation`

Status: `Proposed`

Security Center keeps its own record of what it found fixed. Reading it gives a resolution better grounded than ours, and Tenable's mitigation date.

#### Implementation

Every run reads, for each repository it reads, the patched view (`sourceType: patched`) with the same filter as the cumulative view, by the same paging and validation rules. A result in the patched view is written or updated with Tenable's mitigation fields (`last_mitigated`, `has_been_mitigated` as returned), `state: resolved` and `resolution_source: tenable_mitigated`; one never seen in the cumulative view is still written, as resolved. A result reported in both views in one run (Tenable mitigated it and a later scan found it again) is `current`. A repository whose patched read failed is listed as not read for resolution, and only `tenable_mitigated` resolutions from other repositories apply in that run. Precedence with filters: a result the patched view returns is resolved as `tenable_mitigated` in any run, filtered or not, because it is Tenable's positive statement about that result and not an inference from absence; a filter only narrows which such statements a run reads. The fail-closed rules of `req-tenable-scope` govern the `not_reported` fallback alone, which no incremental run applies.

#### Acceptance Criteria

| ACID | Title | Status | Description | Notes |
| --- | --- | --- | --- | --- |
| req-tenable-mitigation-1 | Both Views Every Run | Proposed | Each repository read is read in both the cumulative and the patched view with one filter, and the run records both reads' outcomes. | |
| req-tenable-mitigation-2 | Tenable's Record First | Proposed | A result in the patched view is resolved with `resolution_source: tenable_mitigated` and Tenable's mitigation date. | |
| req-tenable-mitigation-3 | Current Wins | Proposed | A result in both views in one run is `current`. | |
| req-tenable-mitigation-4 | Failed Patched Read Blocks Fallback | Proposed | When a repository's patched read fails, no result in it resolves by the `not_reported` fallback. | |
| req-tenable-mitigation-5 | Positive Statement Under Any Filter | Proposed | A result returned by the patched view in a run using `last_seen_within` or `min_severity` is resolved as `tenable_mitigated`, and no result in that run resolves as `not_reported`; a test covers both. | `req-tenable-scope-3` governs only the fallback. |

### Repositories
----
RID: `req-tenable-repository`

Status: `Proposed`

A repository is the unit Security Center stores results in, the unit this plugin reads and resolves by, and the place the data format that tells agent data apart is declared.

#### Implementation

`tenable_repository` (`tenable.area: run`), key `(instance_key, repository_id)`, from the probe's `GET /rest/repository`: `id`, `uuid`, `name`, `description`, `type` (Local, Remote, Offline), `dataFormat` (`agent`, `IPv4`, `IPv6`, `mobile`, `universal`), `vulnCount`, `lastSyncTime`, `lastVulnUpdate` and the data lifetimes `activeVulnsLifetime`, `passiveVulnsLifetime`, `complianceVulnsLifetime` and `mitigatedVulnsLifetime` (documented), as returned; the `hostUniqueness` list last seen in it; and `state` (`req-tenable-states-7`). Edges: `HELD_BY_SECURITY_CENTER__tenable` to the Security Center. Observed hosts and scan results point at it (`RECORDED_IN_REPOSITORY__tenable`, `IMPORTED_INTO_REPOSITORY__tenable`).

#### Acceptance Criteria

| ACID | Title | Status | Description | Notes |
| --- | --- | --- | --- | --- |
| req-tenable-repository-1 | One Node Per Repository | Proposed | Each repository the credential can see is one node per scanner, rewritten when its fields change. | |
| req-tenable-repository-2 | Format Drives Path | Proposed | A result's `observation_path` is `passive` when its plugin's type is `passive`, `on_board` when its repository is `agent` format, and `network` otherwise; a test covers all three. | Passive scanners observe traffic, not hosts they probe. |
| req-tenable-repository-3 | Lifetimes Kept | Proposed | The repository stores its four data lifetimes as returned, `null` when absent, and `aged_out` reads them. | Ruled 2026-11-12 (Q49b). |

### Scan Results
----
RID: `req-tenable-scan-result`

Status: `Proposed`

The scans Tenable ran: which, when, under what policy, and how much of the target they covered. This is a record Tenable keeps, not a scan definition, which stays out of scope.

#### Implementation

`tenable_scan_result` (`tenable.area: run`), key `(instance_key, scan_result_id)`, from `GET /rest/scanResult` with an explicit `fields` list, for results whose `finishTime` (or `startTime` while running) falls within `scan_result_window_days`: `id`, `name`, `description`, `status`, `initiator` (id only), `owner` (id only), `repository`, `scan` (id and name), `importStatus`, `importStart`, `importFinish`, `dataFormat`, `resultType`, `resultSource`, `running`, `errorDetails`, `importErrorDetails`, `totalIPs`, `scannedIPs`, `completedIPs`, `completedChecks`, `totalChecks`, `startTime`, `finishTime`, `scanDuration`, `agentScanUUID`, `details` (which names the policy), `downloadAvailable`, as returned; the list is read with `timeCompareField=finishTime`. No user's name or contact details are stored. Edges: `RESULT_OF_SECURITY_CENTER__tenable` to the Security Center, `IMPORTED_INTO_REPOSITORY__tenable` to the repository, and `RUN_BY_SCANNER__tenable` to each scanner its detail record names (`GET /rest/scanResult/{id}`, pinned fields; documented). Which scan last saw each result is a dimension, not an edge, because one scan can see tens of thousands of results and an edge per result would make the scan result a super-node (ruled 2026-11-12, Q53c). This plugin declares and seeds an open dimension `tenable.scan_result`, valued by the scan result's key (`<instance_key>#<scan_result_id>`, so two consoles' scan ids never collide). Each run reads, for every scan result in the window whose import finished, the `individual` view (`sourceType: individual`, the scan result's id, the same pinned body otherwise; documented) once, oldest first, and stamps each finding, compliance result, observed host and observed program it returns with that scan result, so the value is the newest scan that saw it. A dimension holds one value: earlier scans survive only in the node's history, and the dimension is filtered on, not traversed. An `individual` read that fails is listed as not read and changes no stamp; it never resolves anything, because the cumulative and patched views decide state. The `.nessus` step (`req-tenable-nessus-download`) adds what the file alone carries.

#### Acceptance Criteria

| ACID | Title | Status | Description | Notes |
| --- | --- | --- | --- | --- |
| req-tenable-scan-result-1 | Within The Window | Proposed | Only scan results inside the window are read, and the window is recorded on the run. | |
| req-tenable-scan-result-2 | No Personal Data | Proposed | Initiator and owner are stored as ids only. | |
| req-tenable-scan-result-3 | Status As Returned | Proposed | `status` and `importStatus` are stored as returned, with no enum. | The values are undocumented. |
| req-tenable-scan-result-4 | Scanners Named By The Detail | Proposed | A scan result links to each scanner its detail record names, and a scanner not yet known is written from the fields the detail carries; a detail read refused leaves no edge and is counted. | Documented. |
| req-tenable-scan-result-5 | Last Scan As A Dimension | Proposed | Findings, compliance results, observed hosts and observed programs carry `tenable.scan_result`, the newest scan result in the window whose `individual` view returned them; a test reads two scans in order and expects the later one; a failed `individual` read changes no stamp and resolves nothing; no edge from a result to a scan result is written. | Ruled 2026-11-12 (Q53c): a dimension, to avoid a super-node. |

### Observed Hosts
----
RID: `req-tenable-observed-host`

Status: `Proposed`

A host as Tenable tracks it. Tenable's notion of "a host" is its own construct, keyed its own way, so it is an observation and not a `computing_core` host; facts it reports about the host link to shared nodes.

#### Implementation

`tenable_observed_host` (`tenable.area: observation`), key `(instance_key, host_key)`, where `host_key` is derived from the record's `hostUniqueness` fields by the one function `req-tenable-findings` uses, so every result, its host and its programs agree. Written for every keyable result. It carries, as last reported: `host_uniqueness` and the component columns, `host_uuid`, `agent_uuid`, `ip`, `ips`, `dns_name`, `netbios_name` (stored here until a NetBIOS node exists), `mac_address`, `operating_system` (Tenable's guess, as returned), and the per-host facts of the host summary tool (`sumip`): the last authenticated and last unauthenticated scan times and the OS CPE, under the names the tool returns, which are undocumented and settled by the observation command. Cloud identifiers Tenable reports (an EC2 instance id) are stored as attributes when a parser yields them; mapping them to `aws_core` nodes is `req-tenable-reconciler`. Edges: `RECORDED_IN_REPOSITORY__tenable` to the repository; to shared facts, `OBSERVED_AT_ADDRESS__tenable` (address), `REPORTS_DNS_NAME__tenable` (DNS name, once `computing_core__dns_name` exists) and `REPORTS_INTERFACE__tenable` (network interface by MAC), per `req-tenable-shared-facts`. The address edge is Tenable's to retire: when a later run reports a host at a different address, edge authority retires the old one. That applies only to hosts whose `host_key` does not include `ip` (universal and agent repositories, keyed by UUID). Where the repository's `hostUniqueness` names `ip` (IPv4 repositories), Security Center itself treats a host at a new address as a different host, so a new observed host is minted; the old one keeps its address edge, which stays true as history, and its `LAST_SEEN_IN_RUN__tenable` edge shows when it was last reported. Joining the two is the reconciler's job, not this collector's.

#### Acceptance Criteria

| ACID | Title | Status | Description | Notes |
| --- | --- | --- | --- | --- |
| req-tenable-observed-host-1 | Same Key As Its Results | Proposed | A finding's `host_key` equals its observed host's, for IPv4, universal and agent records. | |
| req-tenable-observed-host-2 | Never A computing_core Host | Proposed | No `computing_core__host` is written or rewritten by this plugin. | Tenable's host is an observation. |
| req-tenable-observed-host-3 | Moves Retire Edges | Proposed | A UUID-keyed host reported at a new address gains the new address edge and loses the old one by edge authority; an IP-keyed host at a new address is a new observed host, and the old one's edge is left in place. A two-run test covers both. | IP-keyed identity is Security Center's own rule for IPv4 repositories. |
| req-tenable-observed-host-4 | Scan Coverage Kept | Proposed | The host summary's last authenticated and unauthenticated scan times are stored as returned, `null` when absent. | Whether a host had a credentialed scan is a FedRAMP question. |

### Observed Programs
----
RID: `req-tenable-observed-program`

Status: `Proposed`

What Tenable thinks is listening on a host's port. A network scan infers the service; it does not see the program, so this is an observation, never a `computing_core` program.

#### Implementation

`tenable_observed_program` (`tenable.area: observation`), key `(instance_key, host_key, transport, port_number)`, where `transport` and `port_number` are the result's protocol and port as returned. Security Center's analysis records carry no service name, so a program is written only when a registered service-detection parser yields one: v0 registers a parser for Service Detection (plugin 22964), whose output names the service ("A web server is running on this port."). It carries `service_name`, `detecting_plugin_id` and the evidence segment; `product`, `version` and `cpe` are added with `req-tenable-product-parsers`, which fills them, and not before. Edges: `HOSTS_PROGRAM__tenable` from the observed host, and `OBSERVED_ON_PORT__tenable` to the shared port (`req-tenable-shared-facts`).

#### Acceptance Criteria

| ACID | Title | Status | Description | Notes |
| --- | --- | --- | --- | --- |
| req-tenable-observed-program-1 | Parser Or Nothing | Proposed | A program is written only from a registered service-detection parser's result; a port with no such result has no program. | No empty node per socket. |
| req-tenable-observed-program-2 | Never A computing_core Program | Proposed | No `computing_core__program` is written by this plugin. | |
| req-tenable-observed-program-3 | Keyed By Host And Socket | Proposed | Two services on two ports of one host are two programs; the same port on two hosts is two programs. | |

### Risk Rules
----
RID: `req-tenable-risk-rules`

Status: `Proposed`

An operator's statement in Tenable that a result is accepted, or should be read at another severity. These are Tenable's deviation record, the counterpart of Anchore's VEX annotations, and a finding only carries a flag that one applied.

#### Implementation

`tenable_accept_risk_rule` and `tenable_recast_risk_rule` (`tenable.area: risk`), keys `(instance_key, rule_id)`, from `GET /rest/acceptRiskRule` and `GET /rest/recastRiskRule`: `id`, `repository`, `organization` (id), `user` (id only), `plugin`, `hostType`, `hostValue`, `port`, `protocol`, `expires` (`-1` when unset), `status`, `comments`, `createdTime` and `modifiedTime`, and on a recast rule `newSeverity` and `order`, as returned, plus `state` (`req-tenable-states-7`). A rule's `expires` is stored as returned; a consumer must compare it with the current time itself. `comments` is operator text and is stored as returned under the same stance as plugin output (`req-tenable-findings-9`). Edges: `COVERS_PLUGIN__tenable` to the plugin, `COVERS_REPOSITORY__tenable` to the repository, and, when `hostType` is `asset`, `COVERS_ASSET_LIST__tenable` to the asset list `hostValue` names (`req-tenable-asset-lists`). No edge to individual findings is written in v0, because a rule covering all hosts would fan out across the fleet; which findings a rule covers is the finding's own `accept_risk` or `recast_risk` flag.

#### Acceptance Criteria

| ACID | Title | Status | Description | Notes |
| --- | --- | --- | --- | --- |
| req-tenable-risk-rules-1 | Rules As Returned | Proposed | Rule fields are stored as returned, with the user as an id only. | |
| req-tenable-risk-rules-2 | No Finding Fan-Out | Proposed | No edge runs from a rule to a finding. | |
| req-tenable-risk-rules-3 | Never Applied By This Plugin | Proposed | No rule changes a finding's state or severity here. | Tenable already applied it. |
| req-tenable-risk-rules-4 | Asset Scope Is An Edge | Proposed | A rule whose `hostType` is `asset` links to that asset list; a rule naming an asset list not read records the edge as unwritten and counts it. | Ruled 2026-11-12 (Q53a). |

### Asset Lists
----
RID: `req-tenable-asset-lists`

Status: `Proposed`

Security Center's named host groups. Risk rules, scans and groups refer to them, so a rule scoped to an asset list needs a node to point at. Ruled 2026-11-12 (Q53a): definitions now, membership later.

#### Implementation

`tenable_asset_list` (`tenable.area: risk`), key `(instance_key, asset_id)`, from `GET /rest/asset` with pinned `fields`: `id`, `uuid`, `name`, `description`, `type` (documented: `static`, `dynamic`, `combination`, `dnsname`, `ldapquery`, `watchlist`, among others), the definition fields as returned for its type (`definedIPs`, `definedDNSNames`, `rules`, `combinations`), `tags`, `createdTime`, `modifiedTime`, and `state`. Never the LDAP query's bind credentials or any credential reference. Membership is not stored: Security Center recomputes it, so a membership edge would be a snapshot (`req-tenable-asset-list-membership`, Backlog). `COVERS_ASSET_LIST__tenable` from risk rules (`req-tenable-risk-rules-4`).

#### Acceptance Criteria

| ACID | Title | Status | Description | Notes |
| --- | --- | --- | --- | --- |
| req-tenable-asset-lists-1 | Definition As Returned | Proposed | An asset list's type and definition fields are stored as returned, with no evaluation. | |
| req-tenable-asset-lists-2 | No Membership In v0 | Proposed | No edge from an asset list to a host or address is written. | Backlog. |
| req-tenable-asset-lists-3 | No Credentials | Proposed | No asset-list field holds a bind credential or credential reference; the pinned `fields` names none. | |

### Shared Facts
----
RID: `req-tenable-shared-facts`

Status: `Proposed`

What a result establishes as fact is written to, or linked with, the shared `computing_core` node, so Tenable's data meets every other source's at the same address, port, name or interface.

#### Implementation

Built only after `computing_core` ships the natural-key form that names a dimension beside columns, and the keys below; until then this requirement is unbuilt and the rest of the plugin is not blocked by it. Those keys reference the network dimension node by its id, not its dotted name (a core ruling); this spec writes the dotted name `tap.computing.network_name` for readability. The envelope's `network_name` is a value of that dimension, and `computing_core`'s `network` node of the same name carries its ranges and description; this plugin writes no `network` node.

- `computing_core__ip_address`, key `tap.computing.network_name` plus `address`: from a result's `ip`, on the envelope's `network_name`. Loopback, wildcard and link-local addresses are refused by `computing_core` and counted on the run.
- `computing_core__port`, key the address's plus `transport` and `port_number`: from a result whose port is not `"0"`.
- `computing_core__dns_name`, key `tap.computing.network_name` plus the canonical name: from a result's `dnsName`. This type does not exist in `computing_core` yet; it and `REPORTS_DNS_NAME__tenable` arrive with this requirement's build (the fourth PR), after the `computing_core` change that adds it.
- `computing_core__network_interface`, key `tap.computing.network_name` plus `mac_address`: from a result's `macAddress`. Which results carry a MAC that belongs to the host (and not to a router between it and the scanner) is unobserved, so these edges are written only for results whose path a recording shows to be trustworthy, and until then only from `agent` repositories.

The values sent are converted as `req-tenable-response-contract` states (integer `port_number`, lower-case `transport`, canonical address with IPv4-mapped IPv6 written as IPv4); Tenable's own node keeps the value as returned. Facts come from any result that reports them, network or on-board, because an agent's or a credentialed scan's report of its own address is as true as a network scan's. A fact node is written only with its key fields and is never rewritten when it already exists; shared nodes receive no Tenable dimension. Tenable's view of a fact is an edge from its own node (`ABOUT_PORT__tenable`, `ABOUT_ADDRESS__tenable`, `OBSERVED_AT_ADDRESS__tenable`, `OBSERVED_ON_PORT__tenable`, `REPORTS_DNS_NAME__tenable`, `REPORTS_INTERFACE__tenable`).

#### Acceptance Criteria

| ACID | Title | Status | Description | Notes |
| --- | --- | --- | --- | --- |
| req-tenable-shared-facts-1 | Network From The Envelope | Proposed | Every address, port, DNS name and interface fact carries the envelope's `network_name`. | |
| req-tenable-shared-facts-2 | Written Bare, Never Rewritten | Proposed | A fact node is created with only its key fields and an existing one is not rewritten. | |
| req-tenable-shared-facts-3 | Refusals Counted | Proposed | An address `computing_core` refuses is counted on the run and its result is still stored. | |
| req-tenable-shared-facts-4 | No Port Zero | Proposed | A result with port `"0"` yields no port fact. | Port 0 marks a host-level result. |
| req-tenable-shared-facts-5 | MAC Only When Trustworthy | Proposed | An interface edge is written only from a result path the spec lists as carrying the host's own MAC. | |
| req-tenable-shared-facts-6 | Own Dimensions On Own Nodes | Proposed | This plugin stamps its dimensions (`tenable.area`, `tenable.instance`) only on the types it owns; a test asserts no shared `computing_core` node it writes or links carries a `tenable.*` dimension. | Standing rule, ruled 2026-11-12, to be reviewed as the plugin is used. |
| req-tenable-shared-facts-7 | IPv4-Mapped Written As IPv4 | Proposed | A result reporting `::ffff:10.0.0.5` writes or links the same address node as one reporting `10.0.0.5`. | Otherwise one address is two nodes. |

### Last Seen In Run
----
RID: `req-tenable-run-links`

Status: `Proposed`

Which collector run last read each observation, kept as one edge per observation rather than one per run.

#### Implementation

`LAST_SEEN_IN_RUN__tenable`: from each finding, compliance result, observed host, observed program, repository, scan result, risk rule, scanner, scan zone, plugin family and asset list to the scan run that last read it. Each run moves the edge to itself; edge authority retires the previous one, and the grid's history keeps the earlier runs recoverable. One edge per run would grow by the number of observations every run, the supernode case. Edge authority removes edges only on runs whose reconcile authority an operator has armed (`spec-grid-reconcile`, `req-grid-reconcile-edge-authority-9`); an unarmed run only proposes the removals. The Tenable collector is therefore meant to run armed, and its documentation says so; an unarmed run records `RECONCILE_NOT_ARMED`, and its new edges accumulate beside the old ones until an armed run retires them. Ruled 2026-11-12 (Q52): "start exercising this in the field".

#### Acceptance Criteria

| ACID | Title | Status | Description | Notes |
| --- | --- | --- | --- | --- |
| req-tenable-run-links-1 | One Live Edge | Proposed | After any armed run, each observation it read has exactly one live `LAST_SEEN_IN_RUN__tenable` edge, to that run. | Unarmed runs: `-3`. |
| req-tenable-run-links-2 | Unread Keeps Its Edge | Proposed | An observation in a repository not read keeps its edge to the last run that read it. | |
| req-tenable-run-links-3 | Unarmed Runs Say So | Proposed | A run without reconcile authority records `RECONCILE_NOT_ARMED`; a two-run test shows the old edge retired after an armed run and kept, beside the new one, after an unarmed one. | `req-grid-reconcile-edge-authority-9`: a claim is not a licence. |

### The Observation Command
----
RID: `req-tenable-observe`

Status: `In Development`

An instrument for the first sessions against a real instance, and for any later one: it reads an instance through the guarded transport in a fixed order, records every raw response locally, and reports which assumptions the responses settled. It is not the collector and writes nothing to the grid. It exists so shapes are observed before they are parsed.

#### Implementation

`tap_plugin/tenable/observe.py`, run as `python -m tap_plugin.tenable.observe --list` to see the envelopes and `--key <key>` to observe one (`--dry-run` prints the plan and sends nothing). Every analysis query it sends is narrowed to the envelope's `scope.repository_ids` when that names any, and a repository outside it is listed as not read; the other scope options are not applied, and the report names any the envelope sets. It reads, through the allowlist only: the probe reads, the repository list, a first page of findings per repository, a sampled plugin's `GET /plugin/{id}`, the valid filter names (by sending a known-bad filter, which the allowlist permits as an ordinary analysis query), a ranked count of findings by plugin id so the first parsers are chosen from data, the field names (never values) returned by the host summary (`sumip`) and the service, OS and software list tools, the `hostUniqueness` lists seen per repository format, one compliance result's element names if the instance has any, whether results carry `checkType` values that distinguish remote from local checks, whether accepted results appear without an `acceptRiskStatus` filter, whether results carry `lastMitigated`, `vulnUUID` and `vulnUniqueness`, and the request shapes `req-tenable-response-contract-7` lists as disputed. By default a run saves **shapes only**: per response its status, the header names that cannot carry a credential, and the field names, types and counts, with every value of `pluginText` and of any host or asset field omitted. Saving raw bodies needs the explicit `--record-bodies` flag, because they can hold credentials the plugin output carried (`req-tenable-findings-9`); with it a response is saved as one JSON file with its body under a private directory outside any repository, the path is printed, and the report reminds the operator to delete it when done. The report prints shapes, counts and statuses, never a body, a key, or a host or asset name. Under `--record-bodies`, any value equal to a key in the envelope is replaced before the body is saved, and the replacements are counted. A step with a missing prerequisite is recorded as *not read* with the reason. The report ends with the assumptions ledger, `tap_plugin/tenable/observe_assumptions.json`, one entry per open assumption this spec names (each with the ACID that depends on it), marking each settled, contradicted or not reached by this run. Recordings are never committed; a fixture is committed only after the operator has reviewed a trimmed copy.

#### Acceptance Criteria

| ACID | Title | Status | Description | Notes |
| --- | --- | --- | --- | --- |
| req-tenable-observe-1 | Only The Allowlist | In Development | Every request passes the transport's allowlist; a path outside it is refused before any request. | |
| req-tenable-observe-2 | Local And Private | In Development | Recordings are written outside any repository, judged on the resolved path and never through a symbolic link, with owner-only permissions, and nothing is written to the grid. | The repository is public. |
| req-tenable-observe-3 | Nothing Sensitive Printed; Shapes By Default | In Development | The report and recordings contain no key in any form, and the report contains no body, hostname, IP or asset name; text from an instance is stripped of non-printable characters and bounded before printing. Without `--record-bodies`, nothing saved holds a `pluginText` value or a host or asset name. | |
| req-tenable-observe-4 | Not Read Is Recorded | In Development | A step that cannot run is recorded as not read with the reason, never as empty. | |
| req-tenable-observe-5 | Dry Run Sends Nothing | In Development | `--dry-run` and `--list` send no request. | |
| req-tenable-observe-6 | Ranks Plugins For Parsers | In Development | The report ranks plugin ids by finding count so parsers are written for what the instance actually returns. | |
| req-tenable-observe-7 | Raw Bodies Are Opt-In | In Development | Raw bodies are saved only under `--record-bodies`, in an owner-only directory the command refuses to create inside a repository, with the path printed and a deletion reminder; a fixture is committed only from a trimmed copy the operator has reviewed. | Raw plugin output can carry credentials. |
| req-tenable-observe-8 | Echoed Keys Replaced | In Development | Under `--record-bodies`, a response echoing either key has it replaced before saving, and the report counts replacements; a test feeds an echoing fixture. | Anchore's `observe-3`. |
| req-tenable-observe-9 | Every Operation Accounted For | In Development | The report lists every allowlisted operation as read or not read with the reason; a test fails when the allowlist gains an operation the command does not account for. | Anchore's `observe-6`. |
| req-tenable-observe-10 | Assumptions Ledger | In Development | The ledger file lists every open assumption with its dependent ACID, and the report marks each settled, contradicted or not reached. | Makes "observed" checkable. |

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
- **No Tenable users, groups, roles or scan definitions as nodes.** Users and groups hold personal data (names, contact details, and a group's asset reach, which the run records only as an id); scan results, scanners and zones are nodes (`req-tenable-scan-result`, `req-tenable-scanners-zones`) because they record what Tenable did and with what.
- **Deliberately not read:** credentials (`/credential`; even with secrets masked they carry account names and vault settings), tickets (deprecated in Security Center 6.9), report definitions and reports (`encryptionPassword` field, and their content derives from results already read), scan policies and audit files as configuration, alerts, and the Director (`/mgmt/*`) and Enclave Security (`/tes/*`) APIs, whose deployments the probe refuses (`req-tenable-probe-7`).
- **One organisation per console in v0.** A second organisation's credential on the same console is `req-tenable-multi-org`.
- **Tenable's console-wide host store (`/rest/hosts`) is not read in v0** (ruled 2026-11-12, Q53b): it holds one record per machine across the console, while an observed host is per repository, and whether its UUID equals the analysis `hostUUID` is undocumented; its exposure scores already arrive on each finding. Revisited when a recording shows the UUID relation (`req-tenable-host-assets`, Backlog).
- **No event (LCE), mobile, user or web-application data**, and none of the summary tools that only aggregate results by plugin, severity or CVE, which can be derived from the results on the grid.
- **No cross-source reconciliation.** Linking Tenable's observations to other sources' nodes is `req-tenable-reconciler`.
- **The `dcom` axis is not adopted in v0.** No type is stamped and the plugin does not depend on `dcom`; sibling collectors do not either. Adopting it later is a manifest dependency and a stamping change, and it is the operator's call, not this plugin's default.
- **Backlog, not non-goals:** finding-level CVE narrowing (conditional on a recording showing a need), host software enumeration, product and version parsers, per-scan `.nessus` enrichment, cross-source reconciliation, the cloud transport, named scopes, a vendor drift check, asset-list membership and several organisations per console.

#### Acceptance Criteria

| ACID | Title | Status | Description | Notes |
| --- | --- | --- | --- | --- |
| req-tenable-nongoals-1 | No Write Path Exists | Proposed | A test asserts that no allowlist entry sends a mutating operation. | |
| req-tenable-nongoals-2 | No Page Ships | Proposed | The manifest declares no page or panel type. | |

## Model catalog

Design-time. Superseded by the manifest when the owning requirement is `Implemented`.

| Model | Entity type | Category | Rationale |
| --- | --- | --- | --- |
| Tenable Security Center | `tenable__tenable_security_center` | run | One per console, keyed by its canonical root; the reported version and `network_name` are facts on it, not in its key. |
| Tenable Scanner | `tenable__tenable_scanner` | run | A scan engine the console manages, active or passive; inventory, read optionally. |
| Tenable Scan Zone | `tenable__tenable_scan_zone` | run | A group of scanners and the ranges they cover. |
| Tenable Scan Run | `tenable__tenable_scan_run` | run | Keyed `(instance_key, run_id)`, the id minted once per run, so every edge in the run's batch resolves to one node. |
| Tenable Plugin | `tenable__tenable_plugin` | plugin | Its own node, because many findings share one plugin and the plugin changes on its own schedule. |
| Tenable Plugin Family | `tenable__tenable_plugin_family` | plugin | Many plugins share one; rules and policies name it. |
| Tenable Finding | `tenable__tenable_finding` | finding | One per non-audit plugin result; a package is never copied from here into a shared record. |
| Tenable Compliance Result | `tenable__tenable_compliance_result` | finding | One per audit check result; its `cm:` elements are columns. |
| Tenable Repository | `tenable__tenable_repository` | run | The unit of reading and resolution; its data format marks agent data. |
| Tenable Scan Result | `tenable__tenable_scan_result` | run | A scan Tenable ran, not a scan definition. |
| Tenable Observed Host | `tenable__tenable_observed_host` | observation | A host as Tenable tracks it, keyed by the record's host-uniqueness fields; never a `computing_core` host. |
| Tenable Observed Program | `tenable__tenable_observed_program` | observation | A service Tenable detected on a host's port; never a `computing_core` program. |
| Tenable Accept Risk Rule | `tenable__tenable_accept_risk_rule` | risk | Tenable's accepted-risk statement. |
| Tenable Recast Risk Rule | `tenable__tenable_recast_risk_rule` | risk | Tenable's severity-recast statement. |
| Tenable Asset List | `tenable__tenable_asset_list` | risk | A named host group and its definition; membership is backlog. |

## Edge types

Design-time. Superseded by the manifest when the owning requirement is `Implemented`.

| Edge | From → To | Properties | Rationale |
| --- | --- | --- | --- |
| `RUN_OF_SECURITY_CENTER__tenable` | scan run → Security Center | none | Which console a run read. |
| `MANAGED_BY_SECURITY_CENTER__tenable` | scanner → Security Center | none | Which console manages an engine. |
| `IN_SCAN_ZONE__tenable` | scanner → scan zone | none | A scanner's zone memberships. |
| `RUN_BY_SCANNER__tenable` | scan result → scanner | none | The engines that ran a scan, from its detail record. |
| `IN_PLUGIN_FAMILY__tenable` | plugin → plugin family | none | A plugin's family. |
| `COVERS_ASSET_LIST__tenable` | accept-risk rule, recast-risk rule → asset list | none | A rule scoped to an asset list. |
| `ABOUT_PLUGIN__tenable` | finding, compliance result → plugin | none | The plugin behind a finding, and the finding's route to its CVEs. A plugin reaches its Security Center through its key, so no plugin-to-console edge in v0. |
| `ABOUT_VULNERABILITY__tenable` | plugin → `compliance_core__compliance_vulnerability` | none | From the plugin, not the finding, so edges scale with plugins and not hosts. Written only against an existing node; vocabulary dependency. |
| `FOUND_IN_PACKAGE__tenable` | finding → `computing_core__package` | none | Written only when a parser's result is unambiguous; vocabulary dependency. |
| `ABOUT_HOST__tenable` | finding, compliance result → observed host | none | The host a result concerns. |
| `ABOUT_PORT__tenable` | finding → `computing_core__port` | none | When the result names a port other than `"0"`. |
| `ABOUT_ADDRESS__tenable` | finding → `computing_core__ip_address` | none | When the result names an IP and no port. |
| `HELD_BY_SECURITY_CENTER__tenable` | repository → Security Center | none | Which console holds a repository. |
| `RESULT_OF_SECURITY_CENTER__tenable` | scan result → Security Center | none | Which console ran a scan. |
| `IMPORTED_INTO_REPOSITORY__tenable` | scan result → repository | none | Where a scan's results went. |
| `RECORDED_IN_REPOSITORY__tenable` | observed host → repository | none | Where Tenable records the host. |
| `OBSERVED_AT_ADDRESS__tenable` | observed host → `computing_core__ip_address` | none | Tenable owns it and retires it when the host moves. |
| `REPORTS_DNS_NAME__tenable` | observed host → `computing_core__dns_name` | none | The name Tenable reports for the host. Pending: the target type does not exist yet; built with `req-tenable-shared-facts`. |
| `REPORTS_INTERFACE__tenable` | observed host → `computing_core__network_interface` | none | Only from result paths whose MAC belongs to the host. |
| `HOSTS_PROGRAM__tenable` | observed host → observed program | none | The services Tenable detected on the host. |
| `OBSERVED_ON_PORT__tenable` | observed program → `computing_core__port` | none | The socket the service was seen on. |
| `COVERS_PLUGIN__tenable` | accept-risk rule, recast-risk rule → plugin | none | The plugin a rule applies to. |
| `COVERS_REPOSITORY__tenable` | accept-risk rule, recast-risk rule → repository | none | The repository a rule applies to. |
| `LAST_SEEN_IN_RUN__tenable` | finding, compliance result, observed host, observed program, repository, scan result, rule, scanner, scan zone, plugin family, asset list → scan run | none | One live edge per observation, moved each armed run. |
