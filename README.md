# tenable-tap

TAP plugin that reads Tenable Security Center (on-prem first) and holds what it knows on the grid as Tenable
returns it: every plugin result (vulnerability, informational and configuration audit), the plugins and
families behind them, the hosts and services Tenable observed, its consoles, scanners, zones, repositories,
scans, asset lists and risk rules, and per plugin whatever package information its output carries.

**Status: node and edge types built; no collector yet; nothing run against a real Security Center.** The
15 Tenable-owned node types and 23 edge types exist, with their migration and tests. No collector, parser or
transport is built, and nothing has been observed against an instance: every field and behaviour in the spec
is documented or designed, not observed, and no requirement reaches `Implemented` before a recorded response
replaces its assumptions.

## What it owns, and will own

- Tenable-owned nodes holding Tenable's fields unchanged: the Security Center console, its scanners and scan
  zones, scan runs, repositories, scan results, plugins and plugin families, findings and compliance results,
  observed hosts and programs, accept-risk and recast-risk rules, and asset lists. Linked to
  `compliance_core`'s vulnerability and `computing_core`'s package, address, port and interface only where
  the link is exact.
- A read-only collector for Security Center's REST API, using pyTenable behind a guarded transport that
  permits an enumerated list of operations, pins the fields of every read, and never mutates Tenable
  (`req-tenable-transport`). It is meant to run with reconcile authority armed (`req-tenable-run-links`).
- A per-plugin parser directory that extracts package information from a result's plugin output
  (`req-tenable-parsers`), so which plugins can be read is an explicit, countable list.
- Scope filters, recorded on every run, that never turn "filtered out", "aged out" or "not visible to this
  credential" into "fixed" (`req-tenable-scope`, `req-tenable-states`).

## What lives elsewhere

- Mapping Tenable status onto VDR factors: the VDR plugins.
- Reading Tenable beside other scanners (severity scales, house mappings): a later layer. This plugin writes
  nothing to `compliance_core`.
- Joining Tenable's observed hosts to other sources' hosts: the reconciler (Backlog).
- Asset-list membership, Tenable's console-wide host store, per-scan `.nessus` enrichment and the Tenable VM
  (cloud) transport: Backlog requirements in the spec.
- Pages and panels: none in v0.

## Read first

`specs/spec-tenable-v0.md`: identity, philosophy, every requirement with acceptance criteria, and the model
and edge catalog.

## Standing it up

Plugins are developed against a TAP session:
`spawn-session.sh <label> --from 'git+https://github.com/unified-systems-com/tenable-tap@<rev>#ci' --dev-plugins tenable`,
or, before a tag carries what you need, `--boot-file <checkout>/tap_plugin/tenable/boot/ci.boot.json --dev-plugins tenable`.
Inside the session's `web` container, validate with
`/app/.venv/bin/python -m tap_plugins.validate_plugin /app/_dev-plugins/tenable --repo --strict`
and run the suite with `uv run pytest _dev-plugins/tenable/tap_plugin/tenable/tests -n0`.
