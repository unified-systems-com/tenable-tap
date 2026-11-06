# tenable-tap

TAP plugin that reads vulnerability findings from Tenable Security Center (on-prem first) and holds them on
the grid as Tenable returns them, with the plugin metadata behind each finding and, per plugin, whatever
package information its output carries.

**Status: scaffold, spec-derived and not yet run against a real Security Center.** The package skeleton,
manifest, `ci` boot record and CI exist. No node, edge, collector or parser is built yet, and nothing has
been observed against an instance: every field and behaviour in the spec is documented or designed, not
observed, and no requirement reaches `Implemented` before a recorded response replaces its assumptions.

## What it owns, and will own

- A read-only collector for Security Center's REST API, using pyTenable behind a guarded transport that
  permits an enumerated list of operations and never mutates Tenable (`req-tenable-transport`).
- Tenable-owned nodes (scanner, scan run, plugin, finding) holding Tenable's fields unchanged, linked to
  `compliance_core`'s vulnerability and `computing_core`'s package only where the link is exact.
- A per-plugin parser directory that extracts package information from a finding's plugin output
  (`req-tenable-parsers`), so which plugins can be read is an explicit, countable list.
- Scope filters, recorded on every run, that never turn "filtered out" into "fixed" (`req-tenable-scope`).

## What lives elsewhere

- Mapping Tenable status onto VDR factors: the VDR plugins.
- Reading Tenable beside other scanners (severity scales, house mappings): a later layer. This plugin writes
  nothing to `compliance_core`.
- Host software enumeration, host and address enrichment, and the Tenable VM (cloud) transport: Backlog
  requirements in the spec.
- Pages and panels: none in v0.

## Read first

`specs/spec-tenable-v0.md`: identity, philosophy, every requirement with acceptance criteria, and the
design-time model and edge catalog.

## Standing it up

Plugins are developed against a TAP session:
`spawn-session.sh <label> --from 'git+https://github.com/unified-systems-com/tenable-tap@<rev>#ci' --dev-plugins tenable`.
Inside the session's `web` container, validate with
`/app/.venv/bin/python -m tap_plugins.validate_plugin /app/_dev-plugins/tenable --repo --strict`.
