"""TAP Tenable plugin: Tenable Security Center findings, as Tenable returns them, on the grid.

Spec: specs/spec-tenable-v0.md. A read-only collector over Security Center's REST API; Tenable-owned
nodes hold Tenable's fields unchanged, and per-plugin parsers extract the package information a
finding's plugin output carries.
"""
