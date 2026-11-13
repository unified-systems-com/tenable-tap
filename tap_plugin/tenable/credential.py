"""The Tenable credential envelopes: validation, instance identity, discovery (req-tenable-connection).

Each Security Center instance has one main envelope (scope ``tenable``, kind ``tenable_sc_credential``)
and, optionally, one administrator envelope (kind ``tenable_sc_admin_credential``) used only for
the inventory reads. This module is the consumer-side check the secrets spec leaves to the consumer
(``req-tap-cares-secrets-validation``). It validates ``data`` against the plugin's own schemas,
derives the instance key and finds every envelope in the scope.

It imports no Django and no ``tap_*`` app beyond core's settings-free ``tap.runtime_secrets``, so
the observation command can run from a bare checkout. The keys live only in :class:`Keys`, whose
``repr`` omits them, and no message built here contains a value.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import jsonschema
from tap.runtime_secrets import RuntimeSecretError, SecretEnvelope, load_secret_envelope
from tap.secret_naming import SECRET_EXAMPLE_SUFFIX, SECRET_SUFFIX

from tap_plugin.tenable.identity import canonical_root

SCOPE = "tenable"
KIND = "tenable_sc_credential"
ADMIN_KIND = "tenable_sc_admin_credential"
SCHEMAS = Path(__file__).resolve().parent / "schemas"
SCHEMA_PATH = SCHEMAS / f"{KIND}.schema.json"
ADMIN_SCHEMA_PATH = SCHEMAS / f"{ADMIN_KIND}.schema.json"

DEFAULT_SCAN_RESULT_WINDOW_DAYS = 30
DEFAULT_FEED_STALE_DAYS = 7

# What replaces a key found in text an instance returned. The first candidate that contains no
# form of a key is used, so a key can never survive inside its own marker.
REDACTED = "[REDACTED:credential]"
_MARKERS = (REDACTED, "[redacted]", "[#]", "#", "█", "")


class CredentialError(Exception):
    """An envelope cannot be used. The message names ``tenable:<key>`` and a reason, never a value."""

    def __init__(self, qualified: str, reason: str) -> None:
        super().__init__(f"{qualified}: {reason}")
        self.qualified = qualified
        self.reason = reason


@dataclass(frozen=True)
class Keys:
    """A Security Center API key pair. ``repr`` shows neither key."""

    _access: str = field(repr=False)
    _secret: str = field(repr=False)

    def __repr__(self) -> str:
        return "Keys(<redacted>)"

    @property
    def header(self) -> str:
        """The X-APIKey header value Security Center reads (5.13 and later)."""
        return f"accessKey={self._access}; secretKey={self._secret}"

    @property
    def access_key(self) -> str:
        return self._access

    @property
    def secret_key(self) -> str:
        return self._secret

    def _forms(self) -> tuple[str, ...]:
        """Every form a key is sent in, longest first, so a redaction takes the whole form."""
        forms = {self._access, self._secret, self.header}
        return tuple(sorted((f for f in forms if f), key=len, reverse=True))

    def _marker(self) -> str:
        forms = self._forms()
        return next((m for m in _MARKERS if not any(f in m for f in forms)), "")

    def redact(self, text: str) -> tuple[str, int]:
        """Replace every form of either key in ``text``; returns the text and how many were replaced."""
        marker, count = self._marker(), 0
        for form in self._forms():
            count += text.count(form)
            text = text.replace(form, marker)
        return text, count

    def redact_bytes(self, data: bytes) -> tuple[bytes, int]:
        marker, count = self._marker().encode("utf-8"), 0
        for form in (f.encode("utf-8") for f in self._forms()):
            count += data.count(form)
            data = data.replace(form, marker)
        return data, count


@dataclass(frozen=True)
class AdminCredential:
    """A validated administrator envelope, for the inventory reads only (req-tenable-connection-11)."""

    qualified: str
    instance_key: str
    for_key: str
    ssl_verify: bool
    ca_bundle: str | None
    keys: Keys = field(repr=False)

    @property
    def verify(self) -> bool | str:
        """What ``requests`` is given for certificate verification."""
        return (self.ca_bundle or True) if self.ssl_verify else False

    def __repr__(self) -> str:
        return f"AdminCredential(qualified={self.qualified!r}, instance_key={self.instance_key!r})"


@dataclass(frozen=True)
class Credential:
    """One validated Security Center instance: where it is, how to reach it and what to read."""

    qualified: str
    key: str
    instance_key: str
    ssl_verify: bool
    ca_bundle: str | None
    network_name: str
    scope: dict[str, Any]
    scan_result_window_days: int
    feed_stale_days: int
    keys: Keys = field(repr=False)
    admin: AdminCredential | None = None

    @property
    def plaintext(self) -> bool:
        """Whether this instance is read over plain http (req-tenable-connection-9)."""
        return self.instance_key.startswith("http://")

    @property
    def verify(self) -> bool | str:
        """What ``requests`` is given for certificate verification."""
        return (self.ca_bundle or True) if self.ssl_verify else False

    def warnings(self) -> list[str]:
        """The run warnings this envelope's settings imply, before any request."""
        out = []
        if self.plaintext:
            out.append("PLAINTEXT_TRANSPORT")
        if not self.ssl_verify or (self.admin is not None and not self.admin.ssl_verify):
            out.append("TLS_VERIFICATION_DISABLED")
        return out

    def redact(self, text: str) -> tuple[str, int]:
        """Redact both envelopes' keys from ``text``."""
        text, count = self.keys.redact(text)
        if self.admin is not None:
            text, more = self.admin.keys.redact(text)
            count += more
        return text, count

    def redact_bytes(self, data: bytes) -> tuple[bytes, int]:
        data, count = self.keys.redact_bytes(data)
        if self.admin is not None:
            data, more = self.admin.keys.redact_bytes(data)
            count += more
        return data, count

    def with_admin(self, admin: AdminCredential | None) -> Credential:
        return Credential(
            qualified=self.qualified,
            key=self.key,
            instance_key=self.instance_key,
            ssl_verify=self.ssl_verify,
            ca_bundle=self.ca_bundle,
            network_name=self.network_name,
            scope=self.scope,
            scan_result_window_days=self.scan_result_window_days,
            feed_stale_days=self.feed_stale_days,
            keys=self.keys,
            admin=admin,
        )

    def __repr__(self) -> str:
        return f"Credential(qualified={self.qualified!r}, instance_key={self.instance_key!r}, admin={self.admin is not None})"


def _schema(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _schema_reason(kind: str, exc: jsonschema.ValidationError) -> str:
    """Where the data failed the schema, without the offending value."""
    where = "/".join(str(p) for p in exc.absolute_path) or "(data)"
    return f"data does not match the {kind} schema at {where} ({exc.validator})"


def _validated(envelope: SecretEnvelope, kind: str, schema_path: Path) -> tuple[dict[str, Any], str]:
    """Check scope, kind and schema, and derive the instance key; returns the data and the key."""
    qualified = envelope.qualified
    if envelope.scope != SCOPE:
        raise CredentialError(qualified, f"scope is {envelope.scope!r}, expected {SCOPE!r}")
    if envelope.kind != kind:
        raise CredentialError(qualified, f"kind is {envelope.kind!r}, expected {kind!r}")
    data = dict(envelope.data)
    try:
        jsonschema.validate(data, _schema(schema_path))
    except jsonschema.ValidationError as exc:
        raise CredentialError(qualified, _schema_reason(kind, exc)) from None
    try:
        instance_key = canonical_root(data["base_url"])
    except ValueError as exc:
        raise CredentialError(qualified, str(exc)) from None
    return data, instance_key


def credential_from_envelope(envelope: SecretEnvelope) -> Credential:
    """Validate one main envelope and build its :class:`Credential`.

    Raises CredentialError naming ``tenable:<key>`` and a reason. The reason never contains a value.
    """
    data, instance_key = _validated(envelope, KIND, SCHEMA_PATH)
    return Credential(
        qualified=envelope.qualified,
        key=envelope.key,
        instance_key=instance_key,
        ssl_verify=data.get("ssl_verify", True),
        ca_bundle=data.get("ca_bundle"),
        network_name=data["network_name"],
        scope=dict(data.get("scope", {})),
        scan_result_window_days=data.get("scan_result_window_days", DEFAULT_SCAN_RESULT_WINDOW_DAYS),
        feed_stale_days=data.get("feed_stale_days", DEFAULT_FEED_STALE_DAYS),
        keys=Keys(data["access_key"], data["secret_key"]),
    )


def admin_from_envelope(envelope: SecretEnvelope) -> AdminCredential:
    """Validate one administrator envelope and build its :class:`AdminCredential`."""
    data, instance_key = _validated(envelope, ADMIN_KIND, ADMIN_SCHEMA_PATH)
    return AdminCredential(
        qualified=envelope.qualified,
        instance_key=instance_key,
        for_key=data["for_key"],
        ssl_verify=data.get("ssl_verify", True),
        ca_bundle=data.get("ca_bundle"),
        keys=Keys(data["access_key"], data["secret_key"]),
    )


def _pair(main: list[Credential], admins: list[AdminCredential], errors: list[CredentialError]) -> list[Credential]:
    """Attach each administrator envelope to the main envelope it names; refuse what does not fit."""
    by_key = {c.key: c for c in main}
    claimed: dict[str, list[AdminCredential]] = {}
    for admin in admins:
        target = by_key.get(admin.for_key)
        if target is None:
            errors.append(CredentialError(admin.qualified, f"for_key names {SCOPE}:{admin.for_key}, which is not a usable {KIND} envelope"))
        elif admin.instance_key != target.instance_key:
            errors.append(CredentialError(admin.qualified, f"resolves to a different instance from {target.qualified}"))
        else:
            claimed.setdefault(admin.for_key, []).append(admin)
    out = []
    for credential in main:
        candidates = claimed.get(credential.key, [])
        if len(candidates) > 1:
            names = " and ".join(a.qualified for a in candidates)
            errors.extend(CredentialError(a.qualified, f"more than one administrator envelope serves {credential.qualified} ({names})") for a in candidates)
            out.append(credential)
        else:
            out.append(credential.with_admin(candidates[0] if candidates else None))
    return out


def discover(root: Path) -> tuple[list[Credential], list[CredentialError]]:
    """Every usable instance in scope ``tenable`` under ``root``, and every envelope that is not usable.

    A malformed envelope fails only itself. Two main envelopes that resolve to the same instance key
    are both refused, naming both (req-tenable-connection-6). An administrator envelope is attached
    to the main envelope its ``for_key`` names, and is refused when it resolves to another instance
    (req-tenable-connection-11). Example templates (``*.secret.example.json``) are never read.
    """
    main: list[Credential] = []
    admins: list[AdminCredential] = []
    errors: list[CredentialError] = []
    if not root.is_dir():
        return main, [CredentialError(SCOPE, f"secrets root {root} is not a directory")]
    for path in sorted(root.rglob(f"*{SECRET_SUFFIX}")):
        if path.name.endswith(SECRET_EXAMPLE_SUFFIX):
            continue
        try:
            envelope = load_secret_envelope(path)
        except RuntimeSecretError:
            # A file we cannot read as an envelope may or may not be ours; report it by name only.
            errors.append(CredentialError(f"{SCOPE}:{path.name[: -len(SECRET_SUFFIX)]}", "file is not a readable secret envelope"))
            continue
        if envelope.scope != SCOPE:
            continue
        try:
            if envelope.kind == ADMIN_KIND:
                admins.append(admin_from_envelope(envelope))
            else:
                main.append(credential_from_envelope(envelope))
        except CredentialError as exc:
            errors.append(exc)
    by_instance: dict[str, list[Credential]] = {}
    for credential in main:
        by_instance.setdefault(credential.instance_key, []).append(credential)
    kept: list[Credential] = []
    for credentials in by_instance.values():
        if len(credentials) == 1:
            kept.append(credentials[0])
            continue
        names = " and ".join(c.qualified for c in credentials)
        errors.extend(CredentialError(c.qualified, f"same instance as the other envelopes ({names})") for c in credentials)
    return _pair(kept, admins, errors), errors
