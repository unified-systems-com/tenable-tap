"""TAP Tenable plugin AppConfig.

``name`` is derived from this module's package path and ``label`` / ``verbose_name`` come
from tap-plugin.toml (slug / name); nothing is authored here (req-tap-plugin-manifest-v0-scaffold).
The collector registers in ``ready()`` once it exists (req-tenable-transport).
"""

from tap_plugins.base import TapPluginConfig


class TenableConfig(TapPluginConfig):
    pass
