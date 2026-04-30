"""
Vexor Plugin Manager
"""
import importlib
import importlib.util
import sys
from pathlib import Path
from typing import Optional
from vexor.config import PLUGINS_DIR
from vexor.plugins.base import VexorPlugin


class PluginManager:
    """Manages Vexor plugins"""

    def __init__(self):
        self._plugins: dict[str, VexorPlugin] = {}
        self._load_builtin_plugins()
        self._load_user_plugins()

    def _load_builtin_plugins(self) -> None:
        """Load built-in plugins"""
        pass  # Add built-in plugins here

    def _load_user_plugins(self) -> None:
        """Load user plugins from ~/.vexor/plugins/"""
        if not PLUGINS_DIR.exists():
            return

        for plugin_file in PLUGINS_DIR.glob("*.py"):
            try:
                spec = importlib.util.spec_from_file_location(
                    plugin_file.stem, plugin_file
                )
                module = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(module)

                # Find plugin class
                for attr_name in dir(module):
                    attr = getattr(module, attr_name)
                    if (isinstance(attr, type) and
                            issubclass(attr, VexorPlugin) and
                            attr is not VexorPlugin):
                        plugin = attr()
                        self._plugins[plugin.NAME] = plugin
            except Exception as e:
                print(f"Failed to load plugin {plugin_file.name}: {e}")

    def list_plugins(self) -> list[dict]:
        return [p.info() for p in self._plugins.values()]

    def get_plugin(self, name: str) -> Optional[VexorPlugin]:
        return self._plugins.get(name)

    async def run_plugin(self, name: str, target: str, **kwargs) -> list[dict]:
        plugin = self.get_plugin(name)
        if not plugin:
            return []
        return await plugin.run(target, **kwargs)
