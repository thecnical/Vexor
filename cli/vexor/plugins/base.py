"""
Vexor Plugin Base Class
"""
from abc import ABC, abstractmethod
from typing import Optional


class VexorPlugin(ABC):
    """Base class for all Vexor plugins"""

    NAME = "base_plugin"
    VERSION = "1.0.0"
    DESCRIPTION = "Base plugin"
    AUTHOR = ""

    @abstractmethod
    async def run(self, target: str, **kwargs) -> list[dict]:
        """Run the plugin — returns list of findings"""
        pass

    def info(self) -> dict:
        return {
            "name": self.NAME,
            "version": self.VERSION,
            "description": self.DESCRIPTION,
            "author": self.AUTHOR,
        }
