from abc import ABC, abstractmethod
from pathlib import Path


class Storage(ABC):
    @abstractmethod
    async def write_atomic(self, relative_path: Path, content: bytes) -> Path:
        raise NotImplementedError

    @abstractmethod
    async def read(self, relative_path: Path) -> bytes:
        raise NotImplementedError

    @abstractmethod
    async def exists(self, relative_path: Path) -> bool:
        raise NotImplementedError

    @abstractmethod
    def absolute_path(self, relative_path: Path) -> Path:
        raise NotImplementedError

