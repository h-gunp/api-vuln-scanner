from pathlib import Path

from app.storage.base import Storage


class ObjectStorage(Storage):
    """TBD: Object storage provider and credentials contract pending."""

    async def write_atomic(self, relative_path: Path, content: bytes) -> Path:
        raise NotImplementedError("Object storage is not configured")

    async def read(self, relative_path: Path) -> bytes:
        raise NotImplementedError("Object storage is not configured")

    async def exists(self, relative_path: Path) -> bool:
        raise NotImplementedError("Object storage is not configured")

    def absolute_path(self, relative_path: Path) -> Path:
        raise NotImplementedError("Object storage has no local absolute path")

