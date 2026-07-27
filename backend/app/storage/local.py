import asyncio
import os
import tempfile
from pathlib import Path

from app.storage.base import Storage


class LocalStorage(Storage):
    def __init__(self, root: Path) -> None:
        self.root = root.resolve()

    def _resolve_safe(self, relative_path: Path) -> Path:
        if relative_path.is_absolute():
            raise ValueError("Storage path must be relative")
        resolved = (self.root / relative_path).resolve()
        if self.root not in resolved.parents and resolved != self.root:
            raise ValueError("Storage path escapes configured root")
        return resolved

    async def write_atomic(self, relative_path: Path, content: bytes) -> Path:
        destination = self._resolve_safe(relative_path)
        await asyncio.to_thread(self._write_atomic_sync, destination, content)
        return destination

    @staticmethod
    def _write_atomic_sync(destination: Path, content: bytes) -> None:
        destination.parent.mkdir(parents=True, exist_ok=True)
        temporary_name: str | None = None
        try:
            with tempfile.NamedTemporaryFile(
                mode="wb",
                dir=destination.parent,
                prefix=f".{destination.name}.",
                suffix=".tmp",
                delete=False,
            ) as temporary:
                temporary.write(content)
                temporary.flush()
                os.fsync(temporary.fileno())
                temporary_name = temporary.name
            os.replace(temporary_name, destination)
        finally:
            if temporary_name and os.path.exists(temporary_name):
                os.unlink(temporary_name)

    async def read(self, relative_path: Path) -> bytes:
        return await asyncio.to_thread(self._resolve_safe(relative_path).read_bytes)

    async def exists(self, relative_path: Path) -> bool:
        return await asyncio.to_thread(self._resolve_safe(relative_path).is_file)

    def absolute_path(self, relative_path: Path) -> Path:
        return self._resolve_safe(relative_path)

