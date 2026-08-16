"""Small no-follow, bounded file-reading primitives for public inputs."""

from __future__ import annotations

import os
from pathlib import Path
import stat
from typing import Self


class BoundedReadError(ValueError):
    """A file boundary was not a regular, bounded input."""

    def __init__(
        self,
        message: str,
        *,
        reason: str = "invalid",
        actual_size: int | None = None,
    ) -> None:
        super().__init__(message)
        self.reason = reason
        self.actual_size = actual_size


class ConfinedReader:
    """Read descendants through a pinned root descriptor and no-follow openat calls."""

    def __init__(self, root: str | Path):
        self.root = Path(root)
        self._root_descriptor: int | None = None

    def __enter__(self) -> Self:
        if os.open not in os.supports_dir_fd:
            raise BoundedReadError("platform does not support confined component reads")
        flags = (
            os.O_RDONLY
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_BINARY", 0)
        )
        try:
            descriptor = os.open(self.root, flags)
            metadata = os.fstat(descriptor)
            if not stat.S_ISDIR(metadata.st_mode):
                os.close(descriptor)
                raise BoundedReadError("evaluation root must be a directory")
            self._root_descriptor = descriptor
            return self
        except BoundedReadError:
            raise
        except OSError as exc:
            raise BoundedReadError(f"cannot open evaluation root: {type(exc).__name__}") from exc

    def __exit__(self, *_: object) -> None:
        if self._root_descriptor is not None:
            os.close(self._root_descriptor)
            self._root_descriptor = None

    def read_bounded_bytes(
        self,
        relative: str,
        maximum_bytes: int,
        *,
        label: str,
        remaining_bytes: int | None = None,
    ) -> tuple[bytes, int]:
        """Open every path component relative to the pinned root without following links."""

        if self._root_descriptor is None:
            raise BoundedReadError("confined reader is not open")
        normalized = relative.replace("\\", "/") if os.sep == "\\" else relative
        parts = normalized.split("/")
        if not parts or any(part in {"", ".", ".."} for part in parts):
            raise BoundedReadError(f"{label} is not a safe relative file path")

        directory_descriptor = os.dup(self._root_descriptor)
        file_descriptor: int | None = None
        try:
            directory_flags = (
                os.O_RDONLY
                | getattr(os, "O_DIRECTORY", 0)
                | getattr(os, "O_NOFOLLOW", 0)
                | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_BINARY", 0)
            )
            for component in parts[:-1]:
                next_descriptor = os.open(component, directory_flags, dir_fd=directory_descriptor)
                metadata = os.fstat(next_descriptor)
                if not stat.S_ISDIR(metadata.st_mode):
                    os.close(next_descriptor)
                    raise BoundedReadError(f"{label} contains a non-directory component")
                os.close(directory_descriptor)
                directory_descriptor = next_descriptor

            file_flags = (
                os.O_RDONLY
                | getattr(os, "O_NOFOLLOW", 0)
                | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_BINARY", 0)
            )
            file_descriptor = os.open(parts[-1], file_flags, dir_fd=directory_descriptor)
            metadata = os.fstat(file_descriptor)
            if not stat.S_ISREG(metadata.st_mode):
                raise BoundedReadError(f"{label} must be a regular file")
            size = metadata.st_size
            if size > maximum_bytes:
                raise BoundedReadError(
                    f"{label} exceeds {maximum_bytes} bytes",
                    reason="file_limit",
                    actual_size=size,
                )
            if remaining_bytes is not None and size > remaining_bytes:
                raise BoundedReadError(
                    f"{label} exceeds the remaining total-byte budget",
                    reason="total_limit",
                    actual_size=size,
                )
            with os.fdopen(file_descriptor, "rb", closefd=True) as stream:
                file_descriptor = None
                content = stream.read(maximum_bytes + 1)
            if len(content) > maximum_bytes:
                raise BoundedReadError(
                    f"{label} exceeds {maximum_bytes} bytes",
                    reason="file_limit",
                    actual_size=max(size, len(content)),
                )
            if remaining_bytes is not None and len(content) > remaining_bytes:
                raise BoundedReadError(
                    f"{label} exceeds the remaining total-byte budget",
                    reason="total_limit",
                    actual_size=max(size, len(content)),
                )
            return content, size
        except BoundedReadError:
            raise
        except OSError as exc:
            raise BoundedReadError(f"cannot read {label}: {type(exc).__name__}") from exc
        finally:
            if file_descriptor is not None:
                os.close(file_descriptor)
            os.close(directory_descriptor)


def read_bounded_bytes(path: str | Path, maximum_bytes: int, *, label: str) -> bytes:
    """Read at most ``maximum_bytes`` from a regular file without following a final symlink."""

    target = Path(path)
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor: int | None = None
    try:
        descriptor = os.open(target, flags)
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise BoundedReadError(f"{label} must be a regular file")
        if metadata.st_size > maximum_bytes:
            raise BoundedReadError(f"{label} exceeds {maximum_bytes} bytes")
        with os.fdopen(descriptor, "rb", closefd=True) as stream:
            descriptor = None
            content = stream.read(maximum_bytes + 1)
        if len(content) > maximum_bytes:
            raise BoundedReadError(f"{label} exceeds {maximum_bytes} bytes")
        return content
    except BoundedReadError:
        raise
    except OSError as exc:
        raise BoundedReadError(f"cannot read {label}: {type(exc).__name__}") from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)


def read_bounded_text(path: str | Path, maximum_bytes: int, *, label: str) -> str:
    try:
        return read_bounded_bytes(path, maximum_bytes, label=label).decode("utf-8")
    except UnicodeDecodeError as exc:
        raise BoundedReadError(f"{label} must be UTF-8") from exc
