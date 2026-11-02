"""Path grammar, root confinement and safe file reading."""

from __future__ import annotations

import os
import stat
from typing import List, Tuple


class PathError(Exception):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code
        self.message = message


def validate_path_grammar(p: str) -> None:
    if not isinstance(p, str) or not p:
        raise PathError("pap.package.path-invalid", "empty path")
    if p.startswith("/") or p.endswith("/"):
        raise PathError("pap.package.path-invalid", "invalid path boundaries")
    segments = p.split("/")
    if any(s == "" for s in segments):
        raise PathError("pap.package.path-invalid", "empty segment")
    if len(segments) > 16:
        raise PathError("pap.package.path-invalid", "too many segments")
    if len(p.encode("utf-8")) > 255:
        raise PathError("pap.package.path-invalid", "path too long")
    for seg in segments:
        if seg in (".", ".."):
            raise PathError("pap.package.path-invalid", "dot segment")
        if len(seg.encode("utf-8")) > 255:
            raise PathError("pap.package.path-invalid", "segment too long")
        if not all(c.isascii() and (c.isalnum() or c in "._-") for c in seg):
            raise PathError("pap.package.path-invalid", "invalid path characters")


def case_fold_key(p: str) -> str:
    return p.casefold()


def open_root(root_path: str) -> int:
    try:
        fd = os.open(root_path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except FileNotFoundError as exc:
        raise PathError("pap.package.not-found", f"package root not found: {exc}") from exc
    except NotADirectoryError as exc:
        raise PathError("pap.package.non-regular", f"package root is not a directory: {exc}") from exc
    except PermissionError as exc:
        raise PathError("pap.package.io", f"permission denied opening root: {exc}") from exc
    except OSError as exc:
        if exc.errno in (20,):
            raise PathError("pap.package.non-regular", f"package root is not a directory: {exc}") from exc
        raise PathError("pap.package.io", f"cannot open package root: {exc}") from exc
    try:
        st = os.fstat(fd)
    except OSError as exc:
        os.close(fd)
        raise PathError("pap.package.io", f"cannot stat package root: {exc}") from exc
    if not stat.S_ISDIR(st.st_mode):
        os.close(fd)
        if stat.S_ISLNK(st.st_mode):
            raise PathError("pap.package.symlink", "package root is a symlink")
        raise PathError("pap.package.non-regular", "package root is not a regular directory")
    return fd


def open_relative(root_fd: int, rel_path: str) -> int:
    validate_path_grammar(rel_path)
    segments = rel_path.split("/")
    cur_fd = root_fd
    opened_fds: List[int] = []
    try:
        for i, seg in enumerate(segments):
            flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC
            if i < len(segments) - 1:
                flags |= os.O_DIRECTORY
            try:
                fd = os.open(seg, flags, dir_fd=cur_fd)
            except FileNotFoundError as exc:
                raise PathError("pap.package.declared-file-missing", f"missing path component {seg!r}: {exc}") from exc
            except NotADirectoryError as exc:
                raise PathError("pap.package.non-regular", f"not a directory: {seg!r}: {exc}") from exc
            except PermissionError as exc:
                raise PathError("pap.package.io", f"permission denied: {seg!r}: {exc}") from exc
            except OSError as exc:
                if exc.errno == 40:
                    raise PathError("pap.package.symlink", f"symlink encountered: {seg!r}: {exc}") from exc
                raise PathError("pap.package.io", f"cannot open {seg!r}: {exc}") from exc
            opened_fds.append(fd)
            st = os.fstat(fd)
            if i < len(segments) - 1:
                if stat.S_ISLNK(st.st_mode):
                    raise PathError("pap.package.symlink", f"symlink directory: {seg!r}")
                if not stat.S_ISDIR(st.st_mode):
                    raise PathError("pap.package.non-regular", f"not a directory: {seg!r}")
            else:
                if stat.S_ISLNK(st.st_mode):
                    raise PathError("pap.package.symlink", f"symlink file: {seg!r}")
                if not stat.S_ISREG(st.st_mode):
                    raise PathError("pap.package.non-regular", f"not a regular file: {seg!r}")
            cur_fd = fd
        final_fd = opened_fds[-1]
        opened_fds.pop()
        return final_fd
    finally:
        for fd in opened_fds:
            try:
                os.close(fd)
            except OSError:
                pass


def read_file_bounded(fd: int, per_file_limit: int, total_counter: list[int], total_limit: int) -> bytes:
    st = os.fstat(fd)
    if stat.S_ISLNK(st.st_mode):
        raise PathError("pap.package.symlink", "file is a symlink")
    if not stat.S_ISREG(st.st_mode):
        raise PathError("pap.package.non-regular", "not a regular file")
    chunks = []
    read_total = 0
    while True:
        remaining_file = per_file_limit - read_total
        remaining_total = total_limit - total_counter[0]
        if remaining_file <= 0:
            try:
                probe = os.read(fd, 1)
            except OSError as exc:
                raise PathError("pap.package.io", f"read error: {exc}") from exc
            if probe == b"":
                break
            raise PathError("pap.package.limit-exceeded", "per-file limit exceeded")
        if remaining_total <= 0:
            try:
                probe = os.read(fd, 1)
            except OSError as exc:
                raise PathError("pap.package.io", f"read error: {exc}") from exc
            if probe == b"":
                break
            raise PathError("pap.package.limit-exceeded", "total payload limit exceeded")
        to_read = min(65536, remaining_file, remaining_total)
        try:
            data = os.read(fd, to_read)
        except OSError as exc:
            raise PathError("pap.package.io", f"read error: {exc}") from exc
        if not data:
            break
        chunks.append(data)
        read_total += len(data)
        total_counter[0] += len(data)
        if read_total > per_file_limit or total_counter[0] > total_limit:
            raise PathError("pap.package.limit-exceeded", "payload limit exceeded")
    return b"".join(chunks)


def scan_entries(root_fd: int, max_entries: int) -> tuple[list[tuple[str, bool]], str]:
    results: list[tuple[str, bool]] = []
    stack = [(root_fd, "", False)]
    failed = False
    truncated = False
    seen_count = 0
    try:
        while stack:
            fd, prefix, owns = stack.pop()
            try:
                it = os.scandir(fd)
            except OSError:
                failed = True
                if owns:
                    try:
                        os.close(fd)
                    except OSError:
                        pass
                continue
            try:
                for entry in it:
                    seen_count += 1
                    if seen_count <= max_entries:
                        name = entry.name
                        rel = (prefix + "/" + name) if prefix else name
                        try:
                            st = entry.stat(follow_symlinks=False)
                        except OSError:
                            failed = True
                            continue
                        is_dir = stat.S_ISDIR(st.st_mode)
                        is_file = stat.S_ISREG(st.st_mode)
                        is_link = stat.S_ISLNK(st.st_mode)
                        if is_link:
                            results.append((rel, False))
                        elif is_dir:
                            results.append((rel, True))
                            try:
                                child_fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
                                stack.append((child_fd, rel, True))
                            except OSError:
                                failed = True
                        elif is_file:
                            results.append((rel, False))
                    else:
                        truncated = True
                        # drain remaining entries in this directory without storing
                        continue
            finally:
                if owns:
                    try:
                        os.close(fd)
                    except OSError:
                        pass
        if failed:
            return results, "failed"
        if truncated:
            return results, "truncated"
        return results, "complete"
    except OSError:
        return results, "failed"