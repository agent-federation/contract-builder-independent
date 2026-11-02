"""Path grammar, root confinement and safe file reading."""

from __future__ import annotations

import os
import stat
from typing import Iterator, List, Tuple


class PathError(Exception):
    pass


def validate_path_grammar(p: str) -> None:
    if not isinstance(p, str) or not p:
        raise PathError("empty path")
    if p.startswith("/") or p.endswith("/"):
        raise PathError("invalid path boundaries")
    segments = p.split("/")
    if any(s == "" for s in segments):
        raise PathError("empty segment")
    if len(segments) > 16:
        raise PathError("too many segments")
    if len(p.encode("utf-8")) > 255:
        raise PathError("path too long")
    for seg in segments:
        if seg in (".", ".."):
            raise PathError("dot segment")
        if len(seg.encode("utf-8")) > 255:
            raise PathError("segment too long")
        if not all(c.isascii() and (c.isalnum() or c in "._-") for c in seg):
            raise PathError("invalid path characters")
    # ASCII-only already enforced by isascii above


def case_fold_key(p: str) -> str:
    return p.casefold()


def open_root(root_path: str) -> int:
    # Trust assumption: caller has already validated root_path is a directory path string.
    # We open with O_NOFOLLOW so a symlink root fails ELOOP rather than being followed.
    try:
        fd = os.open(root_path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except OSError as exc:
        raise PathError(f"cannot open package root: {exc}") from exc
    try:
        st = os.fstat(fd)
    except OSError as exc:
        os.close(fd)
        raise PathError(f"cannot stat package root: {exc}") from exc
    if not stat.S_ISDIR(st.st_mode):
        os.close(fd)
        raise PathError("package root is not a directory")
    return fd


def open_relative(root_fd: int, rel_path: str) -> int:
    """Open a validated relative path under root_fd without following symlinks.

    Returns a file descriptor to the final regular file.
    """
    validate_path_grammar(rel_path)
    segments = rel_path.split("/")
    cur_fd = root_fd
    opened_fds: List[int] = []
    try:
        for i, seg in enumerate(segments):
            flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC
            if i < len(segments) - 1:
                flags |= os.O_DIRECTORY
            fd = os.open(seg, flags, dir_fd=cur_fd)
            opened_fds.append(fd)
            st = os.fstat(fd)
            if i < len(segments) - 1:
                if not stat.S_ISDIR(st.st_mode):
                    raise PathError("path component is not a directory")
            else:
                if not stat.S_ISREG(st.st_mode):
                    raise PathError("declared path is not a regular file")
            cur_fd = fd
        final_fd = opened_fds[-1]
        # detach so caller owns it
        opened_fds.pop()
        return final_fd
    except OSError as exc:
        raise PathError(f"cannot open path {rel_path!r}: {exc}") from exc
    finally:
        for fd in opened_fds:
            try:
                os.close(fd)
            except OSError:
                pass


def read_file_bounded(fd: int, per_file_limit: int, total_counter: list[int], total_limit: int) -> bytes:
    st = os.fstat(fd)
    if not stat.S_ISREG(st.st_mode):
        raise PathError("not a regular file")
    # advisory size check
    if st.st_size > per_file_limit:
        raise PathError("file exceeds per-file limit")
    chunks = []
    read_total = 0
    while True:
        remaining_file = per_file_limit - read_total
        remaining_total = total_limit - total_counter[0]
        to_read = min(65536, remaining_file, remaining_total)
        if to_read <= 0:
            # determine which limit
            if read_total >= per_file_limit:
                raise PathError("per-file limit exceeded")
            raise PathError("total payload limit exceeded")
        data = os.read(fd, to_read)
        if not data:
            break
        chunks.append(data)
        read_total += len(data)
        total_counter[0] += len(data)
        if read_total > per_file_limit or total_counter[0] > total_limit:
            raise PathError("payload limit exceeded")
    return b"".join(chunks)


def scan_entries(root_fd: int, max_entries: int) -> List[Tuple[str, bool]]:
    """Return (relative_path, is_dir) for entries under root, bounded.

    Does not follow symlinks. Stops after max_entries.
    """
    results: List[Tuple[str, bool]] = []
    # stack of (dir_fd_owned, prefix)
    # We'll do iterative DFS using dir fds opened with O_NOFOLLOW.
    stack = [(root_fd, "", False)]  # (fd, prefix, owns_fd)
    # root already opened by caller; don't close it here
    while stack and len(results) < max_entries:
        fd, prefix, owns = stack.pop()
        try:
            for entry in os.scandir(fd):
                if len(results) >= max_entries:
                    break
                name = entry.name
                if prefix:
                    rel = prefix + "/" + name
                else:
                    rel = name
                try:
                    st = entry.stat(follow_symlinks=False)
                except OSError:
                    continue
                is_dir = stat.S_ISDIR(st.st_mode)
                is_file = stat.S_ISREG(st.st_mode)
                is_link = stat.S_ISLNK(st.st_mode)
                if is_link:
                    # record as file-like? Symlink is not a regular file; skip reading
                    results.append((rel, False))
                    continue
                if is_dir:
                    results.append((rel, True))
                    # open dir fd
                    try:
                        child_fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
                        stack.append((child_fd, rel, True))
                    except OSError:
                        pass
                elif is_file:
                    results.append((rel, False))
        finally:
            if owns:
                try:
                    os.close(fd)
                except OSError:
                    pass
    return results