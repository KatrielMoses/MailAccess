from __future__ import annotations

import os
import secrets
import stat
import sys
from errno import EACCES, EISDIR
from pathlib import Path


def raise_on_not_writable_file(filename: str) -> None:
    """
    Raise an exception if attempting to open the file for writing would fail.

    Separates files that can never be written from files that are writable but currently locked.

    :param filename: file to check

    :raises OSError: as if the file was opened for writing.

    """
    try:
        # lstat, not stat: it settles exists-and-writable in one syscall, and a hostile symlink planted at the lock
        # path would otherwise make this inspect the link target, letting an attacker turn a contended acquire into a
        # misleading PermissionError / IsADirectoryError and probe that target's attributes. The real open passes
        # O_NOFOLLOW and refuses the symlink anyway.
        file_stat = os.lstat(filename)
    except OSError:
        return  # does not exist, or an error the caller cannot act on

    # No mtime guard: the old `if st_mtime != 0` skip existed for NFS/Linux quirks where os.lstat could return an
    # all-zero struct, which it no longer does. Skipping on mtime 0 let a read-only file or a directory at the lock
    # path pass as missing, so acquire() blocked forever on an open that cannot succeed.
    if not (file_stat.st_mode & stat.S_IWUSR):
        raise PermissionError(EACCES, "Permission denied", filename)

    if stat.S_ISDIR(file_stat.st_mode):
        if sys.platform == "win32":  # pragma: win32 cover
            raise PermissionError(EACCES, "Permission denied", filename)
        raise IsADirectoryError(EISDIR, "Is a directory", filename)  # pragma: win32 no cover


def ensure_directory_exists(filename: Path | str) -> None:
    """
    Ensure the directory containing the file exists (create it if necessary).

    :param filename: file.

    """
    Path(filename).parent.mkdir(parents=True, exist_ok=True)


def break_lock_file(lock_file: str, mtime_before: float, ino_before: int) -> None:
    """
    Atomically break a stale lock file that was judged stale at modification time *mtime_before*.

    The file is renamed to a process-private name before being unlinked, so two processes breaking the same lock
    cannot delete each other's work (only one rename of a given inode succeeds; the loser gets ``OSError``). After the
    rename the file is re-checked: a newer modification time, or a different inode than *ino_before*, means a peer
    recreated the lock between the stale decision and the rename, so we grabbed a live file and must abort, leaving the
    renamed file in place rather than rolling back (a rollback rename is itself racy — same trade-off as the soft
    read/write marker break). The inode check matters because filesystems with coarse modification-time granularity
    (NFS, FAT) can give a same-second recreation the old mtime, so mtime alone would not catch it and a live lock would
    be unlinked; the inode is the reliable identity, mirroring the token re-check in the soft read/write marker break.
    ``lstat`` is used so a hostile symlink swapped in after the decision is not followed.

    The break name carries a random token so it is unguessable and unique per attempt. Without it two breakers in the
    same process share ``<lock>.break.<pid>``, and a second break can rename a freshly recreated live lock onto that
    path in the window between the re-verify ``lstat`` above and the ``unlink`` below, so we would delete a live lock
    the inode check just approved. A private name means nobody else can target our break path, matching the soft
    read/write marker break.

    :param lock_file: path to the lock file to break.
    :param mtime_before: modification time observed when the lock was judged stale.
    :param ino_before: inode number observed when the lock was judged stale.

    :raises OSError: if the rename fails (e.g. the file vanished or is not owned in a sticky directory).

    """
    break_path = f"{lock_file}.break.{os.getpid()}.{secrets.token_hex(16)}"
    Path(lock_file).rename(break_path)
    try:
        st_after = os.lstat(break_path)
    except OSError:
        return
    if st_after.st_mtime > mtime_before or st_after.st_ino != ino_before:
        return
    Path(break_path).unlink()


__all__ = [
    "break_lock_file",
    "ensure_directory_exists",
    "raise_on_not_writable_file",
]
