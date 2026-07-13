from __future__ import annotations

import contextlib
import inspect
import logging
import os
import sys
import time
import warnings
from abc import ABCMeta, abstractmethod
from dataclasses import dataclass
from threading import Lock, local
from typing import TYPE_CHECKING, Any, TypeVar
from weakref import WeakValueDictionary

from ._error import Timeout
from ._util import break_lock_file

#: Sentinel indicating that no explicit file permission mode was passed.
#: When used, lock files are created with 0o666 (letting umask and default ACLs control the final permissions)
#: and fchmod is skipped so that POSIX default ACL inheritance is preserved.
_UNSET_FILE_MODE: int = -1

if TYPE_CHECKING:
    from collections.abc import Callable
    from types import TracebackType

    from ._read_write import ReadWriteLock
    from ._soft_rw import SoftReadWriteLock

    if sys.version_info >= (3, 11):  # pragma: no cover (py311+)
        from typing import Self
    else:  # pragma: no cover (<py311)
        from typing_extensions import Self


_LOGGER = logging.getLogger("filelock")

# On Windows os.path.realpath calls CreateFileW with share_mode=0, which blocks concurrent DeleteFileW and causes
# livelocks under threaded contention with SoftFileLock. os.path.abspath is purely string-based and avoids this.
_canonical = os.path.abspath if sys.platform == "win32" else os.path.realpath


class _ThreadLocalRegistry(local):
    def __init__(self) -> None:
        super().__init__()
        self.held: dict[str, int] = {}


_registry = _ThreadLocalRegistry()


# This is a helper class which is returned by :meth:`BaseFileLock.acquire` and wraps the lock to make sure __enter__
# is not called twice when entering the with statement. If we would simply return *self*, the lock would be acquired
# again in the *__enter__* method of the BaseFileLock, but not released again automatically. issue #37 (memory leak)
class AcquireReturnProxy:
    """A context-aware object that will release the lock file when exiting."""

    def __init__(self, lock: BaseFileLock | ReadWriteLock | SoftReadWriteLock) -> None:
        self.lock: BaseFileLock | ReadWriteLock | SoftReadWriteLock = lock

    def __enter__(self) -> BaseFileLock | ReadWriteLock | SoftReadWriteLock:
        return self.lock

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        self.lock.release()


@dataclass
class FileLockContext:
    """A dataclass which holds the context for a ``BaseFileLock`` object."""

    # The context is held in a separate class to allow optional use of thread local storage via the
    # ThreadLocalFileContext class.

    #: The path to the lock file.
    lock_file: str

    #: The default timeout value.
    timeout: float

    #: The mode for the lock files
    mode: int

    #: Whether the lock should be blocking or not
    blocking: bool

    #: The default polling interval value.
    poll_interval: float

    #: The lock lifetime in seconds; ``None`` means the lock never expires.
    lifetime: float | None = None

    #: The file descriptor for the *_lock_file* as it is returned by the os.open() function, not None when lock held
    lock_file_fd: int | None = None

    #: The lock counter is used for implementing the nested locking mechanism.
    lock_counter: int = 0  # When the lock is acquired is increased and the lock is only released, when this value is 0


class ThreadLocalFileContext(FileLockContext, local):
    """A thread local version of the ``FileLockContext`` class."""


_T = TypeVar("_T", bound="BaseFileLock")


class FileLockMeta(ABCMeta):
    _instances: WeakValueDictionary[str, BaseFileLock]
    _instances_lock: Lock

    def __call__(  # noqa: PLR0913
        cls: type[_T],
        lock_file: str | os.PathLike[str],
        timeout: float = -1,
        mode: int = _UNSET_FILE_MODE,
        thread_local: bool = True,  # noqa: FBT001, FBT002
        *,
        blocking: bool = True,
        is_singleton: bool = False,
        poll_interval: float = 0.05,
        lifetime: float | None = None,
        **kwargs: Any,  # capture remaining kwargs for subclasses  # noqa: ANN401
    ) -> _T:
        params = {
            "timeout": timeout,
            "mode": mode,
            "thread_local": thread_local,
            "blocking": blocking,
            "is_singleton": is_singleton,
            "poll_interval": poll_interval,
            "lifetime": lifetime,
            **kwargs,
        }
        if not is_singleton:
            return cls._create_instance(lock_file, params)

        # Look up, build and store under one lock. Without it two threads racing the first construction for a
        # path both miss the cache and each build their own instance, so callers relying on is_singleton for
        # reentrant locking across instances end up with two "singletons" and acquire()'s deadlock check then
        # rejects a legitimate reentrant acquire; the unguarded writes to the WeakValueDictionary are a data
        # race besides. ReadWriteLock and SoftReadWriteLock already guard their singleton caches this way.
        with cls._instances_lock:
            if (instance := cls._instances.get(str(lock_file))) is None:
                instance = cls._create_instance(lock_file, params)
                cls._instances[str(lock_file)] = instance
                return instance

        params_to_check = {
            "thread_local": (thread_local, instance.is_thread_local()),
            "timeout": (timeout, instance.timeout),
            "mode": (mode, instance._context.mode),  # noqa: SLF001
            "blocking": (blocking, instance.blocking),
            "poll_interval": (poll_interval, instance.poll_interval),
            "lifetime": (lifetime, instance.lifetime),
        }

        non_matching_params = {
            name: (passed_param, set_param)
            for name, (passed_param, set_param) in params_to_check.items()
            if passed_param != set_param
        }
        if not non_matching_params:
            return instance  # ty: ignore[invalid-return-type]  # https://github.com/astral-sh/ty/issues/3231

        # parameters do not match; raise error
        msg = "Singleton lock instances cannot be initialized with differing arguments"
        msg += "\nNon-matching arguments: "
        for param_name, (passed_param, set_param) in non_matching_params.items():
            msg += f"\n\t{param_name} (existing lock has {set_param} but {passed_param} was passed)"
        raise ValueError(msg)

    def _create_instance(cls: type[_T], lock_file: str | os.PathLike[str], params: dict[str, Any]) -> _T:
        # Keep only the params this subclass's __init__ accepts: virtualenv narrows the signature of its
        # BaseFileLock descendant, so passing the full set would break it (https://github.com/tox-dev/filelock/pull/340).
        present_params = inspect.signature(cls.__init__).parameters
        init_params = {key: value for key, value in params.items() if key in present_params}
        return super().__call__(lock_file, **init_params)


class BaseFileLock(contextlib.ContextDecorator, metaclass=FileLockMeta):
    """
    Abstract base class for a file lock object.

    Provides a reentrant, cross-process exclusive lock backed by OS-level primitives. Subclasses implement the actual
    locking mechanism (:class:`UnixFileLock <filelock.UnixFileLock>`, :class:`WindowsFileLock
    <filelock.WindowsFileLock>`, :class:`SoftFileLock <filelock.SoftFileLock>`).

    """

    _instances: WeakValueDictionary[str, BaseFileLock]
    _instances_lock: Lock

    #: How the cross-instance deadlock message names the conflicting holder; the async subclass says "task".
    _deadlock_holder_desc: str = "FileLock instance in this thread"

    def __init_subclass__(cls, **kwargs: dict[str, Any]) -> None:
        """Setup unique state for lock subclasses."""
        super().__init_subclass__(**kwargs)
        cls._instances = WeakValueDictionary()
        cls._instances_lock = Lock()

    def __init__(  # noqa: PLR0913
        self,
        lock_file: str | os.PathLike[str],
        timeout: float = -1,
        mode: int = _UNSET_FILE_MODE,
        thread_local: bool = True,  # noqa: FBT001, FBT002
        *,
        blocking: bool = True,
        is_singleton: bool = False,
        poll_interval: float = 0.05,
        lifetime: float | None = None,
    ) -> None:
        """
        Create a new lock object.

        :param lock_file: path to the file
        :param timeout: default timeout when acquiring the lock, in seconds. It will be used as fallback value in the
            acquire method, if no timeout value (``None``) is given. If you want to disable the timeout, set it to a
            negative value. A timeout of 0 means that there is exactly one attempt to acquire the file lock.
        :param mode: file permissions for the lockfile. When not specified, the OS controls permissions via umask and
            default ACLs, preserving POSIX default ACL inheritance in shared directories.
        :param thread_local: Whether this object's internal context should be thread local or not. If this is set to
            ``False`` then the lock will be reentrant across threads. When ``True`` (the default), **all fields of the
            lock's internal context are per-thread**, including the configuration values ``poll_interval``, ``timeout``,
            ``blocking``, ``mode``, and ``lifetime``. Setting one of these properties from one thread does not change
            the value seen by another thread; threads that did not perform the write continue to see the value supplied
            at construction time. If you need configuration values to be visible across threads, construct the lock
            with ``thread_local=False``.
        :param blocking: whether the lock should be blocking or not
        :param is_singleton: If this is set to ``True`` then only one instance of this class will be created per lock
            file. This is useful if you want to use the lock object for reentrant locking without needing to pass the
            same object around.
        :param poll_interval: default interval for polling the lock file, in seconds. It will be used as fallback value
            in the acquire method, if no poll_interval value (``None``) is given.
        :param lifetime: maximum time in seconds a lock can be held before it is considered expired. When set, a waiting
            process will break a lock whose file modification time is older than ``lifetime`` seconds. ``None`` (the
            default) means locks never expire.

        """
        self._is_thread_local = thread_local
        self._is_singleton = is_singleton

        # Create the context. Note that external code should not work with the context directly and should instead use
        # properties of this class.
        kwargs: dict[str, Any] = {
            "lock_file": os.fspath(lock_file),
            "timeout": timeout,
            "mode": mode,
            "blocking": blocking,
            "poll_interval": poll_interval,
            "lifetime": lifetime,
        }
        self._context: FileLockContext = (ThreadLocalFileContext if thread_local else FileLockContext)(**kwargs)

    def is_thread_local(self) -> bool:
        """:returns: a flag indicating if this lock is thread local or not"""
        return self._is_thread_local

    @property
    def is_singleton(self) -> bool:
        """
        A flag indicating if this lock is singleton or not.

        .. versionadded:: 3.13.0

        """
        return self._is_singleton

    @property
    def lock_file(self) -> str:
        """Path to the lock file."""
        return self._context.lock_file

    @property
    def timeout(self) -> float:
        """
        The default timeout value, in seconds.

        .. versionadded:: 2.0.0

        """
        return self._context.timeout

    @timeout.setter
    def timeout(self, value: float | str) -> None:
        """
        Change the default timeout value.

        :param value: the new value, in seconds

        """
        self._context.timeout = float(value)

    @property
    def blocking(self) -> bool:
        """
        Whether the locking is blocking or not.

        .. versionadded:: 3.14.0

        """
        return self._context.blocking

    @blocking.setter
    def blocking(self, value: bool) -> None:
        """
        Change the default blocking value.

        :param value: the new value as bool

        """
        self._context.blocking = value

    @property
    def poll_interval(self) -> float:
        """
        The default polling interval, in seconds.

        .. versionadded:: 3.24.0

        """
        return self._context.poll_interval

    @poll_interval.setter
    def poll_interval(self, value: float) -> None:
        """
        Change the default polling interval.

        :param value: the new value, in seconds

        """
        self._context.poll_interval = value

    @property
    def lifetime(self) -> float | None:
        """
        The lock lifetime in seconds, or ``None`` if the lock never expires.

        .. versionadded:: 3.24.0

        """
        return self._context.lifetime

    @lifetime.setter
    def lifetime(self, value: float | None) -> None:
        """
        Change the lock lifetime.

        :param value: the new value in seconds, or ``None`` to disable expiration

        :raises ValueError: if *value* is a negative number
        :raises TypeError: if *value* is not ``None`` and not a real number

        """
        if value is not None:
            if isinstance(value, bool) or not isinstance(value, (int, float)):
                msg = f"lifetime must be a non-negative number or None, not {type(value).__name__}"
                raise TypeError(msg)
            if value < 0:
                msg = f"lifetime must be non-negative, not {value!r}"
                raise ValueError(msg)
        self._context.lifetime = value

    @property
    def mode(self) -> int:
        """The file permissions for the lockfile."""
        return 0o644 if self._context.mode == _UNSET_FILE_MODE else self._context.mode

    @property
    def has_explicit_mode(self) -> bool:
        """Whether the file permissions were explicitly set."""
        return self._context.mode != _UNSET_FILE_MODE

    def _open_mode(self) -> int:
        """:returns: the mode for os.open() — 0o666 when unset (let umask/ACLs decide), else the explicit mode"""
        return 0o666 if self._context.mode == _UNSET_FILE_MODE else self._context.mode

    def _try_break_expired_lock(self) -> None:
        """Remove the lock file if its modification time exceeds the configured :attr:`lifetime`."""
        if (lifetime := self._context.lifetime) is None:
            return
        with contextlib.suppress(OSError):
            # lstat, not stat: an attacker with write access to the lock directory can replace a held
            # lock file with a symlink pointing at an old file, making stat() report the target's stale
            # mtime so a waiter breaks a live lock and two processes hold it at once. lstat reads the
            # symlink's own mtime, matching the O_NOFOLLOW reads elsewhere.
            st = os.lstat(self.lock_file)
            if time.time() - st.st_mtime < lifetime:
                return
            break_lock_file(self.lock_file, st.st_mtime, st.st_ino)

    @abstractmethod
    def _acquire(self) -> None:
        """If the file lock could be acquired, self._context.lock_file_fd holds the file descriptor of the lock file."""
        raise NotImplementedError

    @abstractmethod
    def _release(self) -> None:
        """Releases the lock and sets self._context.lock_file_fd to None."""
        raise NotImplementedError

    @property
    def is_locked(self) -> bool:
        """
        A boolean indicating if the lock file is holding the lock currently.

        .. versionchanged:: 2.0.0

            This was previously a method and is now a property.

        """
        return self._context.lock_file_fd is not None

    @property
    def lock_counter(self) -> int:
        """The number of times this lock has been acquired (but not yet released)."""
        return self._context.lock_counter

    @staticmethod
    def _check_give_up(  # noqa: PLR0913
        lock_id: int,
        lock_filename: str,
        *,
        blocking: bool,
        cancel_check: Callable[[], bool] | None,
        timeout: float,
        start_time: float,
    ) -> bool:
        if blocking is False:
            _LOGGER.debug("Failed to immediately acquire lock %s on %s", lock_id, lock_filename)
            return True
        if cancel_check is not None and cancel_check():
            _LOGGER.debug("Cancellation requested for lock %s on %s", lock_id, lock_filename)
            return True
        if 0 <= timeout < time.perf_counter() - start_time:
            _LOGGER.debug("Timeout on acquiring lock %s on %s", lock_id, lock_filename)
            return True
        return False

    def acquire(
        self,
        timeout: float | None = None,
        poll_interval: float | None = None,
        *,
        poll_intervall: float | None = None,
        blocking: bool | None = None,
        cancel_check: Callable[[], bool] | None = None,
    ) -> AcquireReturnProxy:
        """
        Try to acquire the file lock.

        :param timeout: maximum wait time for acquiring the lock, ``None`` means use the default :attr:`~timeout` is and
            if ``timeout < 0``, there is no timeout and this method will block until the lock could be acquired
        :param poll_interval: interval of trying to acquire the lock file, ``None`` means use the default
            :attr:`~poll_interval`
        :param poll_intervall: deprecated, kept for backwards compatibility, use ``poll_interval`` instead
        :param blocking: defaults to True. If False, function will return immediately if it cannot obtain a lock on the
            first attempt. Otherwise, this method will block until the timeout expires or the lock is acquired.
        :param cancel_check: a callable returning ``True`` when the acquisition should be canceled. Checked on each poll
            iteration. When triggered, raises :class:`~Timeout` just like an expired timeout.

        :returns: a context object that will unlock the file when the context is exited

        :raises Timeout: if fails to acquire lock within the timeout period

        .. code-block:: python

            # You can use this method in the context manager (recommended)
            with lock.acquire():
                pass

            # Or use an equivalent try-finally construct:
            lock.acquire()
            try:
                pass
            finally:
                lock.release()

        .. versionchanged:: 2.0.0

            This method returns now a *proxy* object instead of *self*, so that it can be used in a with statement
            without side effects.

        """
        # Use the default timeout, if no timeout is provided.
        if timeout is None:
            timeout = self._context.timeout

        if blocking is None:
            blocking = self._context.blocking

        if poll_intervall is not None:
            msg = "use poll_interval instead of poll_intervall"
            warnings.warn(msg, DeprecationWarning, stacklevel=2)
            poll_interval = poll_intervall

        poll_interval = poll_interval if poll_interval is not None else self._context.poll_interval

        # Increment the number right at the beginning. We can still undo it, if something fails.
        self._context.lock_counter += 1

        canonical = _canonical(self.lock_file)
        self._raise_if_would_deadlock(canonical, timeout=timeout, blocking=blocking)

        start_time = time.perf_counter()
        try:
            self._poll_until_acquired(
                blocking=blocking,
                cancel_check=cancel_check,
                timeout=timeout,
                poll_interval=poll_interval,
                start_time=start_time,
            )
        except BaseException:
            self._undo_acquire(canonical)
            raise
        self._commit_acquire(canonical)
        return AcquireReturnProxy(lock=self)

    def _raise_if_would_deadlock(self, canonical: str, *, timeout: float, blocking: bool) -> None:
        """
        Fail fast when a *different* live instance already holds this path on the current thread/task.

        Only the first, indefinitely-blocking acquire can self-deadlock this way: waiting in the OS primitive would
        block on a lock this thread already owns. A finite timeout or ``blocking=False`` keeps the normal Timeout path.
        """
        would_block = self._context.lock_counter == 1 and not self.is_locked and timeout < 0 and blocking
        if would_block and _registry.held.get(canonical) not in {None, id(self)}:
            self._context.lock_counter -= 1
            msg = (
                f"Deadlock: lock '{self.lock_file}' is already held by a different {self._deadlock_holder_desc}. "
                f"Use is_singleton=True to enable reentrant locking across instances."
            )
            raise RuntimeError(msg)

    def _undo_acquire(self, canonical: str) -> None:
        """Roll back the counter after a failed acquire, dropping the registry entry once nothing holds the path."""
        self._context.lock_counter = max(0, self._context.lock_counter - 1)
        if self._context.lock_counter == 0:
            _registry.held.pop(canonical, None)

    def _commit_acquire(self, canonical: str) -> None:
        """Record this instance as the holder once the first acquire succeeds, so peers can detect the deadlock."""
        if self._context.lock_counter == 1:
            _registry.held[canonical] = id(self)

    def _drop_registry_entry(self) -> None:
        """Forget this path's holder on release so a later cross-instance acquire is not misread as a deadlock."""
        _registry.held.pop(_canonical(self.lock_file), None)

    def _poll_until_acquired(
        self,
        *,
        blocking: bool,
        cancel_check: Callable[[], bool] | None,
        timeout: float,
        poll_interval: float,
        start_time: float,
    ) -> None:
        lock_id = id(self)
        lock_filename = self.lock_file
        while True:
            if not self.is_locked:
                self._try_break_expired_lock()
                _LOGGER.debug("Attempting to acquire lock %s on %s", lock_id, lock_filename)
                self._acquire()
            if self.is_locked:
                _LOGGER.debug("Lock %s acquired on %s", lock_id, lock_filename)
                return
            if self._check_give_up(
                lock_id,
                lock_filename,
                blocking=blocking,
                cancel_check=cancel_check,
                timeout=timeout,
                start_time=start_time,
            ):
                raise Timeout(lock_filename)
            msg = "Lock %s not acquired on %s, waiting %s seconds ..."
            _LOGGER.debug(msg, lock_id, lock_filename, poll_interval)
            time.sleep(poll_interval)

    def release(self, force: bool = False) -> None:  # noqa: FBT001, FBT002
        """
        Release the file lock. The lock is only completely released when the lock counter reaches 0. The lock file
        itself may be deleted automatically, the behavior is platform-specific.

        :param force: If true, the lock counter is ignored and the lock is released in every case.

        """
        if self.is_locked:
            self._context.lock_counter -= 1

            if self._context.lock_counter == 0 or force:
                lock_id, lock_filename = id(self), self.lock_file

                _LOGGER.debug("Attempting to release lock %s on %s", lock_id, lock_filename)
                self._release()
                self._context.lock_counter = 0
                self._drop_registry_entry()
                _LOGGER.debug("Lock %s released on %s", lock_id, lock_filename)

    def __enter__(self) -> Self:
        """
        Acquire the lock.

        :returns: the lock object

        """
        self.acquire()
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        """
        Release the lock.

        :param exc_type: the exception type if raised
        :param exc_value: the exception value if raised
        :param traceback: the exception traceback if raised

        """
        self.release()

    def __del__(self) -> None:
        """Called when the lock object is deleted."""
        self.release(force=True)


__all__ = [
    "_UNSET_FILE_MODE",
    "AcquireReturnProxy",
    "BaseFileLock",
]
