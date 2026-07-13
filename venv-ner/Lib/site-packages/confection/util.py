import functools
import json
import re
from copy import deepcopy
from typing import Any, Callable, Protocol, TypeVar

from ._constants import VARIABLE_RE
from ._errors import ConfigValidationError

_DIn = TypeVar("_DIn")


class Decorator(Protocol):
    """Protocol to mark a function as returning its child with identical signature."""

    def __call__(self, name: str) -> Callable[[_DIn], _DIn]: ...


# This is how functools.partials seems to do it, too, to retain the return type
PartialT = TypeVar("PartialT")


def partial(
    func: Callable[..., PartialT], *args: Any, **kwargs: Any
) -> Callable[..., PartialT]:
    """Wrapper around functools.partial that retains docstrings and can include
    other workarounds if needed.
    """
    partial_func = functools.partial(func, *args, **kwargs)
    partial_func.__doc__ = func.__doc__
    return partial_func


DEFAULT_FROZEN_DICT_ERROR = (
    "Can't write to frozen dictionary. This is likely an internal "
    "error. Are you writing to a default function argument?"
)

DEFAULT_FROZEN_LIST_ERROR = (
    "Can't write to frozen list. Maybe you're trying to modify a computed "
    "property or default function argument?"
)


class SimpleFrozenDict(dict):
    """Simplified implementation of a frozen dict, mainly used as default
    function or method argument (for arguments that should default to empty
    dictionary). Will raise an error if the user attempts to add to dict.
    """

    def __init__(
        self,
        *args,
        error: str = DEFAULT_FROZEN_DICT_ERROR,
        **kwargs,
    ) -> None:
        """Initialize the frozen dict. Can be initialized with pre-defined
        values.

        error (str): The error message when user tries to assign to dict.
        """
        super().__init__(*args, **kwargs)
        self.error = error

    def __setitem__(self, key, value):
        raise NotImplementedError(self.error)

    def pop(self, key, default=None):
        raise NotImplementedError(self.error)

    def update(self, other=(), /, **kwargs):  # pyright: ignore[reportIncompatibleMethodOverride]
        raise NotImplementedError(self.error)

    def __deepcopy__(self, memo):
        return self.__class__(deepcopy({k: v for k, v in self.items()}))


class SimpleFrozenList(list):
    """Wrapper class around a list that lets us raise custom errors if certain
    attributes/methods are accessed. Mostly used for properties that return an
    immutable list (and that we don't want to convert to a tuple to not break
    too much backwards compatibility). If a user accidentally calls
    frozen_list.append(), we can raise a more helpful error.
    """

    def __init__(
        self,
        *args,
        error: str = DEFAULT_FROZEN_LIST_ERROR,
    ) -> None:
        """Initialize the frozen list.

        error (str): The error message when user tries to mutate the list.
        """
        self.error = error
        super().__init__(*args)

    def append(self, *args, **kwargs):
        raise NotImplementedError(self.error)

    def clear(self, *args, **kwargs):
        raise NotImplementedError(self.error)

    def extend(self, *args, **kwargs):
        raise NotImplementedError(self.error)

    def insert(self, *args, **kwargs):
        raise NotImplementedError(self.error)

    def pop(self, *args, **kwargs):
        raise NotImplementedError(self.error)

    def remove(self, *args, **kwargs):
        raise NotImplementedError(self.error)

    def reverse(self, *args, **kwargs):
        raise NotImplementedError(self.error)

    def sort(self, *args, **kwargs):
        raise NotImplementedError(self.error)

    def __deepcopy__(self, memo):
        return self.__class__(deepcopy(v) for v in self)


def is_promise(obj) -> bool:
    if not hasattr(obj, "keys"):
        return False
    id_keys = [k for k in obj.keys() if isinstance(k, str) and k.startswith("@")]
    if len(id_keys):
        return True
    return False


_PYTHON_LITERALS = {"True": True, "False": False, "None": None}


def try_load_json(value: str) -> Any:
    """Load a JSON string if possible, otherwise default to original value.

    Also handles Python-style literals ``True``, ``False``, and ``None``
    which are not valid JSON but are commonly used in config files.
    """
    try:
        return json.loads(value)
    except Exception:
        if value in _PYTHON_LITERALS:
            return _PYTHON_LITERALS[value]
        return value


def try_dump_json(value: Any, data: dict[str, dict] | str = "") -> str:
    """Dump a config value as JSON and output user-friendly error if it fails."""
    # Special case if we have a variable: it's already a string so don't dump
    # to preserve ${x:y} vs. "${x:y}"
    if isinstance(value, str) and VARIABLE_RE.search(value):
        return value
    try:
        value = json.dumps(value)
    except Exception as e:
        err_msg = (
            f"Couldn't serialize config value of type {type(value)}: {e}. Make "
            f"sure all values in your config are JSON-serializable. If you want "
            f"to include Python objects, use a registered function that returns "
            f"the object instead."
        )
        raise ConfigValidationError(config=data, desc=err_msg) from e
    # Escape $ to $$ for configparser, but preserve ${...} variable references
    return re.sub(r"\$(?!\{)", "$$", value)
