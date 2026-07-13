"""
A structural type checker with clean separation of concerns.

The checker validates values against type annotations without requiring
the types to be instantiated. It supports standard library types, generics,
Union/Optional, Literal, Annotated, TypeVar, NewType, dataclasses, and
pydantic-compatible custom types.

Architecture:
    check_type          - entry point, dispatches to custom handlers or standard path
    get_annot_branches  - peels Union/Optional into flat alternatives
    check_branch        - outer_match then decompose+recurse
    outer_match         - does the value match this annotation at the top level?
    decompose           - yield (child_value, child_annotation, child_ctx) triples
"""

from __future__ import annotations

import collections.abc
import inspect
import types
from dataclasses import dataclass, field, is_dataclass
from dataclasses import fields as dataclass_fields
from enum import Enum
from pathlib import PurePath
from types import GeneratorType
from typing import (
    Annotated,
    Any,
    Callable,
    Dict,
    ForwardRef,
    Iterator,
    Literal,
    Optional,
    Tuple,
    TypeVar,
    Union,
    get_args,
    get_origin,
)

# ---------------------------------------------------------------------------
# Error accumulation
# ---------------------------------------------------------------------------


@dataclass
class TypeCheckError:
    """A single type-check failure, recording the path, value, and expected type."""

    path: Tuple[Any, ...]
    value: Any
    annotation: Any

    def __str__(self) -> str:
        path_str = " → ".join(str(p) for p in self.path) if self.path else "root"
        return f"at {path_str}: {self.value!r} is not {self.annotation}"


@dataclass
class Ctx:
    """Accumulates errors during a type-check traversal.

    All recursive calls share the same ``errors`` list via ``child()``,
    so errors from any depth are collected in one place.
    """

    path: Tuple[Any, ...] = ()
    errors: list[TypeCheckError] = field(default_factory=list)

    def child(self, segment: Any) -> Ctx:
        """Create a child context with *segment* appended to the path."""
        return Ctx(self.path + (segment,), self.errors)  # shared errors list

    def fail(self, value: Any, annotation: Any) -> None:
        """Record a type-check failure at the current path."""
        self.errors.append(TypeCheckError(self.path, value, annotation))


# ---------------------------------------------------------------------------
# Main entry points
# ---------------------------------------------------------------------------


def check_type(
    value: Any,
    annotation: Any,
    custom_handlers: Optional[Dict[type, Callable[..., bool]]] = None,
    ctx: Optional[Ctx] = None,
) -> bool:
    """Check whether *value* is compatible with *annotation*.

    Returns ``True`` if the value matches, ``False`` otherwise.  Errors are
    accumulated in *ctx* (created automatically if not provided).

    *custom_handlers* maps ``type(value)`` to a callable
    ``(value, annotation, handlers, ctx) -> bool`` that overrides the
    default checking logic for that runtime type.
    """
    if custom_handlers is None:
        custom_handlers = {}
    if ctx is None:
        ctx = Ctx()

    if type(value) in custom_handlers:
        return custom_handlers[type(value)](value, annotation, custom_handlers, ctx)

    return any(
        check_branch(value, branch, custom_handlers, ctx)
        for branch in get_annot_branches(annotation)
    )


def check_branch(
    value: Any,
    annotation: Any,
    custom_handlers: Dict[type, Callable[..., bool]],
    ctx: Ctx,
) -> bool:
    """Check *value* against a single (non-Union) annotation branch.

    First checks the top-level match via ``outer_match``, then recursively
    checks children yielded by ``decompose``.
    """
    if not outer_match(value, annotation):
        ctx.fail(value, annotation)
        return False
    return all(
        check_type(v, a, custom_handlers, child_ctx)
        for v, a, child_ctx in decompose(value, annotation, ctx)
    )


# ---------------------------------------------------------------------------
# get_annot_branches: peel Union/Optional into flat alternatives
# ---------------------------------------------------------------------------


def get_annot_branches(annotation: Any) -> Tuple[Any, ...]:
    """Split a (possibly Union) annotation into individual branches.

    ``Union[int, str]`` becomes ``(int, str)``.  ``Optional[X]`` becomes
    ``(X, NoneType)``.  ``X | Y`` (Python 3.10+) is handled via
    ``types.UnionType``.  Non-union annotations are returned as a
    single-element tuple.
    """
    origin = get_origin(annotation)

    # Union[X, Y] and Optional[X] (which is Union[X, None])
    if origin is Union:
        return get_args(annotation)

    # types.UnionType handles X | Y syntax (Python 3.10+)
    if origin is types.UnionType or isinstance(annotation, types.UnionType):
        return get_args(annotation)

    return (annotation,)


# ---------------------------------------------------------------------------
# outer_match: does the value match at this level, ignoring children?
# ---------------------------------------------------------------------------

#: Map from typing generic origins to the runtime types used for isinstance.
ORIGIN_TO_BUILTIN: Dict[Any, Any] = {
    list: list,
    dict: dict,
    tuple: tuple,
    set: set,
    frozenset: frozenset,
    collections.abc.Sequence: collections.abc.Sequence,
    collections.abc.MutableSequence: collections.abc.MutableSequence,
    collections.abc.Set: collections.abc.Set,
    collections.abc.MutableSet: collections.abc.MutableSet,
    collections.abc.Mapping: collections.abc.Mapping,
    collections.abc.MutableMapping: collections.abc.MutableMapping,
    collections.abc.Callable: collections.abc.Callable,
    collections.abc.Iterable: collections.abc.Iterable,
    collections.abc.Iterator: collections.abc.Iterator,
}


def outer_match(value: Any, annotation: Any) -> bool:
    """Check whether *value* matches *annotation* at the top level.

    This does **not** recurse into container elements — that is the job of
    ``decompose`` + ``check_branch``.  Coercion rules:

    * ``bool`` requires an exact bool (``0``/``1`` are rejected).
    * ``int`` accepts ints and parseable strings, but rejects bools.
    * ``float`` accepts ints, floats, and parseable strings, but rejects bools.
    * ``Path``/``PurePath`` accept strings.
    * ``str`` enums accept valid member value strings.
    * Generators / iterators always pass (to avoid consuming them).
    * Unresolved ``ForwardRef`` and string annotations always pass.
    """
    # Any / Parameter.empty matches everything
    if annotation is Any or annotation is inspect.Parameter.empty:
        return True

    # None/NoneType
    if annotation is None or annotation is type(None):
        return value is None

    # Generators pass through without consumption
    if isinstance(value, (GeneratorType, collections.abc.Iterator)) and not isinstance(
        value, (str, bytes)
    ):
        return True

    # Literal[v1, v2, ...]
    if get_origin(annotation) is Literal:
        return value in get_args(annotation)

    # Annotated[T, ...] — unwrap to inner type
    if get_origin(annotation) is Annotated:
        inner = get_args(annotation)[0]
        metadata = get_args(annotation)[1:]
        if _has_strict_metadata(metadata):
            return _strict_match(value, inner)
        return outer_match(value, inner)

    # Type[X] — value should be a class that is a subclass of X
    if get_origin(annotation) is type:
        args = get_args(annotation)
        if not isinstance(value, type):
            return False
        if args and args[0] is not Any:
            try:
                return issubclass(value, args[0])
            except (
                TypeError
            ):  # pragma: no cover -- modern Python handles Union in issubclass
                return True  # pragma: no cover
        return True

    # Callable — just check callability here, signature checking is hard
    # and arguably belongs in a custom handler
    if get_origin(annotation) is collections.abc.Callable:
        return callable(value)

    # Generic types: List[int], Dict[str, int], etc.
    origin = get_origin(annotation)
    if origin is not None:
        check_against = ORIGIN_TO_BUILTIN.get(origin, origin)
        try:
            if not isinstance(value, check_against):
                return False
        except TypeError:  # pragma: no cover -- custom generics with non-type origins
            return True  # pragma: no cover
        # Fixed-length tuple: check length here
        if origin is tuple:
            args = get_args(annotation)
            if args and not (len(args) == 2 and args[1] is Ellipsis):
                if len(value) != len(args):
                    return False
        return True

    # NewType — unwrap to supertype
    if callable(annotation) and hasattr(annotation, "__supertype__"):
        return outer_match(value, annotation.__supertype__)  # pyright: ignore[reportFunctionMemberAccess]

    # TypeVar
    if isinstance(annotation, TypeVar):
        bound = annotation.__bound__
        constraints = annotation.__constraints__
        if bound:
            try:
                return isinstance(value, bound)
            except TypeError:
                # bound contains unresolved ForwardRefs or complex generics;
                # use check_type which handles Union via get_annot_branches
                return check_type(value, bound)
        if constraints:
            return any(check_type(value, c) for c in constraints)
        return True

    # Forward references — can't resolve, accept
    if isinstance(annotation, (str, ForwardRef)):
        return True

    # --- Plain types with coercion ---
    if isinstance(annotation, type):
        # bool: exact type (don't accept int 0/1)
        if annotation is bool:
            return isinstance(value, bool)
        # int: accept ints (not bools), reject strings that don't parse
        if annotation is int:
            if isinstance(value, bool):
                return False
            if isinstance(value, int):
                return True
            if isinstance(value, str):
                try:
                    int(value)
                    return True
                except (ValueError, TypeError):
                    return False
            return False
        # float: accept int/float (not bools), strings that parse
        if annotation is float:
            if isinstance(value, bool):
                return False
            if isinstance(value, (int, float)):
                return True
            if isinstance(value, str):
                try:
                    float(value)
                    return True
                except (ValueError, TypeError):
                    return False
            return False
        # str: straightforward
        if annotation is str:
            return isinstance(value, str)
        # Path: accept strings
        if issubclass(annotation, PurePath):
            return isinstance(value, (str, PurePath))
        # str enums: accept plain strings that are valid member values
        if issubclass(annotation, str) and issubclass(annotation, Enum):
            try:
                annotation(value)
                return True
            except (ValueError, KeyError):
                return False
        # Dataclass / Schema with dict value: accept for decompose
        if is_dataclass(annotation) and isinstance(value, dict):
            return True
        if hasattr(annotation, "model_fields") and isinstance(value, dict):
            return True
        # Pydantic v2 validator hook
        if hasattr(annotation, "__get_pydantic_core_schema__"):
            return _pydantic_v2_match(value, annotation)
        # Pydantic v1 validator hook
        if hasattr(annotation, "__get_validators__"):
            return _pydantic_v1_match(value, annotation)
        # Default isinstance
        return isinstance(value, annotation)

    return False


# ---------------------------------------------------------------------------
# Helpers for outer_match
# ---------------------------------------------------------------------------


def _resolve_dataclass_hints(cls: type) -> Dict[str, Any]:
    """Resolve forward references in a dataclass's type annotations.

    Uses ``get_type_hints`` with the class's module globals so that
    forward references like ``ForwardRef('Floats3d')`` are resolved to
    actual types.  Returns an empty dict on failure.
    """
    import sys
    from typing import get_type_hints

    mod = sys.modules.get(cls.__module__)
    globalns = vars(mod) if mod else None
    try:
        return get_type_hints(cls, globalns=globalns)
    except (NameError, AttributeError, TypeError, RecursionError):  # pragma: no cover
        return {}  # pragma: no cover


def _has_strict_metadata(metadata: Tuple[Any, ...]) -> bool:
    """Check if ``Annotated`` metadata contains a ``Strict()`` marker."""
    return any(getattr(m, "strict", False) for m in metadata if hasattr(m, "strict"))


def _strict_match(value: Any, inner_type: type) -> bool:
    """Exact type match for ``Annotated[X, Strict()]``.

    Unlike the normal coercion rules, strict matching requires
    ``type(value)`` to be exactly the annotated type.
    """
    if inner_type is int:
        return type(value) is int and not isinstance(value, bool)
    if inner_type is float:
        return type(value) is float
    if inner_type is str:
        return type(value) is str
    if inner_type is bool:
        return type(value) is bool
    return isinstance(value, inner_type)


class _AnySchemaHandler:
    """Minimal stand-in for pydantic's ``GetCoreSchemaHandler``."""

    def __call__(
        self, _source_type: Any
    ) -> Dict[str, Any]:  # pragma: no cover -- called internally by pydantic hooks
        return {"type": "any"}  # pragma: no cover


def _pydantic_v2_match(value: Any, annotation: type) -> bool:
    """Check *value* against a type with ``__get_pydantic_core_schema__``.

    Extracts the validator function from the pydantic core schema and calls
    it.  Falls back to ``isinstance`` if the value is already an instance.
    """
    if isinstance(value, annotation):
        return True
    try:
        schema = annotation.__get_pydantic_core_schema__(
            annotation, _AnySchemaHandler()
        )
        fn_entry = schema.get("function", {})
        validator = fn_entry.get("function") if isinstance(fn_entry, dict) else None
        if callable(validator):
            validator(value)
            return True
    except (ValueError, TypeError, AssertionError):
        return False
    return False


class _PydanticV1FieldShim:
    """Minimal shim providing ``field.type_`` for pydantic v1 validators."""

    def __init__(self, typ: type) -> None:
        self.type_ = typ


def _pydantic_v1_match(value: Any, annotation: type) -> bool:
    """Check *value* against a type with ``__get_validators__``.

    Iterates through the validators yielded by the type's
    ``__get_validators__`` classmethod.  Validators with more than
    2 parameters are skipped (they require a ``config`` argument we
    don't have).
    """
    if isinstance(value, annotation):
        return True
    shim = _PydanticV1FieldShim(annotation)
    for validator in annotation.__get_validators__():
        try:
            nparams = len(inspect.signature(validator).parameters)
        except (ValueError, TypeError):
            nparams = 1
        if nparams > 2:
            continue
        try:
            value = validator(value) if nparams == 1 else validator(value, shim)
        except (ValueError, TypeError, AssertionError):
            return False
    return True


# ---------------------------------------------------------------------------
# decompose: yield (child_value, child_annotation, child_ctx) triples
# ---------------------------------------------------------------------------

#: Origins that are sequence-like: one type arg, fan across elements.
SEQUENCE_ORIGINS: set[Any] = {
    list,
    set,
    frozenset,
    collections.abc.Sequence,
    collections.abc.MutableSequence,
    collections.abc.Set,
    collections.abc.MutableSet,
    collections.abc.Iterable,
    collections.abc.Iterator,
}

#: Origins that are mapping-like: two type args (key, value).
MAPPING_ORIGINS: set[Any] = {
    dict,
    collections.abc.Mapping,
    collections.abc.MutableMapping,
}


def decompose(value: Any, annotation: Any, ctx: Ctx) -> Iterator[Tuple[Any, Any, Ctx]]:
    """Yield ``(child_value, child_annotation, child_ctx)`` triples.

    This is the recursive engine of the type checker.  For container types
    it fans out over elements; for dataclasses and schemas it fans out
    over fields.  ``outer_match`` has already confirmed the top-level
    match, so we only need to check the children here.
    """
    # Annotated[T, ...] — unwrap
    if get_origin(annotation) is Annotated:
        annotation = get_args(annotation)[0]

    origin = get_origin(annotation)
    args = get_args(annotation)

    # Schema / model_fields annotation with dict value — fan out over fields
    if (
        isinstance(annotation, type)
        and hasattr(annotation, "model_fields")
        and isinstance(value, dict)
    ):
        for name, field_info in annotation.model_fields.items():
            data_key = name
            if hasattr(field_info, "alias") and field_info.alias is not None:
                data_key = field_info.alias
            if data_key in value:
                yield (value[data_key], field_info.annotation, ctx.child(data_key))
        return

    # Dataclass annotation with dict value — fan out over fields
    if (
        isinstance(annotation, type)
        and is_dataclass(annotation)
        and isinstance(value, dict)
    ):
        resolved_hints = _resolve_dataclass_hints(annotation)
        for f in dataclass_fields(annotation):
            if f.name in value:
                hint = resolved_hints.get(f.name, f.type)
                yield (value[f.name], hint, ctx.child(f.name))
        return

    # Dataclass annotation with dataclass value — match fields
    if (
        isinstance(annotation, type)
        and is_dataclass(annotation)
        and is_dataclass(value)
    ):
        resolved_hints = _resolve_dataclass_hints(annotation)
        for f in dataclass_fields(annotation):
            if hasattr(value, f.name):
                hint = resolved_hints.get(f.name, f.type)
                yield (getattr(value, f.name), hint, ctx.child(f.name))
        return

    # No type args means nothing to recurse into for generics
    if not args:
        return

    # Tuple: fixed-length or variable-length
    if origin is tuple:
        if len(args) == 2 and args[1] is Ellipsis:
            # Tuple[int, ...] — variable length, one type
            for i, elem in enumerate(value):
                yield (elem, args[0], ctx.child(i))
        else:
            # Tuple[int, str, float] — fixed length
            # Length already verified in outer_match
            for i, (elem, arg) in enumerate(zip(value, args)):
                yield (elem, arg, ctx.child(i))
        return

    # Sequence-like
    if origin in SEQUENCE_ORIGINS:
        arg = args[0]
        for i, elem in enumerate(value):
            yield (elem, arg, ctx.child(i))
        return

    # Mapping-like
    if origin in MAPPING_ORIGINS:
        k_ann, v_ann = args[0], args[1]
        for k in value:
            yield (k, k_ann, ctx.child(f"key({k!r})"))
            yield (value[k], v_ann, ctx.child(k))
        return

    # Type[X], Callable, TypeVar, Literal — no children to decompose
    # (fully resolved in outer_match)
    return
