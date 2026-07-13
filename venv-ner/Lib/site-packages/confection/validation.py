"""Lightweight type validation system replacing Pydantic.

Provides Schema base class, dynamic schema creation, and type validation
for config values against function signatures.
"""

import inspect
import sys
from typing import Any, Optional, get_type_hints

from .typechecker import Ctx
from .typechecker import check_type as _tc2_check_type

# Optional pydantic imports — confection doesn't depend on pydantic,
# but if it's installed we can detect and convert BaseModel schemas.
# Skip pydantic.v1 on Python 3.14+ where it is unsupported.
if sys.version_info >= (3, 14):
    _PydanticV1BaseModel = None  # type: ignore[assignment,misc]
    _PydanticV1ValidationError = None  # type: ignore[assignment,misc]
else:
    try:
        from pydantic.v1 import (
            BaseModel as _PydanticV1BaseModel,  # pyright: ignore[reportMissingImports]
        )
        from pydantic.v1 import (
            ValidationError as _PydanticV1ValidationError,  # pyright: ignore[reportMissingImports]
        )
    except (ImportError, ModuleNotFoundError):  # pragma: no cover
        _PydanticV1BaseModel = None  # type: ignore[assignment,misc]
        _PydanticV1ValidationError = None  # type: ignore[assignment,misc]

try:
    from pydantic import (
        BaseModel as _PydanticV2BaseModel,  # pyright: ignore[reportMissingImports]
    )
    from pydantic import (
        ValidationError as _PydanticV2ValidationError,  # pyright: ignore[reportMissingImports]
    )
except (ImportError, ModuleNotFoundError):  # pragma: no cover
    _PydanticV2BaseModel = None  # type: ignore[assignment,misc]
    _PydanticV2ValidationError = None  # type: ignore[assignment,misc]

# === Constrained Types ===


class StrictBool:
    """Only accepts actual bool values (not int 0/1)."""

    pass


class PositiveInt:
    """Only accepts positive integers (> 0, not bool)."""

    pass


class StrictFloat:
    """Only accepts actual float values (not int)."""

    pass


# === Field Info ===


class FieldInfo:
    """Information about a schema field."""

    __slots__ = ("default", "alias", "annotation")

    def __init__(self, default=..., *, alias=None):
        self.default = default
        self.alias = alias
        self.annotation: Any = None

    def is_required(self):
        return self.default is ...


def Field(default=..., *, alias=None):
    """Create a field definition."""
    return FieldInfo(default=default, alias=alias)


# === Validation Error ===


class ValidationError(Exception):
    """Raised when schema validation fails."""

    def __init__(self, error_list):
        self._errors = error_list
        msgs = "; ".join(e.get("msg", "") for e in error_list)
        super().__init__(msgs)

    def errors(self):
        return self._errors


# === Schema ===


class _ValidatedResult:
    """Attribute-accessible result from model_validate."""

    def __init__(self, data):
        self.__dict__.update(data)


class Schema:
    """Base class for config validation schemas. Replaces pydantic.BaseModel."""

    model_config: dict = {"extra": "allow", "arbitrary_types_allowed": True}
    model_fields: dict = {}

    def __init_subclass__(cls, **kwargs):
        super().__init_subclass__(**kwargs)
        fields = {}
        all_hints = {}
        for base in reversed(cls.__mro__):
            base_annotations = getattr(base, "__annotations__", {})
            all_hints.update(base_annotations)

        for name, annotation in all_hints.items():
            if name in ("model_config", "model_fields") or name.startswith("_"):
                continue
            default = ...
            alias = None
            for klass in cls.__mro__:
                if name in klass.__dict__:
                    val = klass.__dict__[name]
                    if isinstance(val, FieldInfo):
                        default = val.default
                        alias = val.alias
                    elif not isinstance(
                        val, (type, classmethod, staticmethod, property)
                    ):
                        if not callable(val):
                            default = val
                    break
            field = FieldInfo(default=default, alias=alias)
            field.annotation = annotation
            fields[name] = field

        cls.model_fields = fields

    def __init__(self, **kwargs):
        for name, field in self.__class__.model_fields.items():
            if name in kwargs:
                setattr(self, name, kwargs[name])
            elif not field.is_required():
                setattr(self, name, field.default)

    @classmethod
    def model_validate(cls, data):
        """Validate a dict against this schema."""
        alias_gen = cls.model_config.get("alias_generator")
        errors = _validate_schema(data, cls.model_fields, cls.model_config, alias_gen)
        if errors:
            raise ValidationError(errors)
        # Build result with defaults filled in
        result_data = dict(data)
        for name, field in cls.model_fields.items():
            data_key = name
            if field.alias is not None:
                data_key = field.alias
            elif alias_gen:
                data_key = alias_gen(name)
            if data_key not in result_data and not field.is_required():
                result_data[data_key] = field.default
        return _ValidatedResult(result_data)

    @classmethod
    def from_function(
        cls,
        func,
        *,
        config=None,
    ):
        """Build a Schema subclass from a function's signature.

        Each parameter becomes a field.  The annotation is used as the type
        (defaulting to ``Any`` when missing) and the default value is
        preserved (parameters without defaults become required fields).

        ``*args`` parameters are wrapped in ``Sequence[annotation]`` and
        stored under the ``VARIABLE_POSITIONAL_ARGS`` field name.

        Forward-reference annotations are resolved via
        ``typing.get_type_hints`` against the function's module namespace.
        """
        from typing import Sequence as _Seq

        if config is None:
            config = {"extra": "forbid", "arbitrary_types_allowed": True}

        resolved = resolve_type_hints(func)
        fields = {}
        for param in inspect.signature(func).parameters.values():
            annotation = resolved.get(param.name, param.annotation)
            if annotation is inspect.Parameter.empty:
                annotation = Any
            if param.default is inspect.Parameter.empty:
                default = ...
            else:
                default = param.default
            if param.kind == inspect.Parameter.VAR_POSITIONAL:
                annotation = _Seq[annotation]  # type: ignore[valid-type]
            if param.kind == inspect.Parameter.VAR_KEYWORD:
                continue
            field = FieldInfo(default=default)
            field.annotation = annotation
            fields[param.name] = field

        return create_schema(
            func.__name__,
            __config__=config,
            **{name: (f.annotation, f) for name, f in fields.items()},
        )

    def model_dump(self):
        """Convert instance to dict."""
        result = {}
        for name in self.__class__.model_fields:
            if hasattr(self, name):
                val = getattr(self, name)
                if isinstance(val, Schema):
                    result[name] = val.model_dump()
                else:
                    result[name] = val
        return result


def create_schema(__name, __config__=None, **fields):
    """Dynamically create a Schema subclass.

    Each field value should be a (annotation, FieldInfo) tuple.
    """
    if __config__ is None:
        __config__ = {"extra": "allow"}

    processed = {}
    annotations = {}
    defaults = {}

    for name, field_def in fields.items():
        if isinstance(field_def, tuple) and len(field_def) == 2:
            annotation, field_info = field_def
            if not isinstance(field_info, FieldInfo):
                field_info = FieldInfo(default=field_info)
        else:
            raise ValueError(f"Field {name} must be (annotation, FieldInfo) tuple")

        field_info.annotation = annotation
        processed[name] = field_info
        annotations[name] = annotation
        if not field_info.is_required():
            defaults[name] = field_info.default

    namespace = {
        "__annotations__": annotations,
        "model_config": __config__,
    }
    namespace.update(defaults)

    cls = type(__name, (Schema,), namespace)
    # Apply alias_generator to fields that don't have explicit aliases
    alias_gen = __config__.get("alias_generator") if __config__ else None
    if alias_gen and callable(alias_gen):
        for name, field in processed.items():
            if field.alias is None:
                field.alias = alias_gen(name)
    # Override with our processed fields (preserving aliases)
    cls.model_fields = processed
    return cls


# === Resolve forward references ===


def resolve_type_hints(func):
    """Resolve type hints for a function, handling forward references.

    Falls back to raw annotations if resolution fails.
    """
    try:
        mod_name = getattr(func, "__module__", None)
        module = sys.modules.get(mod_name) if mod_name else None
        globalns = vars(module) if module else None
        return get_type_hints(func, globalns=globalns)
    except (NameError, AttributeError, TypeError, RecursionError):
        # NameError: unresolvable forward reference
        # AttributeError: module without expected attributes
        # TypeError: invalid annotation object
        # RecursionError: self-referential types (Python 3.13+)
        return {}


# === Type Validation ===


def _error_type_for(annotation):
    """Get an error type string for an annotation."""
    if annotation is int or annotation is PositiveInt:
        return "int_parsing"
    elif annotation is str:
        return "string_type"
    elif annotation is float or annotation is StrictFloat:
        return "float_parsing"
    elif annotation is bool or annotation is StrictBool:
        return "bool_type"
    return "value_error"


def validate_type(value, annotation):
    """Validate value against a type annotation.

    Returns None if valid, or an error message string if invalid.
    """
    ctx = Ctx()
    if _tc2_check_type(value, annotation, ctx=ctx):
        return None
    if ctx.errors:
        return str(ctx.errors[0])
    return f"{value!r} does not match {annotation}"  # pragma: no cover -- defensive fallback


# === Schema Validation ===


def _validate_schema(data, fields, config, alias_generator=None):
    """Validate a data dict against schema fields.

    Returns list of error dicts (empty if valid).
    """
    errors = []
    extra_mode = config.get("extra", "allow")

    # Build mapping: data_key -> (field_name, FieldInfo)
    key_to_field = {}
    known_keys = set()

    for name, field in fields.items():
        if field.alias is not None:
            data_key = field.alias
        elif alias_generator:
            data_key = alias_generator(name)
        else:
            data_key = name

        known_keys.add(data_key)
        key_to_field[data_key] = (name, field)

    # Check extra fields
    if extra_mode == "forbid":
        for key in data:
            if key not in known_keys:
                errors.append(
                    {
                        "loc": (key,),
                        "msg": "Extra inputs are not permitted",
                        "type": "extra_forbidden",
                    }
                )

    # Validate each field
    for data_key, (name, field) in key_to_field.items():
        if data_key in data:
            value = data[data_key]
            err = validate_type(value, field.annotation)
            if err:
                errors.append(
                    {
                        "loc": (data_key,),
                        "msg": err,
                        "type": _error_type_for(field.annotation),
                    }
                )
        elif field.is_required():
            errors.append(
                {
                    "loc": (data_key,),
                    "msg": "Field required",
                    "type": "missing",
                }
            )

    return errors


# === Pydantic Compatibility Shim ===

_pydantic_cache: dict = {}


def _get_pydantic_validation_error():
    """Return the pydantic ValidationError class(es) to catch.

    Tries both pydantic.v1 and pydantic so we catch the right exception
    regardless of which API the caller's model was built with.
    """
    errors = []
    if _PydanticV1ValidationError is not None:
        errors.append(_PydanticV1ValidationError)
    if _PydanticV2ValidationError is not None:
        errors.append(_PydanticV2ValidationError)
    if errors:
        return tuple(errors)
    # Should never happen — we only get here if someone passed a pydantic
    # model, which means pydantic is installed.  Fall back to Exception so
    # the except clause still works rather than crashing.
    return (Exception,)  # pragma: no cover


def _is_pydantic_model(cls):
    """Check if cls is a pydantic BaseModel class (v1 or v2) without hard-depending
    on pydantic. Returns False if pydantic is not installed."""
    if not isinstance(cls, type):
        return False
    if issubclass(cls, Schema):
        return False
    if _PydanticV1BaseModel is not None and issubclass(cls, _PydanticV1BaseModel):
        return True
    if _PydanticV2BaseModel is not None and issubclass(cls, _PydanticV2BaseModel):
        return True
    return False


def _pydantic_instance_to_dict(obj):
    """Convert a pydantic model instance to a dict."""
    if hasattr(obj, "model_dump"):
        return obj.model_dump()
    if hasattr(obj, "dict"):
        return obj.dict()
    return obj


def _extract_pydantic_fields(pydantic_cls):
    """Extract field definitions from a pydantic BaseModel class (v1 or v2)."""
    fields = {}

    if hasattr(pydantic_cls, "model_fields"):
        # pydantic v2 interface (check first — v2 also exposes __fields__
        # as a deprecated shim, so we must not fall into the v1 branch)
        for name, pyd_field in pydantic_cls.model_fields.items():
            annotation = pyd_field.annotation
            if pyd_field.is_required():
                default = ...
            else:
                default = pyd_field.default
            alias = pyd_field.alias

            if isinstance(annotation, type) and _is_pydantic_model(annotation):
                annotation = ensure_schema(annotation)
            if default is not ... and hasattr(default, "model_dump"):
                default = _pydantic_instance_to_dict(default)

            field = FieldInfo(default=default, alias=alias)
            field.annotation = annotation
            fields[name] = field

    elif hasattr(pydantic_cls, "__fields__"):
        # pydantic v1 interface
        for name, pyd_field in pydantic_cls.__fields__.items():
            annotation = pyd_field.outer_type_
            # pydantic v1 unwraps Optional[X] into outer_type_=X +
            # allow_none=True.  Re-wrap so our validator sees the Union.
            if getattr(pyd_field, "allow_none", False):
                annotation = Optional[annotation]
            if pyd_field.required:
                default = ...
            else:
                default = pyd_field.default
            alias = pyd_field.alias if pyd_field.alias != name else None

            # Recursively convert nested pydantic model annotations
            if isinstance(annotation, type) and _is_pydantic_model(annotation):
                annotation = ensure_schema(annotation)
            # Convert pydantic instance defaults to dicts
            if default is not ... and hasattr(default, "__fields__"):
                default = _pydantic_instance_to_dict(default)

            field = FieldInfo(default=default, alias=alias)
            field.annotation = annotation
            fields[name] = field

    return fields


def _extract_pydantic_config(pydantic_cls):
    """Extract model config from a pydantic BaseModel class (v1 or v2)."""
    config = {"extra": "allow"}

    if hasattr(pydantic_cls, "__config__"):
        # pydantic v1: inner class Config
        cfg = pydantic_cls.__config__
        extra = getattr(cfg, "extra", "allow")
        # v1 may use an enum (e.g. Extra.forbid); extract the .value
        if hasattr(extra, "value"):
            extra = extra.value  # pyright: ignore[reportAttributeAccessIssue]
        config["extra"] = extra if isinstance(extra, str) else str(extra)
        if hasattr(cfg, "arbitrary_types_allowed"):
            config["arbitrary_types_allowed"] = cfg.arbitrary_types_allowed
    elif hasattr(pydantic_cls, "model_config") and isinstance(
        pydantic_cls.model_config, dict
    ):
        # pydantic v2: dict
        config = dict(pydantic_cls.model_config)

    return config


def ensure_schema(schema_cls):
    """Ensure *schema_cls* satisfies the Schema interface.

    If it already is a Schema subclass, return it unchanged.
    If it is a pydantic BaseModel (v1 or v2), build a thin Schema wrapper
    that exposes the same ``model_fields`` / ``model_config`` and delegates
    ``model_validate`` to the original pydantic class so that pydantic
    validators, strict types, constrained types etc. keep working.

    This allows downstream libraries (spaCy, thinc, …) to keep passing
    pydantic schemas to ``registry.resolve()`` / ``registry.fill()`` even
    though confection itself no longer depends on pydantic.
    """
    if isinstance(schema_cls, type) and issubclass(schema_cls, Schema):
        return schema_cls
    if not _is_pydantic_model(schema_cls):
        return schema_cls

    # Return cached conversion if available
    if schema_cls in _pydantic_cache:
        return _pydantic_cache[schema_cls]

    fields = _extract_pydantic_fields(schema_cls)
    config = _extract_pydantic_config(schema_cls)

    # Build wrapper class that inherits from Schema
    pyd_cls = schema_cls  # capture for closure

    wrapper = type(pydantic_cls_name(schema_cls), (Schema,), {})
    wrapper.model_fields = fields
    wrapper.model_config = config

    # Delegate model_validate to the original pydantic model so that
    # pydantic-level validators / strict types / constraints keep working.
    @classmethod  # type: ignore[misc]
    def _pydantic_model_validate(cls, data):
        # Resolve the concrete pydantic ValidationError class once so the
        # except clause is as narrow as possible.
        pyd_validation_err = _get_pydantic_validation_error()

        try:
            if hasattr(pyd_cls, "model_validate"):
                pyd_cls.model_validate(data)
            elif hasattr(pyd_cls, "parse_obj"):
                pyd_cls.parse_obj(data)
            else:  # pragma: no cover -- all pydantic versions have model_validate or parse_obj
                pyd_cls(**data)  # pragma: no cover
        except pyd_validation_err as e:
            raise ValidationError(
                e.errors()  # pyright: ignore[reportAttributeAccessIssue]
            ) from None
        # Return attribute-accessible result with defaults filled in
        result_data = dict(data)
        for name, field in cls.model_fields.items():
            data_key = field.alias if field.alias is not None else name
            if data_key not in result_data and not field.is_required():
                result_data[data_key] = field.default
        return _ValidatedResult(result_data)

    wrapper.model_validate = _pydantic_model_validate

    _pydantic_cache[schema_cls] = wrapper
    return wrapper


def pydantic_cls_name(cls):
    return getattr(cls, "__name__", "PydanticSchema")
