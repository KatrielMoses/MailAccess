from __future__ import annotations

import copy
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

if sys.version_info >= (3, 11):
    from typing import Self
else:
    from typing_extensions import Self

from ._errors import ConfectionError, ConfigValidationError
from ._parser import parse_config, serialize_config
from .validation import ValidationError, ensure_schema


class Config(dict):
    # TODO: Improve doc string
    """Dict subclass to save TOML-style configuration format from/to string, file
    or bytes.
    """

    is_interpolated: bool

    def __init__(
        self,
        data: Optional[Union[Dict[str, Any], "Config"]] = None,
        *,
        is_interpolated: Optional[bool] = None,
        section_order: Optional[List[str]] = None,
    ) -> None:
        """Initialize a new Config object with optional data."""
        dict.__init__(self)
        if data is None:
            data = {}
        if not isinstance(data, (dict, Config)):
            raise ConfectionError(
                f"Can't initialize Config with data. Expected dict or "
                f"Config but got: {type(data)}"
            )
        # Whether the config has been interpolated. We can use this to check
        # whether we need to interpolate again when it's resolved. We assume
        # that a config is interpolated by default.
        if is_interpolated is not None:
            self.is_interpolated = is_interpolated
        elif isinstance(data, Config):
            self.is_interpolated = data.is_interpolated
        else:
            self.is_interpolated = True
        if section_order is not None:
            self.section_order = section_order
        elif isinstance(data, Config):
            self.section_order = data.section_order
        else:
            self.section_order = []
        # Update with data
        self.update(data)

    def interpolate(self) -> Self:
        """Interpolate (resolve var references) a config.

        Returns a copy of the object.
        """
        # This is currently the most effective way because we need our custom
        # to_str logic to run in order to re-serialize the values so we can
        # interpolate them again. ConfigParser.read_dict will just call str()
        # on all values, which isn't enough.
        return type(self)().from_str(self.to_str())

    def copy(self) -> Self:
        """Deepcopy the config."""
        config = copy.deepcopy(self)
        return type(self)(
            config,
            is_interpolated=self.is_interpolated,
            section_order=self.section_order,
        )

    def merge(
        self, updates: Union[Dict[str, Any], "Config"], remove_extra: bool = False
    ) -> Self:
        """Deep merge the config with updates, using current as defaults."""
        defaults = self.copy()
        updates = Config(updates).copy()
        merged = deep_merge_configs(updates, defaults, remove_extra=remove_extra)
        return type(self)(
            merged,
            is_interpolated=defaults.is_interpolated and updates.is_interpolated,
            section_order=defaults.section_order,
        )

    def validate(self, schema) -> Self:
        """Validate the config against a schema. Raises ConfigValidationError
        if validation fails.
        """
        schema = ensure_schema(schema)
        _validate_recursive(dict(self), schema, self)
        return self

    def fill_defaults(self, schema) -> Self:
        """Fill in missing values from schema defaults and remove extra
        fields if the schema forbids them. Modifies in place and returns self.
        """
        schema = ensure_schema(schema)
        extra = schema.model_config.get("extra", "allow")
        # Fill defaults
        for name, field in schema.model_fields.items():
            if name not in self and not field.is_required():
                self[name] = field.default
            elif name in self and isinstance(self[name], dict):
                field_schema = field.annotation
                if isinstance(field_schema, type) and hasattr(
                    field_schema, "model_fields"
                ):
                    sub_schema = ensure_schema(field_schema)
                    _fill_defaults_recursive(self[name], sub_schema)
        # Strip extras
        if extra == "forbid":
            known = set(schema.model_fields.keys())
            for key in list(self.keys()):
                if key not in known:
                    del self[key]
        return self

    def from_str(
        self,
        text: str,
        *,
        interpolate: bool = True,
        overrides: Dict[str, Any] = {},
        schema=None,
    ) -> Self:
        """Load the config from a string."""
        self.clear()
        self.update(parse_config(text, interpolate=interpolate, overrides=overrides))
        if overrides and interpolate:
            # Re-interpolate now that overrides are applied. The recursive
            # from_str call will have no overrides, so this doesn't loop.
            self = self.interpolate()
        self.is_interpolated = interpolate
        if schema is not None:
            self.fill_defaults(schema)
            self.validate(schema)
        return self

    def to_str(self, *, interpolate: bool = True) -> str:
        """Write the config to a string."""
        return serialize_config(self, interpolate=interpolate)

    def to_bytes(self, *, interpolate: bool = True) -> bytes:
        """Serialize the config to a byte string."""
        return self.to_str(interpolate=interpolate).encode("utf8")

    def from_bytes(
        self,
        bytes_data: bytes,
        *,
        interpolate: bool = True,
        overrides: Dict[str, Any] = {},
    ) -> Self:
        """Load the config from a byte string."""
        return self.from_str(
            bytes_data.decode("utf8"), interpolate=interpolate, overrides=overrides
        )

    def to_disk(self, path: Union[str, Path], *, interpolate: bool = True) -> None:
        """Serialize the config to a file."""
        path = Path(path) if isinstance(path, str) else path
        with path.open("w", encoding="utf8") as file_:
            file_.write(self.to_str(interpolate=interpolate))

    def from_disk(
        self,
        path: Union[str, Path],
        *,
        interpolate: bool = True,
        overrides: Dict[str, Any] = {},
    ) -> Self:
        """Load config from a file."""
        path = Path(path) if isinstance(path, str) else path
        with path.open("r", encoding="utf8") as file_:
            text = file_.read()
        return self.from_str(text, interpolate=interpolate, overrides=overrides)


def _fill_defaults_recursive(data, schema):
    """Fill defaults and strip extras recursively for nested schemas."""
    extra = schema.model_config.get("extra", "allow")
    for name, field in schema.model_fields.items():
        if name not in data and not field.is_required():
            data[name] = field.default
        elif name in data and isinstance(data[name], dict):
            field_schema = field.annotation
            if isinstance(field_schema, type) and hasattr(field_schema, "model_fields"):
                _fill_defaults_recursive(data[name], ensure_schema(field_schema))
    if extra == "forbid":
        known = set(schema.model_fields.keys())
        for key in list(data.keys()):
            if key not in known:
                del data[key]


def _validate_recursive(data, schema, config, parent=""):
    """Validate data against a schema, recursing into nested schemas."""
    try:
        schema.model_validate(data)
    except ValidationError as e:
        section = f" in [{parent}]" if parent else ""
        raise ConfigValidationError(
            config=config,
            errors=e.errors(),
            title=f"Config validation error{section}",
        ) from None
    # Recurse into fields that are themselves schemas
    for name, field in schema.model_fields.items():
        annotation = field.annotation
        if (
            isinstance(annotation, type)
            and hasattr(annotation, "model_validate")
            and name in data
            and isinstance(data[name], dict)
        ):
            child_parent = f"{parent}.{name}" if parent else name
            _validate_recursive(data[name], annotation, config, parent=child_parent)


def deep_merge_configs(
    config: Union[Dict[str, Any], Config],
    defaults: Union[Dict[str, Any], Config],
    *,
    remove_extra: bool = False,
) -> Union[Dict[str, Any], Config]:
    """Deep merge two configs."""
    if remove_extra:
        # Filter out values in the original config that are not in defaults
        keys = list(config.keys())
        for key in keys:
            if key not in defaults:
                del config[key]
    for key, value in defaults.items():
        if isinstance(value, dict):
            node = config.setdefault(key, {})
            if not isinstance(node, dict):
                continue
            value_promises = [k for k in value if k.startswith("@")]
            value_promise = value_promises[0] if value_promises else None
            node_promises = [k for k in node if k.startswith("@")] if node else []
            node_promise = node_promises[0] if node_promises else None
            # We only update the block from defaults if it refers to the same
            # registered function
            if (
                value_promise
                and node_promise
                and (
                    value_promise in node
                    and node[value_promise] != value[value_promise]
                )
            ):
                continue
            if node_promise and (
                node_promise not in value or node[node_promise] != value[node_promise]
            ):
                continue
            defaults = deep_merge_configs(node, value, remove_extra=remove_extra)
        elif key not in config:
            config[key] = value
    return config
