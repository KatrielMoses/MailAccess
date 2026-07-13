import io
import json
import warnings
from configparser import (
    MAX_INTERPOLATION_DEPTH,
    ConfigParser,
    ExtendedInterpolation,
    InterpolationDepthError,
    InterpolationMissingOptionError,
    InterpolationSyntaxError,
    NoOptionError,
    NoSectionError,
    ParsingError,
)
from typing import Any, Dict, List

from ._constants import SECTION_PREFIX
from ._errors import ConfigValidationError
from .util import VARIABLE_RE, try_dump_json, try_load_json


def parse_config(
    text: str,
    *,
    interpolate: bool = True,
    overrides: Dict[str, Any] = {},
) -> dict[str, Any]:
    """Parse a config string into a nested dict.

    Handles the full pipeline: parse with ConfigParser, validate structure,
    apply overrides, interpret values, and resolve section references.

    Returns the nested dict and whether a second interpolation pass is needed
    (when overrides were applied with interpolation enabled).
    """
    config_parser = _get_configparser(interpolate=interpolate and not overrides)
    try:
        config_parser.read_string(text)
    except ParsingError as e:
        desc = f"Make sure the sections and values are formatted correctly.\n\n{e}"
        raise ConfigValidationError(desc=desc) from None
    errors = _validate_configparser(config_parser)
    if errors:
        raise errors[0]
    errors = _validate_overrides(config_parser, overrides)
    if errors:
        raise errors[0]
    result: dict[str, Any] = {}
    section_parts = [section.split(".") for section in config_parser.sections()]
    # Phase 1: Build the skeleton of nested dicts from section names.
    for parts in section_parts:
        node = result
        for part in parts[:-1]:
            node = node.setdefault(part, {}) if part == "*" else node[part]
        node.setdefault(parts[-1], {})
    # Phase 2: Fill in values, processing breadth-first by section depth.
    for section, values in sorted(
        config_parser.items(), key=lambda x: len(x[0].split("."))
    ):
        if section == "DEFAULT":
            continue
        parts = section.split(".")
        node = result
        for part in parts:
            node = node[part]
        for key in values:
            node[key] = _interpret_value(config_parser.get(section, key))
    # Phase 3: Apply overrides on the nested dict.
    _apply_overrides(result, overrides)
    # Phase 4: Replace section reference placeholders with actual dicts.
    _replace_section_refs(result, result)
    return result


def _apply_overrides(result: dict[str, Any], overrides: Dict[str, Any]) -> None:
    """Apply dot-notation overrides to a nested dict.

    Override paths have already been validated by _validate_overrides.
    """
    for key, value in overrides.items():
        path = key.split(".")
        node = result
        for part in path[:-1]:
            node = node[part]
        node[path[-1]] = value


def serialize_config(
    data: dict[str, Any],
    *,
    interpolate: bool = True,
    inline_paths: frozenset[str] = frozenset(),
) -> str:
    """Serialize a nested config dict to a config string.

    inline_paths: dotted paths whose values should be serialized as inline
        JSON rather than expanded into subsections. For example, if "a.b" is
        in inline_paths, data["a"]["b"] (even if it's a dict) will be
        serialized as ``b = {"key": "value"}`` under [a].
    """
    flattened = _get_configparser(interpolate=interpolate)
    queue: list[tuple[tuple, dict[str, Any]]] = [(tuple(), data)]
    for path, node in queue:
        section_name = ".".join(path)
        is_kwarg = path and path[-1] != "*"
        has_leaves = any(not hasattr(v, "items") for v in node.values())
        if path and has_leaves and not flattened.has_section(section_name):
            # Create sections that have leaf values (including * sections).
            flattened.add_section(section_name)
        elif is_kwarg and not flattened.has_section(section_name):
            flattened.add_section(section_name)
        for key, value in node.items():
            child_path = f"{section_name}.{key}" if section_name else key
            if hasattr(value, "items") and child_path not in inline_paths:
                queue.append((path + (key,), value))
            else:
                flattened.set(section_name, key, try_dump_json(value, node))
    string_io = io.StringIO()
    flattened.write(string_io)
    return string_io.getvalue().strip()


def _get_configparser(interpolate: bool = True) -> ConfigParser:
    config = ConfigParser(interpolation=_CustomInterpolation() if interpolate else None)
    # Preserve case of keys: https://stackoverflow.com/a/1611877/6400719
    config.optionxform = str  # type: ignore
    return config


def _validate_configparser(config_parser: ConfigParser) -> list[ConfigValidationError]:
    """Validate a configparser's structure before interpreting it into a Config.

    Checks that:
    - No values leak into the DEFAULT section (top-level values without a section)
    - All parent sections exist for dotted section names (e.g. "a.b" requires "a")
    - No key in a section conflicts with a child section name
    - No interpolation errors in values
    """
    errors = []
    default_section = config_parser.defaults()
    if default_section:  # pragma: no cover -- configparser raises ParsingError first
        err_title = "Found config values without a top-level section"
        err_msg = "not part of a section"
        err = [{"loc": [k], "msg": err_msg} for k in default_section]
        errors.append(ConfigValidationError(errors=err, title=err_title))
    section_names = set(config_parser.sections())
    for section in config_parser.sections():
        path = section.split(".")
        for i in range(1, len(path)):
            # "*" is an implicit list section — it doesn't need a parent
            # section header, and paths through it are always valid.
            if path[i - 1] == "*":
                continue
            parent = ".".join(path[:i])
            # A parent is valid if it's a declared section OR if the path
            # goes through a "*" component (which is implicitly created).
            if parent not in section_names and "*" not in parent.split("."):
                err_title = (
                    "Error parsing config section. Perhaps a section name is wrong?"
                )
                err = [{"loc": path, "msg": f"Section '{path[i - 1]}' is not defined"}]
                errors.append(ConfigValidationError(errors=err, title=err_title))
                break
        keys = set(config_parser.options(section))
        for other in section_names:
            if other.startswith(section + "."):
                child = other[len(section) + 1 :].split(".")[0]
                if child in keys:
                    err = [{"loc": other.split("."), "msg": "found conflicting values"}]
                    errors.append(ConfigValidationError(errors=err))
    return errors


def _validate_overrides(
    config_parser: ConfigParser, overrides: dict[str, Any]
) -> list[ConfigValidationError]:
    errors = []
    err_title = "Error parsing config overrides"
    for key in overrides:
        err_msg = "not a section value that can be overridden"
        err = [{"loc": key.split("."), "msg": err_msg}]
        if "." not in key:
            errors.append(ConfigValidationError(errors=err, title=err_title))
            continue
        section, _ = key.rsplit(".", 1)
        # Check for section and accept if option not in config[section]
        if section not in config_parser:
            errors.append(ConfigValidationError(errors=err, title=err_title))
        # TODO: Are we supposed to chek for the *option*?
    return errors


def _interpret_value(value: Any) -> Any:
    """Interpret a single config value."""
    result = try_load_json(value)
    # If value is a string and it contains a variable, use original value
    # (not interpreted string, which could lead to double quotes:
    # ${x.y} -> "${x.y}" -> "'${x.y}'"). Make sure to check it's a string,
    # so we're not keeping lists as strings.
    # NOTE: This currently can't handle uninterpolated values like [${x.y}]!
    if isinstance(result, str) and VARIABLE_RE.search(value):
        result = value
    return result


def _replace_section_refs(
    root: dict[str, Any], node: dict[str, Any], parent: str = ""
) -> None:
    """Replace section reference placeholders with actual dicts."""
    for key, value in node.items():
        key_parent = f"{parent}.{key}".strip(".")
        if isinstance(value, dict):
            _replace_section_refs(root, value, parent=key_parent)
        elif isinstance(value, list):
            node[key] = [_get_section_ref(root, v, parent=[parent, key]) for v in value]
        else:
            node[key] = _get_section_ref(root, value, parent=[parent, key])


def _get_section_ref(
    root: Dict[str, Any], value: Any, *, parent: List[str] = []
) -> Any:
    """Resolve a single section reference placeholder, or return value as-is."""
    if isinstance(value, str) and value.startswith(
        f'"{SECTION_PREFIX}'
    ):  # pragma: no cover
        value = try_load_json(value)  # pragma: no cover
    if (
        isinstance(value, str)
        and value.startswith(SECTION_PREFIX)
        and value != SECTION_PREFIX
    ):
        parts = value.replace(SECTION_PREFIX, "", 1).split(".")
        result = root
        for item in parts:
            result = result[item]
        return result
    elif isinstance(value, str) and SECTION_PREFIX in value and value != SECTION_PREFIX:
        err_desc = (
            "Can't reference whole sections or return values of function "
            "blocks inside a string or list\n\nYou can change your variable to "
            "reference a value instead. Keep in mind that it's not "
            "possible to interpolate the return value of a registered "
            "function, since variables are interpolated when the config "
            "is loaded, and registered functions are resolved afterwards."
        )
        err = [{"loc": parent, "msg": "uses section variable in string or list"}]
        raise ConfigValidationError(errors=err, desc=err_desc)
    return value


class _CustomInterpolation(ExtendedInterpolation):
    def before_read(  # pyright: ignore[reportIncompatibleMethodOverride]
        self, parser: ConfigParser, section: str, option: str, value: str
    ) -> str:
        # Warn about single-quoted strings (common mistake)
        if value and value[0] == value[-1] == "'":
            warnings.warn(
                f"The value [{value}] seems to be single-quoted, but values "
                "use JSON formatting, which requires double quotes."
            )
        return super().before_read(parser, section, option, value)

    def _coerce_for_string_context(self, v: str) -> str:
        """Coerce a raw config value for use in a compound string expression."""
        # Don't coerce section references - they need to stay quoted for JSON
        if SECTION_PREFIX in v:
            return v
        try:
            parsed = json.loads(v)
        except json.JSONDecodeError:
            return v  # Not valid JSON, already a plain string
        if isinstance(parsed, str):
            return parsed  # Unwrap JSON string
        # Use json.dumps() for non-strings, escaping inner quotes so they don't
        # conflict with the outer JSON string quotes
        return json.dumps(parsed).replace('"', '\\"')

    def before_get(  # pyright: ignore[reportIncompatibleMethodOverride]
        self,
        parser: ConfigParser,
        section: str,
        option: str,
        value: str,
        defaults: Dict[str, str],
    ) -> str:
        # Mostly copy-pasted from the built-in configparser implementation.
        # The interpolate() method resolves ${...} references and appends pieces
        # to L. For a bare reference like ${x}, L has one element. For compound
        # expressions like "hello ${x}", L has multiple pieces that we join.
        # Compound results stay as strings (coerced via _coerce_for_string_context),
        # while bare references keep their JSON type for _interpret_value to parse.
        L: List[str] = []
        self.interpolate(parser, option, L, value, section, defaults, 1)
        if len(L) == 1:
            return L[0]
        return "".join(self._coerce_for_string_context(piece) for piece in L)

    def interpolate(
        self,
        parser: ConfigParser,
        option: str,
        accum: List[str],
        rest: str,
        section: str,
        map: Dict[str, str],
        depth: int,
    ) -> None:
        """Resolve variable references like ${foo.bar}"""
        # Mostly copy-pasted from the built-in configparser implementation.
        # We need to overwrite this method so we can add special handling for
        # block references :( All values produced here should be strings –
        # we need to wait until the whole config is interpreted anyways so
        # filling in incomplete values here is pointless. All we need is the
        # section reference so we can fetch it later.
        rawval = parser.get(section, option, raw=True, fallback=rest)
        if depth > MAX_INTERPOLATION_DEPTH:
            raise InterpolationDepthError(option, section, rawval)
        while rest:
            p = rest.find("$")
            if p < 0:
                accum.append(rest)
                return
            if p > 0:
                accum.append(rest[:p])
                rest = rest[p:]
            # p is no longer used
            c = rest[1:2]
            if c == "$":
                accum.append("$")
                rest = rest[2:]
            elif c == "{":
                # We want to treat both ${a:b} and ${a.b} the same
                m = self._KEYCRE.match(rest)  # type: ignore[attr-defined]
                if m is None:
                    err = f"bad interpolation variable reference {rest}"
                    raise InterpolationSyntaxError(option, section, err)
                orig_var = m.group(1)
                path = orig_var.replace(":", ".").rsplit(".", 1)
                rest = rest[m.end() :]
                sect = section
                opt = option
                try:
                    if len(path) == 1:
                        opt = parser.optionxform(path[0])
                        # Check if the variable references a section rather
                        # than a key in the current section.  If the key
                        # exists in the current map but its raw value is the
                        # same interpolation variable (self-reference), or if
                        # the key doesn't exist in the map, treat it as a
                        # section reference.
                        is_section_ref = opt not in map
                        if not is_section_ref:
                            raw = map[opt]
                            is_section_ref = raw.strip() == rawval.strip()
                        if not is_section_ref:
                            v = map[opt]
                        else:
                            # We have block reference, store it as a special key
                            section_name = parser[parser.optionxform(path[0])].name
                            v = self._get_section_name(section_name)
                    elif len(path) == 2:
                        sect = path[0]
                        opt = parser.optionxform(path[1])
                        fallback = "__FALLBACK__"
                        v = parser.get(sect, opt, raw=True, fallback=fallback)
                        # If a variable doesn't exist, try again and treat the
                        # reference as a section
                        if v == fallback:
                            v = self._get_section_name(parser[f"{sect}.{opt}"].name)
                    else:  # pragma: no cover
                        # Dead code: rsplit(".", 1) produces at most 2 elements
                        err = f"More than one ':' found: {rest}"
                        raise InterpolationSyntaxError(option, section, err)
                except (KeyError, NoSectionError, NoOptionError):
                    raise InterpolationMissingOptionError(
                        option, section, rawval, orig_var
                    ) from None
                if "$" in v:
                    new_map = dict(parser.items(sect, raw=True))
                    self.interpolate(parser, opt, accum, v, sect, new_map, depth + 1)
                else:
                    accum.append(v)
            else:
                err = "'$' must be followed by '$' or '{', found: %r" % (rest,)
                raise InterpolationSyntaxError(option, section, err)

    def _get_section_name(self, name: str) -> str:
        """Generate the name of a section. Note that we use a quoted string here
        so we can use section references within lists and load the list as
        JSON. Since section references can't be used within strings, we don't
        need the quoted vs. unquoted distinction like we do for variables.

        Examples (assuming section = {"foo": 1}):
            - value: ${section.foo} -> value: 1
            - value: "hello ${section.foo}" -> value: "hello 1"
            - value: ${section} -> value: {"foo": 1}
            - value: "${section}" -> value: {"foo": 1}
            - value: "hello ${section}" -> invalid
        """
        return f'"{SECTION_PREFIX}{name}"'


__all__ = ["parse_config", "serialize_config"]
