import re

# Regex to detect whether a value contains a variable
VARIABLE_RE = re.compile(r"\$\{[\w\.:]+\}")

# Internal prefix used to mark section references for custom interpolation
SECTION_PREFIX = "__SECTION__:"

# Field used for positional arguments, e.g. [section.*.xyz]. The alias is
# required for the schema (shouldn't clash with user-defined arg names)
ARGS_FIELD = "*"
ARGS_FIELD_ALIAS = "VARIABLE_POSITIONAL_ARGS"

# Aliases for fields that would otherwise shadow pydantic attributes. Can be any
# string, so we're using name + space so it looks the same in error messages etc.
RESERVED_FIELDS = {
    "validate": "validate\u0020",
    "model_config": "model_config\u0020",
    "model_validate": "model_validate\u2020",
    "model_fields": "model_fields\u2020",
}
RESERVED_FIELDS_REVERSE = {v: k for k, v in RESERVED_FIELDS.items()}
