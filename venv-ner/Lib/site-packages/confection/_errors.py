from typing import Optional


class ConfectionError(ValueError): ...


class ConfigValidationError(ConfectionError):
    def __init__(
        self,
        *,
        config=None,
        errors=None,
        title: Optional[str] = "Config validation error",
        desc: Optional[str] = None,
        parent: Optional[str] = None,
        show_config: bool = True,
    ) -> None:
        """Custom error for validating configs.

        config (Union[Config, Dict[str, Dict[str, Any]], str]): The
            config the validation error refers to.
        errors (Union[Sequence[Mapping[str, Any]], Iterable[Dict[str, Any]]]):
            A list of errors as dicts with keys "loc" (list of strings
            describing the path of the value), "msg" (validation message
            to show) and optional "type" (mostly internals).
            Same format as produced by pydantic's validation error (e.errors()).
        title (str): The error title.
        desc (str): Optional error description, displayed below the title.
        parent (str): Optional parent to use as prefix for all error locations.
            For example, parent "element" will result in "element -> a -> b".
        show_config (bool): Whether to print the whole config with the error.

        ATTRIBUTES:
        config (Union[Config, Dict[str, Dict[str, Any]], str]): The config.
        errors (Iterable[Dict[str, Any]]): The errors.
        error_types (Set[str]): All "type" values defined in the errors, if
            available. This is most relevant for the pydantic errors that define
            types like "type_error.integer". This attribute makes it easy to
            check if a config validation error includes errors of a certain
            type, e.g. to log additional information or custom help messages.
        title (str): The title.
        desc (str): The description.
        parent (str): The parent.
        show_config (bool): Whether to show the config.
        text (str): The formatted error text.
        """
        self.config = config
        self.errors = errors
        self.title = title
        self.desc = desc
        self.parent = parent
        self.show_config = show_config
        self.error_types = set()
        if self.errors:
            for error in self.errors:
                err_type = error.get("type")
                if err_type:
                    self.error_types.add(err_type)
        self.text = self._format()
        ValueError.__init__(self, self.text)

    @classmethod
    def from_error(
        cls,
        err: "ConfigValidationError",
        title: Optional[str] = None,
        desc: Optional[str] = None,
        parent: Optional[str] = None,
        show_config: Optional[bool] = None,
    ) -> "ConfigValidationError":
        """Create a new ConfigValidationError based on an existing error, e.g.
        to re-raise it with different settings. If no overrides are provided,
        the values from the original error are used.

        err (ConfigValidationError): The original error.
        title (str): Overwrite error title.
        desc (str): Overwrite error description.
        parent (str): Overwrite error parent.
        show_config (bool): Overwrite whether to show config.
        RETURNS (ConfigValidationError): The new error.
        """
        return cls(
            config=err.config,
            errors=err.errors,
            title=title if title is not None else err.title,
            desc=desc if desc is not None else err.desc,
            parent=parent if parent is not None else err.parent,
            show_config=show_config if show_config is not None else err.show_config,
        )

    def _format(self) -> str:
        """Format the error message."""
        loc_divider = "->"
        data = []
        if self.errors:
            for error in self.errors:
                err_loc = f" {loc_divider} ".join(
                    [str(p) for p in error.get("loc", [])]
                )
                if self.parent:
                    err_loc = f"{self.parent} {loc_divider} {err_loc}"
                data.append((err_loc, error.get("msg")))
        result = []
        if self.title:
            result.append(self.title)
        if self.desc:
            result.append(self.desc)
        if data:
            result.append("\n".join([f"{entry[0]}\t{entry[1]}" for entry in data]))
        if self.config and self.show_config:
            result.append(f"{self.config}")
        return "\n\n" + "\n".join(result)
