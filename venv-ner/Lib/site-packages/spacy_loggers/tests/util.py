from typing import Tuple

from spacy import Language
from spacy.util import (
    load_model_from_config,
    registry,
    load_config_from_str,
)
from spacy.schemas import ConfigSchemaTraining

from spacy_loggers.util import LoggerT


def load_logger_from_config(config_str: str) -> Tuple[LoggerT, Language]:
    config = load_config_from_str(config_str)
    nlp = load_model_from_config(config, auto_fill=True)
    T = registry.resolve(
        nlp.config.interpolate()["training"], schema=ConfigSchemaTraining
    )
    return T["logger"], nlp
