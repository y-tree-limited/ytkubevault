__version__ = "0.0.1"
import logging
from logging import NullHandler

from .vault import get_secret_or_env, get_vault_secret_keys, is_vault_initialised

__all__ = [
    "get_secret_or_env",
    "get_vault_secret_keys",
    "is_vault_initialised"
]

logging.getLogger(__name__).addHandler(NullHandler())
