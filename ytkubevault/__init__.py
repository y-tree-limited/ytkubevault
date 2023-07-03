__version__ = "0.2.0"
import logging
from logging import NullHandler

from .vault import (
    encrypt_or_default,
    decrypt_or_default,
    get_secret_or_env,
    get_vault_secret_keys,
    is_vault_initialised,
    VaultClient
)

__all__ = [
    "get_secret_or_env",
    "get_vault_secret_keys",
    "is_vault_initialised",
    "encrypt_or_default",
    "decrypt_or_default",
    "VaultClient"
]

logging.getLogger(__name__).addHandler(NullHandler())
