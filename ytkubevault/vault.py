import logging
import os
from typing import Any, Optional

import hvac

VAULT_ENABLED: bool = os.getenv("VAULT_ENABLED", default="false").strip().lower() == "true"
VAULT_ROLE: Optional[str] = os.getenv("VAULT_ROLE", default=None)
VAULT_URL: Optional[str] = os.getenv("VAULT_URL", default=None)
VAULT_SECRETS_PATH: Optional[str] = os.getenv("VAULT_SECRETS_PATH", default=None)

_VAULT_SECRETS = None

logger = logging.getLogger(__name__)


class VaultException(Exception):
    pass


def _vault_login():
    try:
        with open("/var/run/secrets/kubernetes.io/serviceaccount/token") as f:
            jwt = f.read()
        client = hvac.Client(url=VAULT_URL)
        client.auth_kubernetes(role=VAULT_ROLE, jwt=jwt)

        return client

    except Exception as e:
        raise VaultException(f"Failed to log into the vault:  {e}", e)


def _get_all_vault_secrets(client=None, path=None):
    return client.secrets.kv.v2.read_secret_version(
        path=path,
    )


def _initialise_if_needed():
    try:
        if VAULT_ENABLED:
            global _VAULT_SECRETS

            if _VAULT_SECRETS is None:
                _VAULT_SECRETS = _get_all_vault_secrets(
                    client=_vault_login(),
                    path=VAULT_SECRETS_PATH,
                )
    except Exception as e:
        raise VaultException(f"Failed to initialise the Vault:  {e}", e)


def _get_vault() -> Optional[dict[str, Any]]:
    global _VAULT_SECRETS
    return _VAULT_SECRETS


def _get_vault_secret(key: str, default: Optional[str] = None) -> Optional[str]:
    value: Optional[str] = None

    if VAULT_ENABLED:
        vault = _get_vault()
        value = vault['data']['data'].get(key)

    return value if value is not None else default


def _get_env_var(key: str, default: Optional[str] = None) -> Optional[str]:
    return os.environ.get(key, default=default)


def get_secret_or_env(key: str, default: Optional[str] = None) -> Optional[str]:
    """Get the secret value from Vault or as an environment variable.

    :param key: The secret name
    :param default: The default value for the secret if the given `key` is nowhere to be found
    :return: The secret value in `str`

    The function first tries to fetch the secret value with the given `key` from
    the Vault. If that didn't succeed, it will turn to read the value from the environment.
    If there is no such an environment variable, the `default` value will be returned.
    """

    value: Optional[str] = None

    try:
        value = _get_vault_secret(key)
    except Exception as e:
        logger.warning(f"Cannot read from Vault, {e}")

    return value if value is not None else os.environ.get(key, default=default)


# Good for debugging whether the vault is running
def is_vault_initialised() -> bool:
    return _get_vault() is not None


# Good for debugging whether the vault is pulling in the expected secrets
def get_vault_secret_keys() -> list[str]:
    try:
        vault = _get_vault()
        return list(vault["data"]["data"].keys())
    except Exception:
        return []


# Execute the first time this file is imported
# If initialisation fails, it will fail immediately
_initialise_if_needed()
