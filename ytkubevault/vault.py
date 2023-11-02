import base64
import datetime
from functools import wraps
import logging
import os
from typing import Any, Callable, Optional, Union

import hvac
from hvac import api
from hvac.api.auth_methods.kubernetes import DEFAULT_MOUNT_POINT as LOGIN_DEFAULT_MOUNT_POINT
from hvac.api.secrets_engines.kv_v2 import DEFAULT_MOUNT_POINT as SECRET_DEFAULT_MOUNT_POINT
from hvac.api.secrets_engines.transit import DEFAULT_MOUNT_POINT as TRANSIT_DEFAULT_MOUNT_POINT

logger = logging.getLogger(__name__)

try:
    # This is for fetching the service account token from outside the cluster
    import kubernetes
except ImportError:
    logger.info("No kubernetes package installed")

VAULT_ENABLED: bool = os.getenv("VAULT_ENABLED", default="false").strip().lower() == "true"
VAULT_ROLE: Optional[str] = os.getenv("VAULT_ROLE", default=None)
VAULT_URL: Optional[str] = os.getenv("VAULT_URL", default=None)
VAULT_SECRETS_PATH: Optional[str] = os.getenv("VAULT_SECRETS_PATH", default=None)
VAULT_LOGIN_MOUNT_POINT: str = os.getenv("VAULT_LOGIN_MOUNT_POINT", default=LOGIN_DEFAULT_MOUNT_POINT)
VAULT_SECRET_MOUNT_POINT: str = os.getenv("VAULT_SECRET_MOUNT_POINT", default=SECRET_DEFAULT_MOUNT_POINT)
VAULT_TRANSIT_MOUNT_POINT: str = os.getenv("VAULT_TRANSIT_MOUNT_POINT", default=TRANSIT_DEFAULT_MOUNT_POINT)

# Development from outside the cluster
VAULT_DEV_REMOTE_MODE: bool = os.getenv("VAULT_DEV_REMOTE_MODE", default="false").strip().lower() == "true"
VAULT_DEV_REMOTE_CLUSTER: Optional[str] = os.getenv("VAULT_DEV_REMOTE_CLUSTER", default=None)
VAULT_DEV_REMOTE_NAMESPACE: Optional[str] = os.getenv("VAULT_DEV_REMOTE_NAMESPACE", default="default")
VAULT_DEV_REMOTE_SERVICE_ACCOUNT: Optional[str] = os.getenv("VAULT_DEV_REMOTE_SERVICE_ACCOUNT", default=None)

_VAULT_SECRETS = None
_client = None


def _re_login_if_token_about_to_expire(method):
    @wraps(method)
    def _impl(self, *method_args, **method_kwargs):
        if self.token_is_about_to_expire():
            self.login()
        return method(self, *method_args, **method_kwargs)
    return _impl


class VaultClient:
    def __init__(self, vault_url: str = VAULT_URL, role: str = VAULT_ROLE, token_expire_buffer_period_min: int = 10,
                 login_mount_point: str = VAULT_LOGIN_MOUNT_POINT,
                 secret_mount_point: str = VAULT_SECRET_MOUNT_POINT,
                 transit_mount_point: str = VAULT_TRANSIT_MOUNT_POINT):
        self._client = hvac.Client(url=vault_url)
        self._role = role
        self._last_login_time = None
        self._lease_duration = 0  # seconds
        self._token_expires_at = None
        self._service_account_token = None
        self._token_expire_buffer_period_min = token_expire_buffer_period_min    # minutes
        self._login_mount_point = login_mount_point
        self._secret_mount_point = secret_mount_point
        self._transit_mount_point = transit_mount_point

    def _read_service_account_token(self) -> None:
        with open("/var/run/secrets/kubernetes.io/serviceaccount/token") as f:
            jwt = f.read()
        self._service_account_token = jwt

    def _read_service_account_token_from_outside_cluster(self) -> None:
        v1 = kubernetes.client.CoreV1Api(
            api_client=kubernetes.config.new_client_from_config(context=VAULT_DEV_REMOTE_CLUSTER)
        )
        sa = v1.read_namespaced_service_account(name=VAULT_DEV_REMOTE_SERVICE_ACCOUNT,
                                                namespace=VAULT_DEV_REMOTE_NAMESPACE)
        sa_secret_name = sa.secrets[0].name
        sa_secret = v1.read_namespaced_secret(name=sa_secret_name, namespace=VAULT_DEV_REMOTE_NAMESPACE)
        jwt = base64.b64decode(sa_secret.data["token"]).decode("utf-8")
        self._service_account_token = jwt

    def login(self) -> None:
        if not self._service_account_token:
            if VAULT_DEV_REMOTE_MODE:
                self._read_service_account_token_from_outside_cluster()
            else:
                self._read_service_account_token()
        auth_data = api.auth_methods.Kubernetes(
            adapter=self._client.adapter
        ).login(role=self._role, jwt=self._service_account_token, mount_point=self._login_mount_point)["auth"]
        self._last_login_time = datetime.datetime.now(tz=datetime.timezone.utc)
        self._lease_duration = auth_data["lease_duration"]
        self._token_expires_at = self._last_login_time + datetime.timedelta(seconds=self._lease_duration)
        self._client.token = auth_data["client_token"]

    @_re_login_if_token_about_to_expire
    def read_secret_version(self, path: str,
                            version: Optional[int] = None,
                            mount_point: Optional[str] = None,
                            **kwargs) -> dict:
        _mount_point = mount_point if mount_point else self._secret_mount_point
        return self._client.secrets.kv.v2.read_secret_version(path, version, mount_point=_mount_point, **kwargs)

    @_re_login_if_token_about_to_expire
    def create_or_update_secrets(self, path: str,
                                 secrets: dict[str, str],
                                 mount_point: Optional[str] = None,
                                 **kwargs) -> None:
        _mount_point = mount_point if mount_point else self._secret_mount_point
        self._client.secrets.kv.v2.create_or_update_secret(path=path,
                                                           secret=secrets,
                                                           mount_point=_mount_point,
                                                           **kwargs)

    @_re_login_if_token_about_to_expire
    def encrypt(self, encrypt_key: str, plaintext: str, mount_point: Optional[str] = None) -> str:
        _mount_point = mount_point if mount_point else self._transit_mount_point
        try:
            ciphertext = self._client.secrets.transit.encrypt_data(name=encrypt_key,
                                                                   plaintext=plaintext,
                                                                   mount_point=_mount_point)
        except Exception as e:
            raise VaultException(f"Failed to encrypt data: {e}", e)
        return ciphertext["data"]["ciphertext"]

    @_re_login_if_token_about_to_expire
    def decrypt(self, decrypt_key: str, ciphertext: str, mount_point: Optional[str] = None) -> str:
        _mount_point = mount_point if mount_point else self._transit_mount_point
        try:
            decrypt_data_response = self._client.secrets.transit.decrypt_data(name=decrypt_key,
                                                                              ciphertext=ciphertext,
                                                                              mount_point=_mount_point)
        except Exception as e:
            raise VaultException(f"Failed to decrypt data: {e}", e)
        return decrypt_data_response["data"]["plaintext"]

    def token_is_about_to_expire(self) -> bool:
        if not self._token_expires_at:
            return False
        return (datetime.datetime.now(tz=datetime.timezone.utc)
                + datetime.timedelta(minutes=self._token_expire_buffer_period_min) >= self._token_expires_at)


class VaultException(Exception):
    pass


def _vault_login():
    global _client
    if _client:
        return _client
    try:
        vault_client = VaultClient()
        vault_client.login()

    except Exception as e:
        raise VaultException(f"Failed to log into the vault:  {e}", e)
    else:
        _client = vault_client
        return _client


def _get_all_vault_secrets(client=None, path=None):
    return client.read_secret_version(path)


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


def encrypt_or_default(plaintext: Union[bytes, str],
                       encrypt_key: str,
                       default: Optional[Callable[[str], str]] = None) -> str:
    """Encrypt text with Vault Transit Secret Engine.

    :param plaintext: The text or bytes to be encrypted
    :param encrypt_key: The encryption key defined in Vault
    :param default: The default encrypter function to be called if Vault is not enabled. If `None` is provided,
    then the encrypter is the identity function.
    """
    global _client
    if not _client:
        encrypter = default if default else lambda x: x
        return encrypter(plaintext)
    if isinstance(plaintext, str):
        byte_data = plaintext.encode("utf-8")
    else:
        byte_data = plaintext
    encoded_text = base64.b64encode(byte_data)
    try:
        ciphertext = _client.encrypt(encrypt_key=encrypt_key, plaintext=str(encoded_text, "utf-8"))
    except Exception as e:
        raise VaultException(f"Failed to encrypt data: {e}", e)
    return ciphertext


def decrypt_or_default(ciphertext: str,
                       decrypt_key: str,
                       default: Optional[Callable[[str], str]] = None,
                       return_b64decoded: bool = True) -> str:
    """Decrypt text with Vault Transit Secret Engine.

    :param ciphertext: The text to be decrypted
    :param decrypt_key: The decryption key defined in Vault
    :param default: The default decrypter function to be called if Vault is not enabled. If `None` is provided,
    then the decrypter is the identity function.
    :param return_b64decoded: Whether to return the plaintext with base64 decoded. By default, this is set to `False`.
    """
    global _client
    if not _client:
        decrypter = default if default else lambda x: x
        return decrypter(ciphertext)
    try:
        plaintext_encoded_str = _client.decrypt(decrypt_key=decrypt_key, ciphertext=ciphertext)
    except Exception as e:
        raise VaultException(f"Failed to decrypt data: {e}", e)
    if not return_b64decoded:
        return plaintext_encoded_str
    return str(base64.b64decode(plaintext_encoded_str), "utf-8")


def create_or_update_secret(key: str, secret: str):
    """Create or update a secret in vault. If Vault not enabled, then set or update
    the environment variable.
    :param key: The secret key
    :param secret: The secret value

    Note: Since the global variable `_VAULT_SECRETS` is being updated, this code
    is not multithread-safe.
    """
    global _client, _VAULT_SECRETS
    if _client:
        if not _VAULT_SECRETS:
            _VAULT_SECRETS = _get_all_vault_secrets(client=_client, path=VAULT_SECRETS_PATH)
        try:
            _VAULT_SECRETS[key] = secret
            _client.create_or_update_secrets(path=VAULT_SECRETS_PATH, secrets=_VAULT_SECRETS)
        except Exception as e:
            raise VaultException(f"Failed to update secret: {e}", e)
    else:
        os.environ[key] = secret


# Execute the first time this file is imported
# If initialisation fails, it will fail immediately
_initialise_if_needed()
