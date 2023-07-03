# ytkubevault
ytkubevault is a light wrapper of abilities to read secrets
from HashiCorp Vault running in Kubernetes.

When the microservice needs to fetch the secret value from 
Vault, it has to read a token from its containing pod first. 
Then this token is used to communicate with Vault in order to 
obtain a second token. Your service uses the second token to 
get the secrets. ytkubevault simplifies this process with one 
function `get_secret_or_env(key: default:)`, which first tries
to obtain the secret from Vault, and if that didn't succeed,
reads it from the environment. A default value can be provided 
as the last resort.

This is especially convenient when you are developing locally, 
or the application is being built in a CI/CD pipeline where 
the first token is not available.

## Install
```shell
pip install ytkubevault
```

## Usage
First define the following environment variables:
* VAULT_ENABLED
* VAULT_ROLE
* VAULT_URL
* VAULT_SECRETS_PATH

By default, `VAULT_ENABLED` is `"false"`. To enable reading from Vault,
set it to be `"true"`, case-insensitive. And then,

```python
from ytkubevault import get_secret_or_env

db_password = get_secret_or_env("DATABASE_PASSWORD")
```

Since Version 0.2.0, a `VaultClient` is added, and you can explicitly create 
such a client:
```python
from ytkubevault import VaultClient

vault_client = VaultClient()
# login first
try:
    vault_client.login()
except Exception as e:
    print(f"Failed to login: {e}")

# Then you can do encryption, for example:
vault_client.encrypt(encrypt_key="some_key", plaintext="my_secret_message")
```

The old functions now use an implicitly created global `VaultClient`. Note that 
`VaultClient` is not multithread-safe.

## Fetching secrets from outside the cluster
To be able to fetch secrets from outside the Kubernetes cluster, you need to install 
the package with
```shell
pip install 'ytkubevault[dev]'
```
This will also install `kubernetes` package, which allows us to get the service account
token. Additionally, 4 environment variables need to be set:
* VAULT_DEV_REMOTE_MODE: this needs to be `true`, which is `false` by default
* VAULT_DEV_REMOTE_CLUSTER: the cluster string you want to connect to
* VAULT_DEV_REMOTE_NAMESPACE: the namespace the service is in
* VAULT_DEV_REMOTE_SERVICE_ACCOUNT: the service account name of the service