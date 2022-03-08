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