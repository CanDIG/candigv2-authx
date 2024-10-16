# candigv2-authx
Common CanDIGv2 authorization and authentication code.

CanDIGv2 has several separate layers that are involved in authentication and authorization. This repo centralizes the protocols into a single module.

## Authentication: Keycloak

Keycloak acts as the identity provider for CanDIGv2. It uses the OpenID protocol to authenticate the user and issue a jwt in the form of a bearer token, identifying the user and their roles to other services. This token is then provided as an Authorization header to other CanDIGv2 services.

`get_access_token` demonstrates the exchange required to get a token.

`get_auth_token` is a convenience method for plucking out the access token from a request's Authorization header.

## Authorization: Tyk

Tyk acts as a proxy redirect service for the other services of CanDIGv2. When a call is made to CanDIGv2, it goes to Tyk first. Tyk validates the bearer token presented and makes sure that it is not expired and is issued by one of the authorized CanDIGv2 sites. If it is valid, it passes the call to the relevant service. When this fails, it returns a 401 "Key not authorised" error.

`add_provider_to_tyk_api` and `remove_provider_from_tyk_api` add/remove new issuers to a particular API in Tyk.

## Authorization: Opa

Opa does the actual lookup of roles and authorizations for users of CanDIGv2. It contains the information about which datasets a particular user is authorized to access.

`get_opa_datasets` uses the user ID provided in the bearer token to look up the datasets that user is authorized to access for the given path and method. `is_action_allowed_for_program` returns True or False, depending on if the program is in the authorized datasets for the given path and method.

`get_user_id` returns the ID (key defined in .env as CANDIG_USER_KEY) associated with the user.

Opa also confirms if a user is a site admin: `is_site_admin` checks for whether or not this user is present in Opa's known site_admin role and returns True if so.

`add_provider_to_opa` and `remove_provider_from_opa` add/remove new issuers to Opa.

## Access to secrets: Vault

Vault acts as the secret store for CanDIGv2.

Every service can be set up to have its own secret store in Vault. Diff your module's setup against the lib/templates folder to see what you need to add to create a service store:

- your-module_setup.sh needs to call `bash $PWD/create_service_store.sh "your-module"`
- your-module/docker-compose.yml needs to add the following:
```
    secrets:
        - source: vault-approle-token
          target: vault-approle-token
    environment:
        - VAULT_URL="${VAULT_PRIVATE_URL}"
        - SERVICE_NAME="${SERVICE_NAME}"
```

Once those changes have been made, your service can read and write to its service store using the get_service_store_secret and set_service_store_secret methods.

Services that require S3 access need to be authorized in `vault_setup.sh` to access candig-ingest's `aws` secret store. Once that authorization is set up, the service can use the get_aws_credential,


## Access to S3 objects: Minio
Minio acts as the CanDIGv2 client for S3 access. `get_minio_client` returns a Minio object that can be used with the [Python API](https://min.io/docs/minio/linux/developers/python/API.html). This method, by default, returns an object corresponding to the Minio sandbox instance.

For convenience, `get_s3_url` is a one-stop method for returning a presigned URL to an S3 object.


## To use this library:

Add the following to your requirements.txt:

```
candigv2-authx@git+https://github.com/CanDIG/candigv2-authx.git@main
```

Then add `import authx.auth` to your code.
