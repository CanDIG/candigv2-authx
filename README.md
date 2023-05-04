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

Opa does the actual lookup of roles and authorizations for users of CanDIGv2. It contains the information about which datasets a particular user is authorized to access: `get_opa_datasets` uses the email provided in the bearer token to look up the datasets that user is authorized to access.

Opa also confirms if a user is a site admin: `is_site_admin` checks the realm roles for the `CANDIG_OPA_SITE_ADMIN_KEY` and returns True if that role is present in the token.

`OPA_SECRET` is the Opa service's predefined token that authorizes a service to use Opa. It's set as part of the initial setup of the candig-opa container.

`add_provider_to_opa` and `remove_provider_from_opa` add/remove new issuers to Opa.

## Access to secrets: Vault

Vault acts as the secret store for CanDIGv2. For now, the only store that we use is the key-value store `aws`, for storing and retrieving S3-style credentials.

Services that require S3 access should have an environment variable `VAULT_S3_TOKEN` that is exchanged with Vault as a header `X-Vault-Token` for authorization to get the credentials. These exchanges are handled by the `get_aws_credential` and `store_aws_credential` methods.

## Access to S3 objects: Minio
Minio acts as the CanDIGv2 client for S3 access. `get_minio_client` returns a Minio object that can be used with the [Python API](https://min.io/docs/minio/linux/developers/python/API.html). This method, by default, returns an object corresponding to the Minio sandbox instance.

For convenience, `get_s3_url` is a one-stop method for returning a presigned URL to an S3 object.


## To use this library:

Add the following to your requirements.txt:

```
candigv2-authx@git+https://github.com/CanDIG/candigv2-authx.git@main
```

Then add `import authx.auth` to your code.
