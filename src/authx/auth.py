import os
import re
import requests
import jwt
import base64
import json


## Env vars for most auth methods:
CANDIG_OPA_SITE_ADMIN_KEY = os.getenv("OPA_SITE_ADMIN_KEY", "site_admin")
KEYCLOAK_PUBLIC_URL = os.getenv('KEYCLOAK_PUBLIC_URL', None)
OPA_URL = os.getenv('OPA_URL', None)
OPA_SECRET = os.getenv('OPA_SECRET', None)
VAULT_URL = os.getenv('VAULT_URL', None)
VAULT_S3_TOKEN = os.getenv('VAULT_S3_TOKEN', None)
TYK_SECRET_KEY = os.getenv("TYK_SECRET_KEY")
TYK_POLICY_ID = os.getenv("TYK_POLICY_ID")
TYK_LOGIN_TARGET_URL = os.getenv("TYK_LOGIN_TARGET_URL")
SERVICE_NAME = os.getenv("SERVICE_NAME")

## Env vars for ingest and other site admin tasks:
CLIENT_ID = os.getenv("CANDIG_CLIENT_ID", None)
CLIENT_SECRET = os.getenv("CANDIG_CLIENT_SECRET", None)
SITE_ADMIN_USER = os.getenv("CANDIG_SITE_ADMIN_USER", None)
SITE_ADMIN_PASSWORD = os.getenv("CANDIG_SITE_ADMIN_PASSWORD", None)


class CandigAuthError(Exception):
    pass


def get_auth_token(request):
    """
    Extracts token from request's Authorization header
    """
    token = request.headers['Authorization']
    if token is None:
        return None
    return token.split()[1]


def get_access_token(
    keycloak_url=KEYCLOAK_PUBLIC_URL,
    client_id=CLIENT_ID,
    client_secret=CLIENT_SECRET,
    username=None,
    password=None
    ):
    """
    Gets a token from the keycloak server.
    """
    if keycloak_url is None:
        raise CandigAuthError("keycloak_url was not provided")
    if client_id is None or client_secret is None:
        raise CandigAuthError("client_id and client_secret required for token")
    if username is None or password is None:
        raise CandigAuthError("Username and password required for token")
    payload = {
        "client_id": client_id,
        "client_secret": client_secret,
        "grant_type": "password",
        "username": username,
        "password": password,
        "scope": "openid"
    }
    response = requests.post(f"{keycloak_url}/auth/realms/candig/protocol/openid-connect/token", data=payload)
    if response.status_code == 200:
        return response.json()["access_token"]
    else:
        raise CandigAuthError(f"Check for environment variables: {response.text}")


def get_site_admin_token():
    return get_access_token(username=SITE_ADMIN_USER, password=SITE_ADMIN_PASSWORD)


def get_opa_datasets(request, opa_url=OPA_URL, admin_secret=None):
    """
    Get allowed dataset result from OPA
    Returns array of strings
    """

    token = get_auth_token(request)

    body = {
        "input": {
            "token": token,
            "body": {
                "path": request.path,
                "method": request.method
            }
        }
    }
    headers = {
        "Authorization": f"Bearer {token}"
    }
    if admin_secret is not None:
        headers["X-Opa"] = f"{admin_secret}"

    response = requests.post(
        opa_url + "/v1/data/permissions/datasets",
        headers=headers,
        json=body
    )
    response.raise_for_status()
    allowed_datasets = response.json()["result"]
    return allowed_datasets


def is_site_admin(request, opa_url=OPA_URL, admin_secret=None, site_admin_key=CANDIG_OPA_SITE_ADMIN_KEY):
    """
    Is the user associated with the token a site admin?
    Returns boolean.
    """
    if opa_url is None:
        print("WARNING: AUTHORIZATION IS DISABLED; OPA_URL is not present")
        return True
    if "Authorization" in request.headers:
        token = get_auth_token(request)
        headers = {
            "Authorization": f"Bearer {token}"
        }
        if admin_secret is not None:
            headers["X-Opa"] = f"{admin_secret}"
        response = requests.post(
            opa_url + "/v1/data/idp/" + site_admin_key,
            headers=headers,
            json={
                "input": {
                        "token": token
                    }
                }
            )
        if 'result' in response.json():
            return True
    return False


def get_user_email(request, opa_url=OPA_URL, admin_secret=None):
    """
    Returns the email address associated with the user.
    """
    if opa_url is None:
        print("WARNING: AUTHORIZATION IS DISABLED; OPA_URL is not present")
        return None
    if "Authorization" in request.headers:
        token = get_auth_token(request)
        headers = {
            "Authorization": f"Bearer {token}"
        }
        if admin_secret is not None:
            headers["X-Opa"] = f"{admin_secret}"
        response = requests.post(
            opa_url + "/v1/data/idp/email",
            headers=headers,
            json={
                "input": {
                        "token": token
                    }
                }
            )
        if 'result' in response.json():
            return response.json()['result']
    return None


def get_vault_token(token=None, vault_s3_token=None, vault_url=VAULT_URL):
    """
    Given a known vault_s3_token, exchange for a valid X-Vault-Token.
    Returns token, status_code
    """
    if vault_url is None:
        return {"error": f"Vault error: service did not provide VAULT_URL"}, 500
    if vault_s3_token is None:
        if token is None:
            return {"error": f"Vault error: service did not provide VAULT_S3_TOKEN"}, 500
        headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
            "charset": "utf-8"
        }
        body = {
            "jwt": token,
            "role": "site_admin"
        }
        url = f"{vault_url}/v1/auth/jwt/login"
        response = requests.post(url, json=body, headers=headers)
        if response.status_code == 200:
            client_token = response.json()["auth"]["client_token"]
            return client_token, 200
        else:
            return response.json(), response.status_code
    return vault_s3_token, 200


def get_aws_credential(token=None, vault_url=VAULT_URL, endpoint=None, bucket=None, vault_s3_token=VAULT_S3_TOKEN):
    """
    Look up S3 credentials in Vault.
    Returns credential object, status code
    """
    if endpoint is None or bucket is None:
        return {"error": "Error getting S3 credentials: missing either endpoint or bucket"}, 400

    # eat any http stuff from endpoint:
    endpoint_parse = re.match(r"https*:\/\/(.+)?", endpoint)
    if endpoint_parse is not None:
        endpoint = endpoint_parse.group(1)
    # if it's any sort of amazon endpoint, it can just be s3.amazonaws.com
    if "amazonaws.com" in endpoint:
        endpoint = "s3.amazonaws.com"
    # clean up endpoint name:
    endpoint = re.sub(r"\W", "_", endpoint)

    vault_token, status_code = get_vault_token(token=token, vault_s3_token=vault_s3_token, vault_url=vault_url)
    if status_code != 200:
        return f"get_vault_token failed: {vault_token}", status_code
    response = requests.get(
        f"{vault_url}/v1/aws/{endpoint}-{bucket}",
        headers={
            "Authorization": f"Bearer {token}",
            "X-Vault-Token": vault_token
            }
    )
    if response.status_code == 200:
        result = response.json()['data']
        result['endpoint'] = endpoint
        result['bucket'] = bucket
        return result, response.status_code
    return {"error": f"Vault error: could not get credential for endpoint {endpoint} and bucket {bucket}"}, response.status_code


def store_aws_credential(token=None, endpoint=None, s3_url=None, bucket=None, access=None, secret=None, vault_s3_token=VAULT_S3_TOKEN, vault_url=VAULT_URL):
    """
    Store aws credentials in Vault.
    Returns credential object, status code
    """
    if endpoint is None or bucket is None or access is None or secret is None:
        return {"error": "S3 credentials not provided to store in Vault"}, 400
    if token is None:
        return {"error": "Bearer token not provided"}, 400
    # eat any http stuff from endpoint:
    secure = True
    endpoint_parse = re.match(r"(https*):\/\/(.+)?", endpoint)
    if endpoint_parse is not None:
        endpoint = endpoint_parse.group(2)
        if endpoint_parse.group(1) == "http":
            secure = False
    # if it's any sort of amazon endpoint, it can just be s3.amazonaws.com
    if "amazonaws.com" in endpoint:
        endpoint = "s3.amazonaws.com"
    if s3_url is None:
        s3_url = endpoint

    # clean up endpoint name:
    endpoint = re.sub(r"\W", "_", endpoint)
    vault_token, status_code = get_vault_token(token=token, vault_s3_token=vault_s3_token, vault_url=vault_url)
    if status_code != 200:
        return f"get_vault_token failed: {vault_token}", status_code

    headers={
        "Authorization": f"Bearer {token}",
        "X-Vault-Token": vault_token
        }
    url = f"{vault_url}/v1/aws/{endpoint}-{bucket}"
    body = {
        "url": s3_url,
        "access": access,
        "secret": secret,
        "secure": secure
    }
    response = requests.post(url, headers=headers, json=body)
    if response.status_code >= 200 and response.status_code < 300:
        response = requests.get(url, headers=headers)
        result = response.json()["data"]
        result["endpoint"] = endpoint
        return result, 200
    return response.json(), response.status_code


def get_minio_client(token=None, s3_endpoint=None, bucket=None, access_key=None, secret_key=None, region=None, secure=True, public=False):
    """
    Return an object including a minio client that either refers to the specified endpoint and bucket, or refers to the Minio playbox.
    """
    # url = "play.min.io:9000"
    url = None
    if s3_endpoint is None or s3_endpoint == "play.min.io:9000":
        endpoint = "play.min.io:9000"
        access_key="Q3AM3UQ867SPQQA43P2F"
        secret_key="zuf+tfteSlswRu7BJ86wekitnifILbZam1KYY3TG"
        if bucket is None:
            bucket = "candigtest"
    else:
        endpoint = s3_endpoint
        if access_key is None and not public:
            if token is None:
                return {"error": f"No Authorization token provided"}, 401
            response, status_code = get_aws_credential(token=token, endpoint=s3_endpoint, bucket=bucket)
            if "error" in response:
                raise CandigAuthError(response)
            access_key = response["access"]
            secret_key = response["secret"]
            url = response["url"]
            secure = response["secure"]
        else:
            endpoint_parse = re.match(r"(https*):\/\/(.+)?", endpoint)
            if endpoint_parse is not None:
                url = endpoint_parse.group(2)
                if endpoint_parse.group(1) == "http":
                    secure = False
            else:
                url = endpoint
    if url is None:
        raise CandigAuthError("No endpoint found")
    from minio import Minio
    if region is None:
        client = Minio(
            endpoint = url,
            access_key = access_key,
            secret_key = secret_key,
            secure = secure
        )
    else:
        client = Minio(
            endpoint = url,
            access_key = access_key,
            secret_key = secret_key,
            region = region,
            secure = secure
        )

    if not client.bucket_exists(bucket):
        if region is None:
            client.make_bucket(bucket)
        else:
            client.make_bucket(bucket, location=region)

    return {
        "endpoint": endpoint,
        "client": client,
        "bucket": bucket,
        "access": access_key,
        "secret": secret_key
    }


def get_s3_url(request, s3_endpoint=None, bucket=None, object_id=None, access_key=None, secret_key=None, region=None, public=False):
    """
    Get a signed URL for an object stored in an S3 bucket.
    Returns url, status_code
    """
    try:
        response = get_minio_client(token=get_auth_token(request), s3_endpoint=s3_endpoint, bucket=bucket, access_key=access_key, secret_key=secret_key, region=region, public=public)
        client = response["client"]
        result = client.stat_object(bucket_name=response["bucket"], object_name=object_id)
        url = client.presigned_get_object(bucket_name=response["bucket"], object_name=object_id)
    except Exception as e:
        return {"error": str(e)}, 500
    return url, 200


if __name__ == "__main__":
    print(get_access_token(
        keycloak_url=KEYCLOAK_PUBLIC_URL,
        username=SITE_ADMIN_USER,
        password=SITE_ADMIN_PASSWORD
        ))


def decode_verify_token(token, issuer):
    # the token is a valid CanDIG token from the new server: it contains its issuer and audience
    data = jwt.decode(token, options={"verify_signature": False})
    if data['iss'] != issuer:
        raise CandigAuthError(f"The token's iss ({data['iss']}) does not match the issuer ({issuer})")

    url = f"{data['iss']}/.well-known/openid-configuration"
    response = requests.request("GET", url)
    if response.status_code == 200:
        cert_url = response.json()['jwks_uri']
        response = requests.request("GET", cert_url)
        jwks_client = jwt.PyJWKClient(cert_url)
        signing_key = jwks_client.get_signing_key_from_jwt(token)
        data = jwt.decode(
            token,
            signing_key.key,
            algorithms=["RS256"],
            audience=data['azp'],
            options={'verify_exp': False}
        )
        return data
    return None


def add_provider_to_tyk_api(api_id, token, issuer, policy_id=TYK_POLICY_ID):
    jwt = decode_verify_token(token, issuer)
    client_id_64 = base64.b64encode(bytes(jwt['azp'], 'utf-8')).decode('utf-8')
    new_provider = {
        "issuer": jwt['iss'],
        "client_ids": {
            client_id_64: policy_id
        }
    }
    url = f"{TYK_LOGIN_TARGET_URL}/tyk/apis/{api_id}"
    headers = { "x-tyk-authorization": TYK_SECRET_KEY }
    response = requests.request("GET", url, headers=headers)
    if response.status_code == 200:
        api_json = response.json()
        # check to see if it's already here:
        found = False
        for s in api_json['openid_options']['providers']:
            if json.dumps(s, sort_keys=True) == json.dumps(new_provider, sort_keys=True):
                found = True
        if not found:
            api_json['openid_options']['providers'].append(new_provider)
            response = requests.request("PUT", url, headers=headers, json=api_json)
            if response.status_code == 200:
                response = requests.request("GET", f"{TYK_LOGIN_TARGET_URL}/tyk/reload", params={"block": True}, headers=headers)
                print("reloaded")
                return requests.request("GET", url, headers=headers)
    return response


def remove_provider_from_tyk_api(api_id, issuer, policy_id=TYK_POLICY_ID):
    url = f"{TYK_LOGIN_TARGET_URL}/tyk/apis/{api_id}"
    headers = { "x-tyk-authorization": TYK_SECRET_KEY }
    response = requests.request("GET", url, headers=headers)
    if response.status_code == 200:
        api_json = response.json()
        new_providers = []
        for p in api_json['openid_options']['providers']:
            if issuer not in p['issuer']:
                new_providers.append(p)
            else:
                if policy_id not in p['client_ids'].values():
                    new_providers.append(p)

        api_json['openid_options']['providers'] = new_providers
        response = requests.request("PUT", url, headers=headers, json=api_json)
        if response.status_code == 200:
            response = requests.request("GET", f"{TYK_LOGIN_TARGET_URL}/tyk/reload", params={"block": True}, headers=headers)
            print("reloaded")
            return requests.request("GET", url, headers=headers)
    return response


def add_provider_to_opa(token, issuer, test_key=None):
    # get the existing values
    response, status_code = get_service_store_secret("opa", key="data")

    if status_code == 200:
        data = response["keys"]
        jwt = decode_verify_token(token, issuer)
        jwks_response = requests.get(f"{jwt['iss']}/.well-known/openid-configuration")
        if jwks_response.status_code == 200:
            jwks_response = requests.get(jwks_response.json()["jwks_uri"])
            if jwks_response.status_code == 200:
                new_provider = {"iss": jwt['iss'], "cert": jwks_response.text}
                if test_key is not None:
                    new_provider['test'] = test_key
                # check to see if it's already here:
                found = False
                for s in data:
                    if s['iss'] == new_provider['iss']:
                        found = True
                        if 'test' in new_provider:
                            if 'test' not in s:
                                found = False # not the same because s doesn't have a test key
                            else:
                                if s['test'] != new_provider['test']:
                                    found = False # not the same because they have different test keys
                if not found:
                    data.append(new_provider)
                    response, status_code = set_service_store_secret("opa", key="data", value=response)
                else:
                    print(f"{issuer} is already a provider")
    else:
        raise CandigAuthError("couldn't get data from opa store")
    return response["keys"]


def remove_provider_from_opa(issuer, test_key=None):
    response, status_code = get_service_store_secret("opa", key="data")
    if status_code == 200:
        data = response["keys"]
        new_providers = []
        for p in data:
            if issuer in p['iss']:
                if test_key is not None:
                    if "test" in p:
                        if p['test'] != test_key:
                            new_providers.append(p)
                    else:
                        new_providers.append(p)
            else:
                new_providers.append(p)
        response, status_code = set_service_store_secret("opa", key="data", value={"keys": new_providers})
    else:
        raise CandigAuthError("couldn't get data from opa store")
    return response["keys"]


def get_vault_token_for_service(service=SERVICE_NAME, vault_url=VAULT_URL, approle_token=None, role_id=None, secret_id=None):
    """
    Get this service's vault token
    """
    # if there is no SERVICE_NAME env var, something is wrong
    if service is None:
        raise CandigAuthError("no SERVICE_NAME specified")
    # in CanDIGv2 docker stack, approle token should have been passed in
    if approle_token is None:
        with open("/run/secrets/vault-approle-token") as f:
            approle_token = f.read().strip()
    if approle_token is None:
        raise CandigAuthError("no approle token found")

    # in CanDIGv2 docker stack, roleid should have been passed in
    if role_id is None:
        try:
            with open("/home/candig/roleid") as f:
                role_id = f.read().strip()
        except Exception as e:
            raise CandigAuthError(str(e))
    if role_id is None:
        raise CandigAuthError("no role_id found")

    # get the secret_id
    if secret_id is None:
        url = f"{vault_url}/v1/auth/approle/role/{service}/secret-id"
        headers = { "X-Vault-Token": approle_token }
        response = requests.post(url=url, headers=headers)
        if response.status_code == 200:
            secret_id = response.json()["data"]["secret_id"]
        else:
            raise CandigAuthError(f"secret_id: {response.text}")

        # swap the role_id and service_id for a token
        data = {
            "role_id": role_id,
            "secret_id": secret_id
        }
        url = f"{vault_url}/v1/auth/approle/login"
        response = requests.post(url, json=data)
        if response.status_code == 200:
            return response.json()["auth"]["client_token"]
        else:
            raise CandigAuthError(f"login: {response.text}")
    return None


def set_service_store_secret(service, key=None, value=None, vault_url=VAULT_URL, role_id=None, secret_id=None, token=None):
    if token is None:
        try:
            token = get_vault_token_for_service(vault_url=vault_url, role_id=role_id, secret_id=secret_id)
        except Exception as e:
            return {"error": str(e)}, 500
    if token is None:
        return {"error": f"could not obtain token for {service}"}, 400
    if key is None:
        return {"error": "no key specified"}, 400

    headers = {
        "X-Vault-Token": token
    }
    url = f"{vault_url}/v1/{service}/{key}"
    response = requests.post(url, headers=headers, data=value)
    if response.status_code >= 200 and response.status_code < 300:
        response = requests.get(url, headers=headers)
        result = response.json()["data"]
        return result, 200
    return response.json(), response.status_code


def get_service_store_secret(service, key=None, vault_url=VAULT_URL, role_id=None, secret_id=None, token=None):
    if token is None:
        try:
            token = get_vault_token_for_service(vault_url=vault_url, role_id=role_id, secret_id=secret_id)
        except Exception as e:
            return {"error": str(e)}, 500
    if token is None:
        return {"error": f"could not obtain token for {service}"}, 400
    if key is None:
        return {"error": "no key specified"}, 400

    headers = {
        "X-Vault-Token": token
    }
    url = f"{vault_url}/v1/{service}/{key}"
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        result = response.json()["data"]
        return result, 200
    return response.text, response.status_code
