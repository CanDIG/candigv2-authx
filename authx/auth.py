import os
import re
import requests


## Env vars for most auth methods:
CANDIG_OPA_SITE_ADMIN_KEY = os.getenv("OPA_SITE_ADMIN_KEY", "site_admin")
KEYCLOAK_PUBLIC_URL = os.getenv('KEYCLOAK_PUBLIC_URL', None)
OPA_URL = os.getenv('OPA_URL', None)
VAULT_URL = os.getenv('VAULT_URL', None)
VAULT_S3_TOKEN = os.getenv('VAULT_S3_TOKEN', None)

## Env vars for ingest and other site admin tasks:
CLIENT_ID = os.getenv("CANDIG_CLIENT_ID", None)
CLIENT_SECRET = os.getenv("CANDIG_CLIENT_SECRET", None)
SITE_ADMIN_USER = os.getenv("CANDIG_SITE_ADMIN_USER", None)
SITE_ADMIN_PASSWORD = os.getenv("CANDIG_SITE_ADMIN_PASSWORD", None)


def get_auth_token(request):
    """
    Extracts token from request's Authorization header
    """
    token = request.headers['Authorization']
    if token is None:
        return ""
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
        raise Exception("keycloak_url was not provided")
    if client_id is None or client_secret is None:
        raise Exception("client_id and client_secret required for token")
    if username is None or password is None:
        raise Exception("Username and password required for token")
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
        raise Exception(f"Check for environment variables: {response.text}")


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
    response = requests.post(
        opa_url + "/v1/data/permissions/datasets",
        headers={
            "X-Opa": f"{admin_secret}",
            "Authorization": f"Bearer {token}"
        },
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
        response = requests.post(
            opa_url + "/v1/data/idp/" + site_admin_key,
            headers={
                "X-Opa": f"{admin_secret}",
                "Authorization": f"Bearer {token}"
            },
            json={
                "input": {
                        "token": token
                    }
                }
            )
        if 'result' in response.json():
            return True
    return False


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


def get_minio_client(token=None, s3_endpoint=None, bucket=None, access_key=None, secret_key=None, region=None, secure=True):
    """
    Return an object including a minio client that either refers to the specified endpoint and bucket, or refers to the Minio playbox.
    """
    if s3_endpoint is None or s3_endpoint == "play.min.io:9000":
        endpoint = "play.min.io:9000"
        url = endpoint
        access_key="Q3AM3UQ867SPQQA43P2F"
        secret_key="zuf+tfteSlswRu7BJ86wekitnifILbZam1KYY3TG"
        if bucket is None:
            bucket = "candigtest"
    else:
        endpoint = s3_endpoint
        if token is None:
            return {"error": f"No Authorization token provided"}, 401
        if access_key is None:
            response, status_code = get_aws_credential(token=token, endpoint=s3_endpoint, bucket=bucket)
            if "error" in response:
                raise Exception(response["error"])
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


def get_s3_url(request, s3_endpoint=None, bucket=None, object_id=None, access_key=None, secret_key=None, region=None):
    """
    Get a signed URL for an object stored in an S3 bucket.
    Returns url, status_code
    """
    try:
        response = get_minio_client(token=get_auth_token(request), s3_endpoint=s3_endpoint, bucket=bucket, access_key=access_key, secret_key=secret_key, region=region)
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
