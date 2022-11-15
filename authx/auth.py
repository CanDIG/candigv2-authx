import os
import re
import requests


## Make sure these env vars are available:
CANDIG_OPA_SITE_ADMIN_KEY = os.getenv("CANDIG_OPA_SITE_ADMIN_KEY", "site_admin")
KEYCLOAK_PUBLIC_URL = os.getenv('KEYCLOAK_PUBLIC_URL', None)
OPA_URL = os.getenv('OPA_PUBLIC_URL', None)
VAULT_URL = os.getenv('VAULT_URL', None)
VAULT_S3_TOKEN = os.getenv('VAULT_S3_TOKEN', None)


def is_site_admin(request, opa_url=OPA_URL, admin_secret=None, site_admin_key=CANDIG_OPA_SITE_ADMIN_KEY):
    """
    Is the user associated with the token a site admin?
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


def get_auth_token(request):
    """
    Extracts token from request's Authorization header
    """
    token = request.headers['Authorization']
    if token is None:
        return ""
    return token.split()[1]


def get_opa_datasets(request, opa_url=OPA_URL, admin_secret=None):
    """
    Get allowed dataset result from OPA
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


def get_site_admin_token(keycloak_url=KEYCLOAK_PUBLIC_URL):
    payload = {
        "client_id": os.getenv("CANDIG_CLIENT_ID"),
        "client_secret": os.getenv("CANDIG_CLIENT_SECRET"),
        "grant_type": "password",
        "username": os.getenv("CANDIG_SITE_ADMIN_USER"),
        "password": os.getenv("CANDIG_SITE_ADMIN_PASSWORD"),
        "scope": "openid"
    }
    response = requests.post(f"{keycloak_url}/auth/realms/candig/protocol/openid-connect/token", data=payload)
    if response.status_code == 200:
        return response.json()["access_token"]
    else:
        raise Exception(f"Check for environment variables: {response.text}")


def get_minio_client(request, s3_endpoint=None, bucket=None, access_key=None, secret_key=None, region=None):
    if s3_endpoint is None or s3_endpoint == "play.min.io:9000":
        endpoint = "play.min.io:9000"
        access_key="Q3AM3UQ867SPQQA43P2F"
        secret_key="zuf+tfteSlswRu7BJ86wekitnifILbZam1KYY3TG"
        if bucket is None:
            bucket = "candigtest"
    else:
        # eat any http stuff from endpoint:
        endpoint_parse = re.match(r"https*:\/\/(.+)?", s3_endpoint)
        if endpoint_parse is not None:
            endpoint = endpoint_parse.group(1)
            
        # if it's any sort of amazon endpoint, it can just be s3.amazonaws.com
        if "amazonaws.com" in s3_endpoint:
            endpoint = "s3.amazonaws.com"
        else:
            endpoint = s3_endpoint

        endpoint = s3_endpoint
        response, status_code = get_aws_credential(request, endpoint=endpoint, bucket=bucket)
        if "error" in response:
            raise Exception(response["error"])
        access_key = response["access"]
        secret_key = response["secret"]

    from minio import Minio
    if region is None:
        client = Minio(
            endpoint = endpoint,
            access_key = access_key,
            secret_key = secret_key
        )
    else:
        client = Minio(
            endpoint = endpoint,
            access_key = access_key,
            secret_key = secret_key,
            region = region
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
    try:
        response = get_minio_client(request, s3_endpoint=s3_endpoint, bucket=bucket, access_key=access_key, secret_key=secret_key, region=region)
        client = response["client"]
        result = client.stat_object(bucket_name=bucket, object_name=object_name)
        url = client.presigned_get_object(bucket_name=bucket, object_name=object_name)
    except Exception as e:
        return {"message": str(e)}, 500
    return {"url": url}, 200


def parse_aws_credential(awsfile):
    # parse the awsfile:
    access = None
    secret = None
    with open(awsfile) as f:
        lines = f.readlines()
        while len(lines) > 0 and (access is None or secret is None):
            line = lines.pop(0)
            parse_access = re.match(r"(aws_access_key_id|AWSAccessKeyId)\s*=\s*(.+)$", line)
            if parse_access is not None:
                access = parse_access.group(2)
            parse_secret = re.match(r"(aws_secret_access_key|AWSSecretKey)\s*=\s*(.+)$", line)
            if parse_secret is not None:
                secret = parse_secret.group(2)
    if access is None:
        return {"error": "awsfile did not contain access ID"}
    if secret is None:
        return {"error": "awsfile did not contain secret key"}
    return {"access": access, "secret": secret}


def store_aws_credential(client, vault_url=VAULT_URL, token=None):
    # get client token for site_admin:
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
        headers["X-Vault-Token"] = client_token
    
    # check to see if credential exists:
    url = f"{vault_url}/v1/aws/{client['endpoint']}-{client['bucket']}"
    response = requests.get(url, headers=headers)
    if response.status_code == 404:
        # add credential:
        body = {
            "access": client['access'],
            "secret": client['secret']
        }
        response = requests.post(url, headers=headers, json=body)
    if response.status_code >= 200 and response.status_code < 300:
        return True, None
    return False, json.dumps(response.json())
    
    
def get_aws_credential(request, vault_url=VAULT_URL, endpoint=None, bucket=None, vault_s3_token=VAULT_S3_TOKEN):
    if vault_s3_token is None:
        return {"error": f"Vault error: service did not provide VAULT_S3_TOKEN"}, 500
    if vault_url is None:
        return {"error": f"Vault error: service did not provide VAULT_URL"}, 500
    response = requests.get(
        f"{vault_url}/v1/aws/{endpoint}-{bucket}",
        headers={
            "Authorization": f"Bearer {get_auth_token(request)}",
            "X-Vault-Token": vault_s3_token
            }
    )
    if response.status_code == 200:
        return response.json()["data"], response.status_code
    return {"error": f"Vault error: could not get credential for endpoint {endpoint} and bucket {bucket}"}, response.status_code


if __name__ == "__main__":
    print(get_site_admin_token())
