import os
import re
import requests
import jwt
import base64
import json
import uuid
import getpass
from candigv2_logging.logging import CanDIGLogger


## Env vars for most auth methods:
KEYCLOAK_PUBLIC_URL = os.getenv('KEYCLOAK_PUBLIC_URL', None)
OPA_URL = os.getenv('OPA_URL', None)
VAULT_URL = os.getenv('VAULT_URL', None)
TYK_SECRET_KEY = os.getenv("TYK_SECRET_KEY")
TYK_POLICY_ID = os.getenv("TYK_POLICY_ID")
TYK_LOGIN_TARGET_URL = os.getenv("TYK_LOGIN_TARGET_URL")
SERVICE_NAME = os.getenv("SERVICE_NAME")
CANDIG_USER_KEY = os.getenv("CANDIG_USER_KEY", "email")

## Env vars for ingest and other site admin tasks:
CLIENT_ID = os.getenv("CANDIG_CLIENT_ID", None)
CLIENT_SECRET = os.getenv("CANDIG_CLIENT_SECRET", None)
KEYCLOAK_REALM = os.getenv("KEYCLOAK_REALM", "candig")

logger = CanDIGLogger(__file__)


class CandigAuthError(Exception):
    pass


def get_auth_token(request, token=None):
    """
    Extracts token from request's Authorization header
    """
    if request is not None:
        token = request.headers['Authorization']
        token = token.split(",")[0].strip()
        token = token.split()[1]
    if token is None:
        return None

    data = jwt.decode(token, options={"verify_signature": False})
    if data["typ"] == "Refresh":
        return get_access_token(refresh_token=token)
    return token


def get_oauth_response(
    keycloak_url=KEYCLOAK_PUBLIC_URL,
    keycloak_realm=KEYCLOAK_REALM,
    keycloak_realm_url=None,
    client_id=CLIENT_ID,
    client_secret=CLIENT_SECRET,
    username=None,
    password=None,
    refresh_token=None
    ):
    """
    Gets a token from the keycloak server.
    """
    if keycloak_url is None:
        raise CandigAuthError("keycloak_url was not provided")
    if client_id is None or client_secret is None:
        raise CandigAuthError("client_id and client_secret required for token")

    payload = {
        "client_id": client_id,
        "client_secret": client_secret,
        "scope": "openid"
    }

    if refresh_token is not None:
        payload["refresh_token"] = refresh_token
        payload["grant_type"] = "refresh_token"
    else:
        if username is None or password is None:
            raise CandigAuthError("Username and password required for token")
        else:
            payload["grant_type"] = "password"
            payload["username"] = username
            payload["password"] = password

    url = keycloak_realm_url
    if url is None:
        url = f"{keycloak_url}/auth/realms/{keycloak_realm}"
    response = requests.post(f"{url}/protocol/openid-connect/token", data=payload)
    if response.status_code == 200:
        return response.json()
    else:
        return {"error": f"Error obtaining access token: {response.text}"}


def get_access_token(
    keycloak_url=KEYCLOAK_PUBLIC_URL,
    client_id=CLIENT_ID,
    client_secret=CLIENT_SECRET,
    username=None,
    password=None,
    refresh_token=None
    ):

    if client_id is None:
        response = get_service_store_secret("keycloak", "client-id")
        if response[1] == 200:
            client_id = response[0]["value"]
    if client_secret is None:
        response = get_service_store_secret("keycloak", "client-secret")
        if response[1] == 200:
            client_secret = response[0]["value"]

    result = get_oauth_response(
        keycloak_url=keycloak_url,
        client_id=client_id,
        client_secret=client_secret,
        username=username,
        password=password,
        refresh_token=refresh_token
        )
    return result["access_token"]


def get_site_admin_token(refresh_token=None):
    username = os.getenv("CANDIG_SITE_ADMIN_USER", None)
    password = os.getenv("CANDIG_SITE_ADMIN_PASSWORD", None)
    if username is None:
        username = input("Enter username: ")
    if password is None:
        password = getpass.getpass("Enter password: ")

    return get_access_token(username=username, password=password, refresh_token=refresh_token)


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
                "method": request.method
            }
        }
    }
    if hasattr(request, 'path'):
        body["input"]["body"]["path"] = request.path
    elif hasattr(request, 'url'):
        body["input"]["body"]["path"] = request.url

    headers = {
        "Authorization": f"Bearer {token}"
    }
    response = requests.post(
        opa_url + "/v1/data/permissions",
        headers=headers,
        json=body
    )
    if response.status_code == 200:
        if "datasets" in response.json()["result"]:
            return response.json()["result"]["datasets"]

    return []


def is_site_admin(request, token=None, opa_url=OPA_URL, admin_secret=None):
    """
    Is the user associated with the token a site admin?
    Returns boolean.
    """
    if opa_url is None:
        print("WARNING: AUTHORIZATION IS DISABLED; OPA_URL is not present")
        return True
    if request is not None and "Authorization" in request.headers:
        token = get_auth_token(request)
    headers = {
        "Authorization": f"Bearer {token}"
    }
    response = requests.post(
        opa_url + "/v1/data/permissions",
        headers=headers,
        json={
            "input": {
                    "token": token
                }
            }
        )
    if response.status_code == 200:
        if 'site_admin' in response.json()["result"]:
            return response.json()["result"]["site_admin"]
    return False


def is_action_allowed_for_program(token, method=None, path=None, program=None, opa_url=OPA_URL, admin_secret=None):
    """
    Is the user allowed to perform this action on this program?
    """

    token = get_auth_token(None, token=token)
    if opa_url is None:
        print("WARNING: AUTHORIZATION IS DISABLED; OPA_URL is not present")
        return True
    headers = {
        "Authorization": f"Bearer {token}"
    }
    response = requests.post(
        opa_url + "/v1/data/permissions",
        headers=headers,
        json={
            "input": {
                    "token": token,
                    "body": {
                        "method": method,
                        "path": path,
                        "program": program
                    }
                }
            }
        )
    if response.status_code == 200:
        if 'allowed' in response.json()["result"]:
            return response.json()["result"]["allowed"]
    return False


def get_user_id(request, token=None, opa_url=OPA_URL):
    """
    Returns the ID (key defined in .env as CANDIG_USER_KEY) associated with the user.
    """
    if opa_url is None:
        print("WARNING: AUTHORIZATION IS DISABLED; OPA_URL is not present")
        return None
    if token is None:
        if "Authorization" in request.headers:
            token = get_auth_token(request)
    headers = {
        "Authorization": f"Bearer {token}"
    }
    response = requests.post(
        opa_url + f"/v1/data/idp/user_key",
        headers=headers,
        json={
            "input": {
                    "token": token
                }
            }
        )
    if response.status_code == 200:
        if 'result' in response.json():
            return response.json()['result']
    return None


def get_user_email(request, opa_url=OPA_URL, admin_secret=None):
    """
    Same as get_user_id, kept for backwards compatibility
    """
    return get_user_id(request, opa_url)


def get_aws_credential(endpoint=None, bucket=None, vault_url=VAULT_URL):
    """
    Look up S3 credentials in Vault. Executing service must be authorized to access candig-ingest's `/aws` Vault secret path.
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

    response, status_code = get_service_store_secret("candig-ingest", key=f"aws/{endpoint}/{bucket}")
    if status_code == 200:
        response['endpoint'] = endpoint
        response['bucket'] = bucket
        return response, status_code
    return {"error": f"Vault error: could not get credential for endpoint {endpoint} and bucket {bucket}"}, status_code


def store_aws_credential(endpoint=None, s3_url=None, bucket=None, access=None, secret=None, region=None, vault_url=VAULT_URL):
    """
    Store aws credentials in Vault. Executing service must be authorized to write to candig-ingest's `/aws` Vault secret path.
    Returns credential object, status code
    """
    if endpoint is None or bucket is None or access is None or secret is None:
        return {"error": "S3 credentials not provided to store in Vault"}, 400
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
    body = {
            "url": s3_url,
            "access_key": access,
            "secret_key": secret,
            "secure": secure
        }
    if region is not None:
        body["region"] = region
    response, status_code = set_service_store_secret("candig-ingest", key=f"aws/{endpoint}/{bucket}", value=body)
    if status_code >= 200 and status_code < 300:
        response, status_code = get_service_store_secret("candig-ingest", key=f"aws/{endpoint}/{bucket}")
        if status_code == 200:
            response["endpoint"] = endpoint
            response["bucket"] = bucket
            return response, 200
    return response, status_code


def remove_aws_credential(endpoint=None, bucket=None, vault_url=VAULT_URL):
    """
    Delete S3 credentials in Vault. Executing service must be authorized to delete from candig-ingest's `/aws` Vault secret path.
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

    status_code = delete_service_store_secret("candig-ingest", key=f"aws/{endpoint}-{bucket}")
    if status_code == 200:
        result = {}
        result['endpoint'] = endpoint
        result['bucket'] = bucket
        return result, status_code
    if status_code >= 400:
        return {"error": "No such credential exists"}, status_code
    return {"error": f"Vault error: could not get credential for endpoint {endpoint} and bucket {bucket}"}, status_code


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
            response, status_code = get_aws_credential(token=token, endpoint=s3_endpoint, bucket=bucket)
            if "error" in response:
                raise CandigAuthError(response)
            access_key = response["access_key"]
            secret_key = response["secret_key"]
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
        raise CandigAuthError(f"bucket {bucket} does not exist at {url}")

    return {
        "endpoint": endpoint,
        "client": client,
        "bucket": bucket,
        "access": access_key,
        "secret": secret_key
    }


def get_s3_url(s3_endpoint=None, bucket=None, object_id=None, access_key=None, secret_key=None, region=None, public=False):
    """
    Get a signed URL for an object stored in an S3 bucket.
    Returns url, status_code
    """
    try:
        response = get_minio_client(token=None, s3_endpoint=s3_endpoint, bucket=bucket, access_key=access_key, secret_key=secret_key, region=region, public=public)
        client = response["client"]
        result = client.stat_object(bucket_name=response["bucket"], object_name=object_id)
        url = client.presigned_get_object(bucket_name=response["bucket"], object_name=object_id)
    except Exception as e:
        return {"error": str(e)}, 500
    return {"metadata": result, "url": url}, 200


if __name__ == "__main__":
    print(get_access_token(
        keycloak_url=KEYCLOAK_PUBLIC_URL))


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
        for i in range(0, len(api_json['openid_options']['providers'])):
            s = api_json['openid_options']['providers'][i]
            if json.dumps(s, sort_keys=True) == json.dumps(new_provider, sort_keys=True):
                found = True
                api_json['openid_options']['providers'][i] = new_provider
                break
        if not found:
            api_json['openid_options']['providers'].append(new_provider)
        response = requests.request("PUT", url, headers=headers, json=api_json)
        if response.status_code == 200:
            response = requests.request("GET", f"{TYK_LOGIN_TARGET_URL}/tyk/reload", params={"block": True}, headers=headers)
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
    new_provider = None
    jwt = decode_verify_token(token, issuer)
    jwks_response = requests.get(f"{jwt['iss']}/.well-known/openid-configuration")
    if jwks_response.status_code == 200:
        jwks_response = requests.get(jwks_response.json()["jwks_uri"])
        if jwks_response.status_code == 200:
            new_provider = {"cert": jwks_response.text, "iss": jwt['iss'], "aud": jwt['aud']}
            if test_key is not None:
                new_provider['test'] = test_key
    else:
        raise CandigAuthError("couldn't get a response for openid config")
    if new_provider is None:
        raise CandigAuthError("couldn't get a jwks_uri")

    # get the existing values
    response, status_code = get_service_store_secret("opa", key="data")

    if status_code == 200:
        # check to see if it's already here:
        found = False
        for i in range(0, len(response["keys"])):
            s = response["keys"][i]
            if s['iss'] == new_provider['iss']:
                found = True
                if 'test' in new_provider:
                    if 'test' not in s:
                        found = False # not the same because s doesn't have a test key
                    else:
                        if s['test'] != new_provider['test']:
                            found = False # not the same because they have different test keys
                if found:
                    # replace with the new provider data
                    response["keys"][i] = new_provider
                    break
        if not found:
            response["keys"].append(new_provider)
    else:
        response = {
            "keys": [new_provider]
        }
    response, status_code = set_service_store_secret("opa", key="data", value=json.dumps(response))
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
        response, status_code = set_service_store_secret("opa", key="data", value=json.dumps({"keys": new_providers}))
    else:
        raise CandigAuthError("couldn't get data from opa store")
    return response["keys"]

def get_program_in_opa(program_id):
    """
    Returns a ProgramAuthorization for the program_id
    Authorized only if the service requesting it is allowed to see Opa's vault secrets.
    """
    response, status_code = get_service_store_secret("opa", key=f"programs/{program_id}")
    if status_code < 300:
        return response, status_code
    return {"message": f"{program_id} not found"}, status_code


def list_programs_in_opa():
    progs_response, status_code = get_service_store_secret("opa", key="programs")
    if status_code == 200:
        return progs_response['programs'], status_code
    return progs_response, status_code


def add_program_to_opa(program_auth):
    """
    Creates or updates a ProgramAuthorization in Opa for the program_id.
    Authorized only if the requesting service is allowed to write Opa's vault secrets.
    """
    program_id = program_auth["program_id"]
    response, status_code = get_program_in_opa(program_id)
    if status_code < 300 or status_code == 404:
        # create or update the program itself
        if "date_created" not in program_auth:
            from datetime import datetime
            program_auth["date_created"] = datetime.today().strftime('%Y-%m-%d')
        response, status_code = set_service_store_secret("opa", key=f"programs/{program_id}", value=json.dumps({program_id: program_auth}))
        if status_code < 300:
            # update the values for the program list
            response2, status_code = get_service_store_secret("opa", key="programs")

            if status_code == 200:
                # check to see if it's already here:
                if program_id not in response2['programs']:
                    response2['programs'].append(program_id)
            else:
                response2 = {'programs': [program_id]}
            response2, status_code = set_service_store_secret("opa", key="programs", value=json.dumps(response2))
            return response, status_code

    return {"message": f"{program_id} not added"}, status_code


def remove_program_from_opa(program_id):
    """
    Removes the ProgramAuthorization in Opa for the program_id.
    Authorized only if the requesting service is allowed to write Opa's vault secrets.
    """
    response, status_code = get_program_in_opa(program_id)
    if status_code == 404:
        return response, status_code
    if status_code < 300:
        # create or update the program itself
        response = delete_service_store_secret("opa", key=f"programs/{program_id}")

        # update the values for the program list
        response, status_code = get_service_store_secret("opa", key="programs")

        if status_code == 200:
            # check to see if it's here:
            if program_id in response['programs']:
                response['programs'].remove(program_id)
                response, status_code = set_service_store_secret("opa", key="programs", value=json.dumps(response))

        return {"success": f"{program_id} removed"}, status_code
    return {"message": f"{program_id} not removed"}, status_code


def get_vault_token_for_service(service=SERVICE_NAME, vault_url=VAULT_URL, approle_token=None, role_id=None, secret_id=None):
    """
    Get this service's vault token. Should only be called from inside a container.
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
    """
    Set a Vault service store secret. Should only be called from inside a container.
    """
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
    print(f"storing secret of type {str(type(value))}")
    if ("json" in str(type(value))):
        print("converting json to string")
        value = json.dumps(value)
    response = requests.post(url, headers=headers, data=value)
    if response.status_code >= 200 and response.status_code < 300:
        return get_service_store_secret(service, key, token=token)
    return response.json(), response.status_code


def get_service_store_secret(service, key=None, vault_url=VAULT_URL, role_id=None, secret_id=None, token=None):
    """
    Get a Vault service store secret. Should only be called from inside a container.
    """
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


def delete_service_store_secret(service, key=None, vault_url=VAULT_URL, role_id=None, secret_id=None, token=None):
    """
    Delete a Vault service store secret. Should only be called from inside a container.
    """
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
    response = requests.delete(url, headers=headers)
    return response.status_code


def create_service_token(vault_url=VAULT_URL):
    """
    Create a token that can be used to verify this service. Should only be called from inside a container.
    """

    if SERVICE_NAME is None:
        raise CandigAuthError("No SERVICE_NAME specified. Was this called from a CanDIG docker container?")
    # create the random token:
    token = uuid.uuid1()
    try:
        response, status_code = set_service_store_secret(SERVICE_NAME, key=f"token/{token}", value={"token": token})
        if status_code != 200:
            raise CandigAuthError(f"Could not create_service_token from {SERVICE_NAME}: {response}")
    except Exception as e:
        raise CandigAuthError(f"Could not create_service_token from {SERVICE_NAME}: {str(e)}")
    return str(token)


def verify_service_token(service=None, token=None):
    """
    Verify that a token comes from a particular service. Should only be called from inside a container.
    """
    if service is None:
        return False
    if token is None:
        return False
    body = {
        "input": {
            "service": service,
            "token": token
        }
    }

    response = requests.post(
        OPA_URL + "/v1/data/service/verified",
        json=body
    )

    return response.status_code == 200 and "result" in response.json() and response.json()["result"]
