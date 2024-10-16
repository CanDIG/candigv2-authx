import requests
import os
import pytest
import authx.auth
import tempfile
from pathlib import Path
import warnings
import time


CANDIG_OPA_SITE_ADMIN_KEY = os.getenv("OPA_SITE_ADMIN_KEY", "site_admin")
KEYCLOAK_PUBLIC_URL = os.getenv('KEYCLOAK_PUBLIC_URL', None)
OPA_URL = os.getenv('OPA_URL', None)
OPA_SECRET = os.getenv('OPA_SECRET', None)
VAULT_URL = os.getenv('VAULT_URL', None)
SITE_ADMIN_USER = os.getenv("CANDIG_SITE_ADMIN_USER", None)
SITE_ADMIN_PASSWORD = os.getenv("CANDIG_SITE_ADMIN_PASSWORD", None)
NOT_ADMIN_USER = os.getenv("CANDIG_NOT_ADMIN_USER", None)
NOT_ADMIN_PASSWORD = os.getenv("CANDIG_NOT_ADMIN_PASSWORD", None)
MINIO_URL = os.getenv("MINIO_URL", None)
MINIO_ACCESS_KEY = os.getenv("MINIO_ACCESS_KEY", None)
MINIO_SECRET_KEY = os.getenv("MINIO_SECRET_KEY", None)
TYK_SECRET_KEY = os.getenv("TYK_SECRET_KEY")
TYK_LOGIN_TARGET_URL = os.getenv("TYK_LOGIN_TARGET_URL")
SERVICE_NAME = os.getenv("SERVICE_NAME")


class FakeRequest:
    def __init__(self, token=None, site_admin=False):
        if KEYCLOAK_PUBLIC_URL is None:
            warnings.warn(UserWarning("KEYCLOAK_URL is not set"))
            token = "testtesttest"
        elif site_admin:
            token = authx.auth.get_access_token(
                keycloak_url=KEYCLOAK_PUBLIC_URL,
                username=SITE_ADMIN_USER,
                password=SITE_ADMIN_PASSWORD
                )
        else:
            token = authx.auth.get_access_token(
                keycloak_url=KEYCLOAK_PUBLIC_URL,
                username=NOT_ADMIN_USER,
                password=NOT_ADMIN_PASSWORD
                )
        self.headers = {"Authorization": f"Bearer {token}"}
        self.path = f"/htsget/v1/variants/search"
        self.method = "GET"


def test_add_opa_provider():
    """
    If OPA is present, try adding a new provider (just ourselves again). Otherwise, just assert True.
    """
    if KEYCLOAK_PUBLIC_URL is None:
        warnings.warn(UserWarning("KEYCLOAK_URL is not set"))
        return

    if OPA_URL is not None:
        token = authx.auth.get_access_token(
        keycloak_url=KEYCLOAK_PUBLIC_URL,
        username=SITE_ADMIN_USER,
        password=SITE_ADMIN_PASSWORD
        )
        test_key="testtest"
        response = authx.auth.add_provider_to_opa(token, f"{KEYCLOAK_PUBLIC_URL}/auth/realms/candig", test_key=test_key)
        print(response)
        assert len(response) > 0
        found = False
        for p in response:
            if 'test' in p and p['test'] == test_key:
                found = True
        assert found

        # try adding the same thing again: the count should stay the same
        count = len(response)
        response = authx.auth.add_provider_to_opa(token, f"{KEYCLOAK_PUBLIC_URL}/auth/realms/candig", test_key=test_key)
        assert len(response) == count
    else:
        warnings.warn(UserWarning("OPA_URL is not set"))


def test_site_admin():
    """
    If OPA is present, check to see if SITE_ADMIN_USER is a site admin and that NOT_ADMIN_USER isn't. Otherwise, just assert True.
    """
    if OPA_URL is not None:
        print(f"{OPA_URL} {OPA_SECRET}")
        assert authx.auth.is_site_admin(FakeRequest(site_admin=True), opa_url=OPA_URL, admin_secret=OPA_SECRET)
        assert not authx.auth.is_site_admin(FakeRequest(), opa_url=OPA_URL, admin_secret=OPA_SECRET)

    else:
        warnings.warn(UserWarning("OPA_URL is not set"))


def test_user_email():
        """
        If OPA is present, check to see that the user's email is returned.
        """
        if OPA_URL is not None:
            assert authx.auth.get_user_email(FakeRequest(site_admin=True), opa_url=OPA_URL, admin_secret=OPA_SECRET) == f"{SITE_ADMIN_USER}@test.ca"
        else:
            warnings.warn(UserWarning("OPA_URL is not set"))


def test_remove_opa_provider():
    """
    If OPA is present, remove the test provider we added before. Otherwise, just assert True.
    """
    if KEYCLOAK_PUBLIC_URL is None:
        warnings.warn(UserWarning("KEYCLOAK_URL is not set"))
        return

    if OPA_URL is not None:
        token = authx.auth.get_access_token(
        keycloak_url=KEYCLOAK_PUBLIC_URL,
        username=SITE_ADMIN_USER,
        password=SITE_ADMIN_PASSWORD
        )
        test_key="testtest"

        response = authx.auth.add_provider_to_opa(token, f"{KEYCLOAK_PUBLIC_URL}/auth/realms/candig", test_key=test_key)
        count = len(response)
        response = authx.auth.remove_provider_from_opa(KEYCLOAK_PUBLIC_URL, test_key=test_key)
        assert len(response) < count
        found = False
        for p in response:
            if 'test' in p and p['test'] == test_key:
                found = True
        assert not found
    else:
        warnings.warn(UserWarning("OPA_URL is not set"))


def test_get_opa_datasets():
    """
    Get allowed dataset result from OPA
    """
    if OPA_URL is not None:
        # try to get user1 datasets without OPA_SECRET:
        try:
            user_datasets = authx.auth.get_opa_datasets(FakeRequest())
        except requests.HTTPError as e:
            # get_opa_datasets should raise an error
            assert True

        # user1 has controlled4 in its datasets
        user_datasets = authx.auth.get_opa_datasets(FakeRequest(), admin_secret=OPA_SECRET)
        print(user_datasets)
        assert "SYNTHETIC-1" in user_datasets

        # user2 has controlled5 in its datasets
        user_datasets = authx.auth.get_opa_datasets(FakeRequest(site_admin=True), admin_secret=OPA_SECRET)
        print(user_datasets)
        assert "SYNTHETIC-2" in user_datasets
    else:
        warnings.warn(UserWarning("OPA_URL is not set"))


def test_put_aws_credential():
    """
    Test adding credentials to Vault
    """
    if VAULT_URL is not None:
        if os.getenv("SERVICE_NAME") != "candig-ingest":
            warnings.warn(UserWarning("aws credential tests can only be run within the candig-ingest container"))
            return
        endpoint = "http://test.endpoint"
        # store credential using not-site-admin token
        result, status_code = authx.auth.store_aws_credential(token=authx.auth.get_auth_token(FakeRequest()), endpoint=endpoint, bucket="test_bucket", access="test", secret="secret", vault_url=VAULT_URL)
        print(result, status_code)
        assert status_code == 200

        # try getting it with a non-site_admin token
        result, status_code = authx.auth.get_aws_credential(token=authx.auth.get_auth_token(FakeRequest()), vault_url=VAULT_URL, endpoint=endpoint, bucket="test_bucket")
        print(result)
        assert "errors" in result

        # try getting it with a site_admin token
        result, status_code = authx.auth.get_aws_credential(token=authx.auth.get_auth_token(FakeRequest(site_admin=True)), vault_url=VAULT_URL, endpoint=endpoint, bucket="test_bucket")
        assert result['secret'] == 'secret'
        assert result['url'] == 'test.endpoint'
    else:
        warnings.warn(UserWarning("VAULT_URL is not set"))


def test_get_s3_url():
    """
    Put something in a minio bucket (playbox endpoint) and then get it back
    """
    text = "test test"

    fp = tempfile.NamedTemporaryFile()
    fp.write(bytes(text, 'utf-8'))
    fp.seek(0)
    if MINIO_URL is not None:
        if VAULT_URL is not None:
            if os.getenv("SERVICE_NAME") != "candig-ingest":
                warnings.warn(UserWarning("aws credential tests can only be run within the candig-ingest container"))
                return
            result, status_code = authx.auth.store_aws_credential(token=authx.auth.get_auth_token(FakeRequest()),endpoint=MINIO_URL, bucket="test", access=MINIO_ACCESS_KEY, secret=MINIO_SECRET_KEY, vault_url=VAULT_URL)
            assert result['url'] in MINIO_URL
            minio = authx.auth.get_minio_client(token=authx.auth.get_auth_token(FakeRequest()), s3_endpoint=MINIO_URL, bucket="test")
            assert minio['endpoint'] == MINIO_URL
        else:
            warnings.warn(UserWarning("VAULT_URL is not set"))
        minio = authx.auth.get_minio_client(token=authx.auth.get_auth_token(FakeRequest()), s3_endpoint=MINIO_URL, access_key=MINIO_ACCESS_KEY, secret_key=MINIO_SECRET_KEY, bucket="test")
    else:
        warnings.warn(UserWarning("MINIO_URL is not set"))
        return
    filename = Path(fp.name).name
    minio['client'].put_object(minio['bucket'], filename, fp, Path(fp.name).stat().st_size)
    fp.close()

    url_obj, status_code = authx.auth.get_s3_url(object_id=filename, s3_endpoint=minio['endpoint'], bucket=minio['bucket'], access_key=minio['access'], secret_key=minio['secret'])
    print(url_obj["url"])
    assert status_code == 200

    response = requests.get(url_obj["url"])
    print(response.text)
    assert response.text == str(text)
    minio['client'].remove_object(minio['bucket'], filename)


def test_get_public_s3_url():
    url_obj, status_code = authx.auth.get_s3_url(public=True, bucket="1000genomes", s3_endpoint="http://s3.us-east-1.amazonaws.com", object_id="README.ebi_aspera_info", access_key=None, secret_key=None, region="us-east-1")
    response = requests.get(url_obj["url"])
    print(response.text)
    assert "If you wish to use aspera" in response.text


def test_tyk_api():
    if KEYCLOAK_PUBLIC_URL is None:
        warnings.warn(UserWarning("KEYCLOAK_URL is not set"))
        return

    token = authx.auth.get_access_token(
    keycloak_url=KEYCLOAK_PUBLIC_URL,
    username=SITE_ADMIN_USER,
    password=SITE_ADMIN_PASSWORD
    )
    policy_id="testtest"
    response = authx.auth.add_provider_to_tyk_api("91", token, f"{KEYCLOAK_PUBLIC_URL}/auth/realms/candig", policy_id=policy_id)
    assert response.status_code == 200
    time.sleep(5) # tyk takes a second to refresh this after reloading
    url = f"{TYK_LOGIN_TARGET_URL}/tyk/apis/91"
    headers = { "x-tyk-authorization": TYK_SECRET_KEY }
    response = requests.request("GET", url, headers=headers)
    print(response.json()['openid_options']['providers'])
    found = False
    for p in response.json()['openid_options']['providers']:
        if policy_id in p['client_ids'].values():
            found = True
    assert found

    # try adding the same thing again: the count should stay the same
    count = len(response.json()['openid_options']['providers'])
    response = authx.auth.add_provider_to_tyk_api("91", token, f"{KEYCLOAK_PUBLIC_URL}/auth/realms/candig", policy_id=policy_id)
    assert response.status_code == 200
    time.sleep(5) # tyk takes a second to refresh this after reloading
    assert len(response.json()['openid_options']['providers']) == count

    response = authx.auth.remove_provider_from_tyk_api("91", KEYCLOAK_PUBLIC_URL, policy_id=policy_id)
    time.sleep(5) # tyk takes a second to refresh this after reloading
    assert response.status_code == 200
    response = requests.request("GET", url, headers=headers)
    print(response.json()['openid_options']['providers'])
    found = False
    for p in response.json()['openid_options']['providers']:
        if policy_id in p['client_ids'].values():
            found = True
    assert not found

def test_service_store_secret():
    """
    Test adding secrets to Vault
    """
    if VAULT_URL is not None:
        # we can only test the service store of the service we're in:
        if SERVICE_NAME is None:
            warnings.warn(UserWarning("SERVICE_NAME is not set"))
        else:
            data = {"payload": "test"}
            response, status_code = authx.auth.set_service_store_secret(SERVICE_NAME, key="testtest", value=data)
            print(response)
            assert status_code == 200
            assert response["payload"] == "test"
    else:
        warnings.warn(UserWarning("VAULT_URL is not set"))

def test_verify_service():
    """
    Test verifying the service
    """
    if VAULT_URL is not None:
        # we can only test the service store of the service we're in:
        if SERVICE_NAME is None:
            warnings.warn(UserWarning("SERVICE_NAME is not set"))
        else:
            token = authx.auth.create_service_token()
            assert authx.auth.verify_service_token(service=SERVICE_NAME, token=token)
            assert not authx.auth.verify_service_token(service=SERVICE_NAME, token="foo")
    else:
        warnings.warn(UserWarning("VAULT_URL is not set"))
