import requests
import os
import pytest
import authx.auth
import tempfile
from pathlib import Path
import warnings

CANDIG_OPA_SITE_ADMIN_KEY = os.getenv("OPA_SITE_ADMIN_KEY", "site_admin")
KEYCLOAK_PUBLIC_URL = os.getenv('KEYCLOAK_PUBLIC_URL', None)
OPA_URL = os.getenv('OPA_URL', None)
OPA_SECRET = os.getenv('OPA_SECRET', None)
VAULT_URL = os.getenv('VAULT_URL', None)
VAULT_S3_TOKEN = os.getenv('VAULT_S3_TOKEN', None)
SITE_ADMIN_USER = os.getenv("CANDIG_SITE_ADMIN_USER", None)
SITE_ADMIN_PASSWORD = os.getenv("CANDIG_SITE_ADMIN_PASSWORD", None)
NOT_ADMIN_USER = os.getenv("CANDIG_NOT_ADMIN_USER", None)
NOT_ADMIN_PASSWORD = os.getenv("CANDIG_NOT_ADMIN_PASSWORD", None)


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

def test_site_admin():
    """
    If OPA is present, check to see if SITE_ADMIN_USER is a site admin and that NOT_ADMIN_USER isn't. Otherwise, just assert True.
    """
    if OPA_URL is not None:
        print(f"{OPA_URL} {OPA_SECRET}")
        assert authx.auth.is_site_admin(FakeRequest(site_admin=True), opa_url=OPA_URL, admin_secret=OPA_SECRET, site_admin_key=CANDIG_OPA_SITE_ADMIN_KEY)
        assert not authx.auth.is_site_admin(FakeRequest(), opa_url=OPA_URL, admin_secret=OPA_SECRET, site_admin_key=CANDIG_OPA_SITE_ADMIN_KEY)

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
        assert "controlled4" in user_datasets

        # user2 has controlled5 in its datasets
        user_datasets = authx.auth.get_opa_datasets(FakeRequest(site_admin=True), admin_secret=OPA_SECRET)
        print(user_datasets)
        assert "controlled5" in user_datasets
    else:
        warnings.warn(UserWarning("OPA_URL is not set"))


def test_put_aws_credential():
    """
    Test adding credentials to Vault
    """
    if VAULT_URL is not None:
        endpoint = "http://test.endpoint"
        # store credential using vault_s3_token and not-site-admin token
        result, status_code = authx.auth.store_aws_credential(token=authx.auth.get_auth_token(FakeRequest()),endpoint=endpoint, bucket="test_bucket", access="test", secret="secret", vault_url=VAULT_URL, vault_s3_token=VAULT_S3_TOKEN)
        print(result, status_code)
        assert status_code == 200

        # try getting it with a non-site_admin token
        result, status_code = authx.auth.get_aws_credential(token=authx.auth.get_auth_token(FakeRequest()), vault_url=VAULT_URL, endpoint=endpoint, bucket="test_bucket", vault_s3_token=None)
        print(result)
        assert "errors" in result

        # try getting it with a site_admin token
        result, status_code = authx.auth.get_aws_credential(token=authx.auth.get_auth_token(FakeRequest(site_admin=True)), vault_url=VAULT_URL, endpoint=endpoint, bucket="test_bucket", vault_s3_token=None)
        assert result['secret'] == 'secret'
        assert result['url'] == 'test.endpoint'
    else:
        warnings.warn(UserWarning("VAULT_URL is not set"))


# def test_get_s3_url():
#     """
#     Put something in a minio bucket (playbox endpoint) and then get it back
#     """
#     text = "test test"
#
#     fp = tempfile.NamedTemporaryFile()
#     fp.write(bytes(text, 'utf-8'))
#     fp.seek(0)
#     minio = authx.auth.get_minio_client(token=authx.auth.get_auth_token(FakeRequest()))
#     filename = Path(fp.name).name
#     minio['client'].put_object(minio['bucket'], filename, fp, Path(fp.name).stat().st_size)
#     fp.close()
#
#     url, status_code = authx.auth.get_s3_url(FakeRequest(), object_id=filename)
#     print(url)
#     assert status_code == 200
#
#     response = requests.get(url)
#     print(response.text)
#     assert response.text == str(text)

def test_get_public_s3_url():
    url, status_code = authx.auth.get_s3_url(FakeRequest(), public=True, bucket="1000genomes", s3_endpoint="http://s3.us-east-1.amazonaws.com", object_id="README.ebi_aspera_info", access_key=None, secret_key=None, region="us-east-1")
    response = requests.get(url)
    print(response.text)
    assert "If you wish to use aspera" in response.text
