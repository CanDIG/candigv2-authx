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


class FakeRequest:
    def __init__(self, token=None):
        if KEYCLOAK_PUBLIC_URL is None:
            warnings.warn(UserWarning("KEYCLOAK_URL is not set"))
            token = "testtesttest"
        else:
            token = authx.auth.get_access_token(
                keycloak_url=KEYCLOAK_PUBLIC_URL,
                username=SITE_ADMIN_USER,
                password=SITE_ADMIN_PASSWORD
                )
        self.headers = {"Authorization": f"Bearer {token}"}
        self.path = f"/htsget/v1/variants/search"
        self.method = "GET"

def test_site_admin():
    """
    If OPA is present, check to see if user2 is a site admin. Otherwise, just assert True.
    """
    if OPA_URL is not None:
        print(f"{OPA_URL} {OPA_SECRET}")
        assert authx.auth.is_site_admin(FakeRequest(), opa_url=OPA_URL, admin_secret=OPA_SECRET, site_admin_key=CANDIG_OPA_SITE_ADMIN_KEY)
    else:
        warnings.warn(UserWarning("OPA_URL is not set"))


def test_get_opa_datasets():
    """
    Get allowed dataset result from OPA
    """
    if OPA_URL is not None:
        # user2 by default has three datasets, open1, open2, and controlled5
        assert len(authx.auth.get_opa_datasets(FakeRequest())) >= 3
    else:
        warnings.warn(UserWarning("OPA_URL is not set"))


def test_put_aws_credential():
    """
    Test adding credentials to Vault
    """
    if VAULT_URL is not None:
        endpoint = "http://test.endpoint"
        result, status_code = authx.auth.store_aws_credential(endpoint=endpoint, bucket="test_bucket", access="test", secret="secret", keycloak_url=KEYCLOAK_PUBLIC_URL, vault_url=VAULT_URL)
        print(result, status_code)
        assert status_code == 200

        result, status_code = authx.auth.get_aws_credential(token=authx.auth.get_auth_token(FakeRequest()), vault_url=VAULT_URL, endpoint=endpoint, bucket="test_bucket", vault_s3_token=VAULT_S3_TOKEN)
        print(result, status_code)
        assert result['secret'] == 'secret'
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
    minio = authx.auth.get_minio_client(token=authx.auth.get_auth_token(FakeRequest()))
    filename = Path(fp.name).name
    minio['client'].put_object(minio['bucket'], filename, fp, Path(fp.name).stat().st_size)
    fp.close()

    url, status_code = authx.auth.get_s3_url(FakeRequest(), object_id=filename)
    print(url)
    assert status_code == 200

    response = requests.get(url)
    print(response.text)
    assert response.text == str(text)
