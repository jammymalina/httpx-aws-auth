import typing
from datetime import datetime, timedelta, timezone

import httpx
import pytest
from pytest_mock import MockerFixture

from httpx_aws_auth import AwsSigV4AssumeRoleAuth


@pytest.mark.freeze_time("2024-03-14T12:08:40+0000")
@pytest.mark.parametrize("method_name", ["GET", "GeT", "get"], ids=["GET", "GeT", "get"])
def test_sync_assume_role(mocker: MockerFixture, freezer: typing.Any, method_name: str) -> None:
    now = datetime.now(timezone.utc)
    freezer.move_to(now)
    # Arrange
    sts_mock = mocker.Mock()
    sts_mock.assume_role = mocker.Mock(
        return_value={
            "Credentials": {
                "AccessKeyId": "access_key",
                "SecretAccessKey": "secret_key",
                "SessionToken": "session_token",
                "Expiration": now + timedelta(hours=1),
            }
        }
    )

    session_mock = mocker.Mock()
    session_mock.client = mocker.Mock(return_value=sts_mock)

    auth = AwsSigV4AssumeRoleAuth(
        session=session_mock, role_arn="arn:aws:iam::123456789012:role/test-role", region="eu-west-1"
    )
    request = httpx.Request(
        method=method_name,
        url="https://api.example.com",
    )

    # Act & Assert

    for _ in range(10):
        auth_request = next(auth.sync_auth_flow(request), None)

        assert auth_request is not None
        assert dict(auth_request.headers) == {
            "host": "api.example.com",
            "authorization": "AWS4-HMAC-SHA256 "
            + "Credential=access_key/20240314/eu-west-1/execute-api/aws4_request, "
            + "SignedHeaders=host;x-amz-date;x-amz-security-token, "
            + "Signature=deae23bb2dca27aa37770a33d62af0d9ac0443cb61dcca3fea2682974752e78d",
            "x-amz-date": "20240314T120840Z",
            "x-amz-content-sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "x-amz-security-token": "session_token",
        }

    freezer.move_to(now + timedelta(hours=3))

    auth_request = next(auth.sync_auth_flow(request), None)

    assert auth_request is not None
    assert dict(auth_request.headers) == {
        "host": "api.example.com",
        "authorization": "AWS4-HMAC-SHA256 "
        + "Credential=access_key/20240314/eu-west-1/execute-api/aws4_request, "
        + "SignedHeaders=host;x-amz-date;x-amz-security-token, "
        + "Signature=9eee85cab30de510da389609998a9f8d1b7db0dc1f10a9e08c8714d37cc7157f",
        "x-amz-date": "20240314T150840Z",
        "x-amz-content-sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "x-amz-security-token": "session_token",
    }

    assert sts_mock.assume_role.call_count == 2


@pytest.mark.freeze_time("2024-03-14T12:08:40+0000")
@pytest.mark.parametrize("method_name", ["GET", "GeT", "get"], ids=["GET", "GeT", "get"])
async def test_async_assume_role(mocker: MockerFixture, freezer: typing.Any, method_name: str) -> None:
    now = datetime.now(timezone.utc)
    freezer.move_to(now)
    # Arrange

    sts_mock = mocker.Mock()
    sts_mock.assume_role = mocker.AsyncMock(
        return_value={
            "Credentials": {
                "AccessKeyId": "access_key",
                "SecretAccessKey": "secret_key",
                "SessionToken": "session_token",
                "Expiration": now + timedelta(hours=1),
            }
        }
    )

    sts_mock_context = mocker.AsyncMock()
    sts_mock_context.__aenter__ = mocker.AsyncMock(return_value=sts_mock)
    sts_mock_context.__aexit__ = mocker.AsyncMock(return_value=None)

    session_mock = mocker.Mock()
    session_mock.client = mocker.Mock(return_value=sts_mock_context)

    auth = AwsSigV4AssumeRoleAuth(
        async_session=session_mock, role_arn="arn:aws:iam::123456789012:role/test-role", region="eu-west-1"
    )
    request = httpx.Request(
        method=method_name,
        url="https://api.example.com",
    )

    # Act & Assert

    for _ in range(10):
        auth_request = await auth.async_auth_flow(request).__anext__()

        assert auth_request is not None
        assert dict(auth_request.headers) == {
            "host": "api.example.com",
            "authorization": "AWS4-HMAC-SHA256 "
            + "Credential=access_key/20240314/eu-west-1/execute-api/aws4_request, "
            + "SignedHeaders=host;x-amz-date;x-amz-security-token, "
            + "Signature=deae23bb2dca27aa37770a33d62af0d9ac0443cb61dcca3fea2682974752e78d",
            "x-amz-date": "20240314T120840Z",
            "x-amz-content-sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "x-amz-security-token": "session_token",
        }

    freezer.move_to(now + timedelta(hours=3))

    auth_request = await auth.async_auth_flow(request).__anext__()

    assert auth_request is not None
    assert dict(auth_request.headers) == {
        "host": "api.example.com",
        "authorization": "AWS4-HMAC-SHA256 "
        + "Credential=access_key/20240314/eu-west-1/execute-api/aws4_request, "
        + "SignedHeaders=host;x-amz-date;x-amz-security-token, "
        + "Signature=9eee85cab30de510da389609998a9f8d1b7db0dc1f10a9e08c8714d37cc7157f",
        "x-amz-date": "20240314T150840Z",
        "x-amz-content-sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "x-amz-security-token": "session_token",
    }

    assert sts_mock.assume_role.call_count == 2
