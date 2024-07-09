from httpx_aws_auth import AwsCredentials, AWSSigV4Auth

from typing import Any

import httpx
import pytest


@pytest.mark.freeze_time("2024-03-14T12:08:40+0000")
@pytest.mark.parametrize("method_name", ["GET", "GeT", "get"], ids=["GET", "GeT", "get"])
def test_aws_request_auth_simple_get(method_name: str) -> None:
    # Arrange
    credentials = AwsCredentials(
        access_key="access_key",
        secret_key="secret_key",
        session_token="session_token",
    )

    auth = AWSSigV4Auth(credentials=credentials, region="eu-west-1")
    request = httpx.Request(
        method=method_name,
        url="https://api.example.com",
    )

    # Act
    auth_request = next(auth.auth_flow(request), None)

    # Assert
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


@pytest.mark.freeze_time("2024-03-14T12:08:40+0000")
@pytest.mark.parametrize(
    "query_params, query_params_string",
    [
        ({"param1": "some value", "param2": "a diff value"}, ""),
        ({"param2": "a diff value", "param1": "some value"}, ""),
        (None, "param1=some%20value&param2=a%20diff%20value"),
        (None, "param2=a%20diff%20value&param1=some%20value"),
        (None, "param1=some value&param2=a diff value"),
    ],
    ids=["dict_sort", "dict_sort_reverse", "string_sort", "string_sort_reverse", "unescaped_query_string"],
)
def test_aws_request_auth_get_query_strings(query_params: Any, query_params_string: str) -> None:
    # Arrange
    credentials = AwsCredentials(
        access_key="access_key",
        secret_key="secret_key",
        session_token="session_token",
    )

    url = "https://api.example.com"
    if query_params_string:
        url += "?" + query_params_string

    auth = AWSSigV4Auth(credentials=credentials, region="eu-west-1")
    request = httpx.Request(
        method="GET",
        url=url,
        params=query_params,
    )

    # Act
    auth_request = next(auth.auth_flow(request), None)

    # Assert
    assert auth_request is not None
    assert dict(auth_request.headers) == {
        "host": "api.example.com",
        "authorization": "AWS4-HMAC-SHA256 "
        + "Credential=access_key/20240314/eu-west-1/execute-api/aws4_request, "
        + "SignedHeaders=host;x-amz-date;x-amz-security-token, "
        + "Signature=7f3371485625d9bacabb71ac47afb8144968c23185dc2464f5b0652f80b6d2b5",
        "x-amz-date": "20240314T120840Z",
        "x-amz-content-sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "x-amz-security-token": "session_token",
    }


@pytest.mark.freeze_time("2024-03-14T12:08:40+0000")
def test_aws_request_auth_post_content() -> None:
    # Arrange
    credentials = AwsCredentials(
        access_key="access_key",
        secret_key="secret_key",
        session_token="session_token",
    )

    auth = AWSSigV4Auth(credentials=credentials, region="eu-west-1")
    request = httpx.Request(
        method="POST",
        url="https://api.example.com",
        json={"key1": "value1", "key2": "value2"},
    )

    # Act
    auth_request = next(auth.auth_flow(request), None)

    # Assert
    assert auth_request is not None
    assert dict(auth_request.headers) == {
        "host": "api.example.com",
        "content-length": "36",
        "content-type": "application/json",
        "authorization": "AWS4-HMAC-SHA256 "
        + "Credential=access_key/20240314/eu-west-1/execute-api/aws4_request, "
        + "SignedHeaders=host;x-amz-date;x-amz-security-token, "
        + "Signature=6f4a1511f97aac9a51e0f92e47853d6f2171b705783d364d6376820963c4d203",
        "x-amz-date": "20240314T120840Z",
        "x-amz-content-sha256": "6366030fcfbc5e29da7855c8a2c2c0c48670a1cc067d7dbeb1481865105f9515",
        "x-amz-security-token": "session_token",
    }
