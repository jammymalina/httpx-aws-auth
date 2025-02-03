from typing import Any

import httpx
import pytest

from httpx_aws_auth import AwsCredentials, AwsSigV4Auth


@pytest.mark.freeze_time("2024-03-14T12:08:40+0000")
@pytest.mark.parametrize("method_name", ["GET", "GeT", "get"], ids=["GET", "GeT", "get"])
def test_aws_request_auth_simple_get(method_name: str) -> None:
    # Arrange
    credentials = AwsCredentials(
        access_key="access_key",
        secret_key="secret_key",
        session_token="session_token",
    )

    auth = AwsSigV4Auth(credentials=credentials, region="eu-west-1")
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
        (None, "param1=some+value&param2=a+diff+value"),
        (None, "param2=a+diff+value&param1=some+value"),
    ],
    ids=["dict_sort", "dict_sort_reverse", "string_sort", "string_sort_reverse"],
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

    auth = AwsSigV4Auth(credentials=credentials, region="eu-west-1")
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
        + "Signature=ad22e5c46b0d5927747edd33245c7eee70322c63c789a9f5285c9339c46c8784",
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

    auth = AwsSigV4Auth(credentials=credentials, region="eu-west-1")
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
        "content-length": "33",
        "content-type": "application/json",
        "authorization": "AWS4-HMAC-SHA256 "
        + "Credential=access_key/20240314/eu-west-1/execute-api/aws4_request, "
        + "SignedHeaders=host;x-amz-date;x-amz-security-token, "
        + "Signature=f1808546ef192f3141bb08a678fed95b623f1611c11dbe5d67323a0a04aa6e13",
        "x-amz-date": "20240314T120840Z",
        "x-amz-content-sha256": "b734413c644ec49f6a7c07d88b267244582d6422d89eee955511f6b3c0dcb0f2",
        "x-amz-security-token": "session_token",
    }
