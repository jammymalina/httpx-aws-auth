import hashlib
import hmac
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, Generator, Optional
from urllib.parse import quote

import httpx


@dataclass
class AwsCredentials:
    access_key: str
    secret_key: str
    session_token: Optional[str] = None
    expiration: datetime = field(default_factory=lambda: datetime.max.replace(tzinfo=timezone.utc))


class AwsSigV4Auth(httpx.Auth):
    service: str
    credentials: AwsCredentials
    region: str

    def __init__(self, credentials: AwsCredentials, region: str, service: str = "execute-api") -> None:
        self.credentials = credentials
        self.region = region
        self.service = service

    def auth_flow(self, request: httpx.Request) -> Generator[httpx.Request, httpx.Response, None]:
        aws_headers = self.__get_aws_auth_headers(request)
        request.headers.update(aws_headers)
        yield request

    def __get_aws_auth_headers(self, request: httpx.Request) -> Dict[str, str]:
        current_time = datetime.now(timezone.utc)
        amzdate = current_time.strftime("%Y%m%dT%H%M%SZ")
        datestamp = current_time.strftime("%Y%m%d")

        aws_host = request.url.netloc.decode("utf-8")

        canonical_uri = self.__get_canonical_path(request)
        canonical_querystring = self.__get_canonical_querystring(request)

        canonical_headers = "host:" + aws_host + "\n" + "x-amz-date:" + amzdate + "\n"
        if self.credentials.session_token:
            canonical_headers += "x-amz-security-token:" + self.credentials.session_token + "\n"

        signed_headers = "host;x-amz-date"
        if self.credentials.session_token:
            signed_headers += ";x-amz-security-token"

        payload_hash = hashlib.sha256(request.content).hexdigest()

        canonical_request: str = (
            str(request.method)
            + "\n"
            + canonical_uri
            + "\n"
            + canonical_querystring
            + "\n"
            + canonical_headers
            + "\n"
            + signed_headers
            + "\n"
            + payload_hash
        )

        algorithm = "AWS4-HMAC-SHA256"
        credential_scope = datestamp + "/" + self.region + "/" + self.service + "/" + "aws4_request"
        string_to_sign = (
            algorithm
            + "\n"
            + amzdate
            + "\n"
            + credential_scope
            + "\n"
            + hashlib.sha256(canonical_request.encode("utf-8")).hexdigest()
        )

        signing_key = self.__get_signature_key(
            secret_key=self.credentials.secret_key, datestamp=datestamp, region=self.region
        )

        string_to_sign_utf8 = string_to_sign.encode("utf-8")
        signature = hmac.new(signing_key, string_to_sign_utf8, hashlib.sha256).hexdigest()

        authorization_header = (
            algorithm
            + " "
            + "Credential="
            + self.credentials.access_key
            + "/"
            + credential_scope
            + ", "
            + "SignedHeaders="
            + signed_headers
            + ", "
            + "Signature="
            + signature
        )

        headers = {"Authorization": authorization_header, "x-amz-date": amzdate, "x-amz-content-sha256": payload_hash}
        if self.credentials.session_token:
            headers["X-Amz-Security-Token"] = self.credentials.session_token
        return headers

    def __sign(self, key: bytes, msg: str) -> bytes:
        return hmac.new(key, msg.encode("utf-8"), hashlib.sha256).digest()

    def __get_signature_key(self, secret_key: str, datestamp: str, region: str) -> bytes:
        signed_date = self.__sign(("AWS4" + secret_key).encode("utf-8"), datestamp)
        signed_region = self.__sign(signed_date, region)
        signed_service = self.__sign(signed_region, self.service)
        signature = self.__sign(signed_service, "aws4_request")
        return signature

    def __get_canonical_path(self, request: httpx.Request) -> str:
        return quote(request.url.path if request.url.path else "/", safe="/-_.~")

    def __get_canonical_querystring(self, request: httpx.Request) -> str:
        canonical_querystring = ""

        querystring_sorted = "&".join(sorted(request.url.query.decode("utf-8").split("&")))

        for query_param in querystring_sorted.split("&"):
            key_val_split = query_param.split("=", 1)

            key = key_val_split[0]
            if len(key_val_split) > 1:
                val = key_val_split[1]
            else:
                val = ""

            if key:
                if canonical_querystring:
                    canonical_querystring += "&"
                canonical_querystring += "=".join([key, val])

        return canonical_querystring
