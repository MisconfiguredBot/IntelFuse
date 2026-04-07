"""Provider clients for VirusTotal, GreyNoise, and AbuseIPDB."""

from __future__ import annotations

import base64
import hashlib
import mimetypes
import os
import urllib.parse
import uuid

from .http import HTTPClient
from .models import LookupTarget

VT_API_BASE = "https://www.virustotal.com/api/v3"
GREYNOISE_API_BASE = "https://api.greynoise.io/v3"
ABUSEIPDB_API_BASE = "https://api.abuseipdb.com/api/v2"
LARGE_FILE_THRESHOLD = 32 * 1024 * 1024


def hash_file(path: str) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


class VirusTotalClient:
    def __init__(self, api_key: str, *, timeout: float = 15.0) -> None:
        self.api_key = api_key
        self.http = HTTPClient("VirusTotal", timeout=timeout)

    def fetch_target(self, target: LookupTarget) -> dict:
        return self.http.get_json(self._build_url(target), headers=self._headers())

    def fetch_ip(self, ip: str) -> dict:
        target = LookupTarget(raw_value=ip, kind="ip", endpoint_value=ip)
        return self.fetch_target(target)

    def get_upload_url(self, path: str) -> str:
        size = os.path.getsize(path)
        if size <= LARGE_FILE_THRESHOLD:
            return f"{VT_API_BASE}/files"
        payload = self.http.get_json(f"{VT_API_BASE}/files/upload_url", headers=self._headers())
        upload_url = payload.get("data")
        if not upload_url:
            raise RuntimeError(f"VirusTotal did not return an upload URL for {path}")
        return upload_url

    def upload_file(self, path: str) -> dict:
        upload_url = self.get_upload_url(path)
        body, content_type = self._build_multipart_form(path)
        return self.http.request_json(
            "POST",
            upload_url,
            headers={**self._headers(), "content-type": content_type},
            body=body,
            retries=1,
        )

    def _build_url(self, target: LookupTarget) -> str:
        if target.kind == "ip":
            return f"{VT_API_BASE}/ip_addresses/{urllib.parse.quote(target.endpoint_value)}"
        if target.kind == "file":
            return f"{VT_API_BASE}/files/{urllib.parse.quote(target.endpoint_value)}"
        if target.kind == "url":
            return f"{VT_API_BASE}/urls/{urllib.parse.quote(target.endpoint_value)}"
        raise ValueError(f"Unsupported lookup kind: {target.kind}")

    def _headers(self) -> dict[str, str]:
        return {"x-apikey": self.api_key}

    @staticmethod
    def _build_multipart_form(path: str) -> tuple[bytes, str]:
        boundary = f"----intelfuse{uuid.uuid4().hex}"
        filename = os.path.basename(path)
        mime_type = mimetypes.guess_type(filename)[0] or "application/octet-stream"
        with open(path, "rb") as handle:
            file_bytes = handle.read()

        parts = [
            f"--{boundary}\r\n".encode("ascii"),
            (
                'Content-Disposition: form-data; name="file"; filename="{}"\r\n'.format(filename)
            ).encode("utf-8"),
            f"Content-Type: {mime_type}\r\n\r\n".encode("ascii"),
            file_bytes,
            b"\r\n",
            f"--{boundary}--\r\n".encode("ascii"),
        ]
        return b"".join(parts), f"multipart/form-data; boundary={boundary}"


class GreyNoiseClient:
    def __init__(self, api_key: str | None = None, *, timeout: float = 15.0) -> None:
        self.http = HTTPClient("GreyNoise", timeout=timeout)
        self.api_key = api_key

    def fetch_ip(self, ip: str) -> dict:
        headers = {"key": self.api_key} if self.api_key else None
        return self.http.get_json(
            f"{GREYNOISE_API_BASE}/community/{urllib.parse.quote(ip)}",
            headers=headers,
        )


class AbuseIPDBClient:
    def __init__(self, api_key: str, *, timeout: float = 15.0) -> None:
        self.http = HTTPClient("AbuseIPDB", timeout=timeout)
        self.api_key = api_key

    def fetch_ip(self, ip: str) -> dict:
        return self.http.get_json(
            f"{ABUSEIPDB_API_BASE}/check",
            headers={"Key": self.api_key},
            params={"ipAddress": ip, "maxAgeInDays": 90, "verbose": True},
        )


def encode_url_target(url: str) -> str:
    encoded = base64.urlsafe_b64encode(url.encode("utf-8")).decode("ascii")
    return encoded.rstrip("=")
