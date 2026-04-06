#!/usr/bin/env python3
"""VirusTotal CLI lookup tool with interactive mode and optional uploads."""

from __future__ import annotations

import argparse
import base64
import hashlib
import ipaddress
import json
import mimetypes
import os
import sys
import urllib.error
import urllib.parse
import urllib.request
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone


API_BASE = "https://www.virustotal.com/api/v3"
LARGE_FILE_THRESHOLD = 32 * 1024 * 1024


class APIError(RuntimeError):
    def __init__(self, target: str, status_code: int, payload: dict | None = None):
        self.target = target
        self.status_code = status_code
        self.payload = payload or {}
        error = self.payload.get("error", {})
        code = error.get("code", "APIError")
        message = error.get("message", "Unknown VirusTotal API error")
        super().__init__(f"VirusTotal API error for {target}: HTTP {status_code} {code}: {message}")


@dataclass(frozen=True)
class LookupTarget:
    raw_value: str
    kind: str
    endpoint_value: str
    local_path: str | None = None


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Query VirusTotal for IP addresses, file hashes, URLs, and local files."
    )
    parser.add_argument(
        "targets",
        nargs="*",
        help="One or more IPs, hashes, URLs, or local file paths to query.",
    )
    parser.add_argument(
        "--api-key",
        dest="api_key",
        help="VirusTotal API key. Defaults to VT_API_KEY environment variable.",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Print the raw VirusTotal response JSON for each target.",
    )
    parser.add_argument(
        "--upload-missing",
        action="store_true",
        help="Upload local files if VirusTotal has no existing result for their hash.",
    )
    return parser.parse_args()


def prompt_for_targets() -> list[str]:
    print("Interactive mode")
    print("Paste one or more IPs, hashes, URLs, or local file paths.")
    print("Press Enter on a blank line when finished.")

    collected: list[str] = []

    while True:
        prompt = "target> " if not collected else "next>   "
        try:
            line = input(prompt)
        except EOFError:
            break

        stripped = line.strip()
        if not stripped:
            break

        collected.extend(stripped.split())

    if not collected:
        raise ValueError("No targets provided.")

    return collected


def hash_file(path: str) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def classify_target(value: str) -> LookupTarget:
    stripped = value.strip()
    if not stripped:
        raise ValueError("Empty target provided.")

    if os.path.isfile(stripped):
        return LookupTarget(stripped, "file", hash_file(stripped), local_path=os.path.abspath(stripped))

    try:
        ipaddress.ip_address(stripped)
    except ValueError:
        pass
    else:
        return LookupTarget(stripped, "ip", stripped)

    lowered = stripped.lower()
    if lowered.startswith(("http://", "https://")):
        encoded = base64.urlsafe_b64encode(stripped.encode("utf-8")).decode("ascii")
        return LookupTarget(stripped, "url", encoded.rstrip("="))

    if all(ch in "0123456789abcdefABCDEF" for ch in stripped) and len(stripped) in {32, 40, 64}:
        return LookupTarget(stripped, "file", stripped.lower())

    raise ValueError(
        f"Unsupported target: {value!r}. Expected an IP, URL, MD5/SHA1/SHA256 hash, or local file path."
    )


def api_request(
    api_key: str,
    method: str,
    url: str,
    *,
    target_label: str,
    accept_json: bool = True,
    body: bytes | None = None,
    content_type: str | None = None,
) -> dict:
    headers = {
        "x-apikey": api_key,
        "user-agent": "vt-lookup-cli",
    }
    if accept_json:
        headers["accept"] = "application/json"
    if content_type:
        headers["content-type"] = content_type

    request = urllib.request.Request(url, headers=headers, method=method, data=body)

    try:
        with urllib.request.urlopen(request, timeout=60) as response:
            if not accept_json:
                return {}
            return json.load(response)
    except urllib.error.HTTPError as exc:
        raw = exc.read().decode("utf-8", errors="replace")
        try:
            payload = json.loads(raw) if raw else {}
        except json.JSONDecodeError:
            payload = {"error": {"code": "HTTPError", "message": raw or "No response body"}}
        raise APIError(target_label, exc.code, payload) from exc
    except urllib.error.URLError as exc:
        raise RuntimeError(f"Network error for {target_label}: {exc.reason}") from exc


def build_url(target: LookupTarget) -> str:
    if target.kind == "ip":
        return f"{API_BASE}/ip_addresses/{urllib.parse.quote(target.endpoint_value)}"
    if target.kind == "file":
        return f"{API_BASE}/files/{urllib.parse.quote(target.endpoint_value)}"
    if target.kind == "url":
        return f"{API_BASE}/urls/{urllib.parse.quote(target.endpoint_value)}"
    raise ValueError(f"Unsupported lookup kind: {target.kind}")


def fetch_result(api_key: str, target: LookupTarget) -> dict:
    return api_request(api_key, "GET", build_url(target), target_label=target.raw_value)


def get_upload_url(api_key: str, path: str) -> str:
    size = os.path.getsize(path)
    if size <= LARGE_FILE_THRESHOLD:
        return f"{API_BASE}/files"

    payload = api_request(api_key, "GET", f"{API_BASE}/files/upload_url", target_label=path)
    upload_url = payload.get("data")
    if not upload_url:
        raise RuntimeError(f"VirusTotal did not return an upload URL for {path}")
    return upload_url


def build_multipart_form(path: str) -> tuple[bytes, str]:
    boundary = f"----vtlookup{uuid.uuid4().hex}"
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


def upload_file(api_key: str, path: str) -> dict:
    upload_url = get_upload_url(api_key, path)
    body, content_type = build_multipart_form(path)
    return api_request(
        api_key,
        "POST",
        upload_url,
        target_label=path,
        body=body,
        content_type=content_type,
    )


def format_timestamp(value: int | None) -> str:
    if not value:
        return "n/a"
    return datetime.fromtimestamp(value, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def join_values(values: list[str] | dict | None, limit: int = 5) -> str:
    if not values:
        return "n/a"
    if isinstance(values, dict):
        ordered = [f"{key}={value}" for key, value in sorted(values.items())]
        return ", ".join(ordered[:limit]) or "n/a"
    return ", ".join(str(value) for value in values[:limit]) or "n/a"


def detection_summary(attributes: dict) -> str:
    stats = attributes.get("last_analysis_stats", {})
    keys = ["malicious", "suspicious", "harmless", "undetected", "timeout"]
    return ", ".join(f"{key}={stats.get(key, 0)}" for key in keys)


def top_detections(attributes: dict, limit: int = 5) -> str:
    results = attributes.get("last_analysis_results", {})
    matches: list[str] = []
    for engine, result in results.items():
        category = result.get("category")
        if category not in {"malicious", "suspicious"}:
            continue
        label = result.get("result") or category
        matches.append(f"{engine}: {label}")
        if len(matches) >= limit:
            break
    return "; ".join(matches) if matches else "none"


def print_common_result(target: LookupTarget, payload: dict) -> tuple[dict, dict]:
    data = payload.get("data", {})
    attributes = data.get("attributes", {})

    display_type = "file" if target.kind == "file" else target.kind
    print(f"Target:        {target.raw_value}")
    print(f"Lookup type:   {display_type}")
    if target.local_path:
        print(f"Local file:    {target.local_path}")
        print(f"Computed hash: {target.endpoint_value}")
    print(f"ID:            {data.get('id', 'n/a')}")
    print(f"Stats:         {detection_summary(attributes)}")
    print(f"Detections:    {top_detections(attributes)}")

    votes = attributes.get("total_votes", {})
    if votes:
        print(f"Votes:         {join_values(votes)}")

    return data, attributes


def print_human_result(target: LookupTarget, payload: dict) -> None:
    data, attributes = print_common_result(target, payload)

    if target.kind == "ip":
        print(f"ASN:           {attributes.get('asn', 'n/a')}")
        print(f"Owner:         {attributes.get('as_owner', 'n/a')}")
        print(f"Network:       {attributes.get('network', 'n/a')}")
        print(f"Country:       {attributes.get('country', 'n/a')}")
        print(f"Continent:     {attributes.get('continent', 'n/a')}")
        print(f"Reputation:    {attributes.get('reputation', 'n/a')}")
        print(f"Tags:          {join_values(attributes.get('tags'))}")
        print(f"Last analysis: {format_timestamp(attributes.get('last_analysis_date'))}")
        print(f"Whois date:    {format_timestamp(attributes.get('whois_date'))}")
    elif target.kind == "file":
        print(f"SHA256:        {attributes.get('sha256', target.endpoint_value)}")
        print(f"SHA1:          {attributes.get('sha1', 'n/a')}")
        print(f"MD5:           {attributes.get('md5', 'n/a')}")
        print(f"Size:          {attributes.get('size', 'n/a')}")
        print(f"Type:          {attributes.get('type_description', 'n/a')}")
        print(f"Magic:         {attributes.get('magic', 'n/a')}")
        print(f"Names:         {join_values(attributes.get('names'), limit=6)}")
        print(f"Tags:          {join_values(attributes.get('tags'))}")
        print(f"Meaningful:    {attributes.get('meaningful_name', 'n/a')}")
        threat = attributes.get("popular_threat_classification", {})
        print(f"Threat names:  {join_values(threat.get('popular_threat_name'))}")
        print(f"Threat family: {join_values(threat.get('popular_threat_category'))}")
        print(f"First seen:    {format_timestamp(attributes.get('first_submission_date'))}")
        print(f"Last seen:     {format_timestamp(attributes.get('last_submission_date'))}")
        print(f"Last analysis: {format_timestamp(attributes.get('last_analysis_date'))}")
    elif target.kind == "url":
        print(f"Title:         {attributes.get('title', 'n/a')}")
        print(f"Final URL:     {attributes.get('last_final_url', 'n/a')}")
        print(f"Reputation:    {attributes.get('reputation', 'n/a')}")
        print(f"Categories:    {join_values(attributes.get('categories'))}")
        print(f"Tags:          {join_values(attributes.get('tags'))}")
        print(f"Last analysis: {format_timestamp(attributes.get('last_analysis_date'))}")
        print(f"First seen:    {format_timestamp(attributes.get('first_submission_date'))}")
        print(f"Last seen:     {format_timestamp(attributes.get('last_submission_date'))}")

    link = data.get("links", {}).get("self")
    if link:
        print(f"API:           {link}")


def print_upload_result(path: str, payload: dict) -> None:
    data = payload.get("data", {})
    print(f"Uploaded:      {path}")
    print(f"Analysis ID:   {data.get('id', 'n/a')}")
    print(f"Status:        {data.get('type', 'analysis')}")
    link = data.get("links", {}).get("self")
    if link:
        print(f"API:           {link}")
    print("Message:       File submitted to VirusTotal for analysis.")


def explain_api_error(exc: APIError, target: LookupTarget) -> str:
    if exc.status_code == 404:
        if target.local_path:
            return (
                f"No VirusTotal record found for {target.local_path} "
                f"(SHA256 {target.endpoint_value})."
            )
        return f"No VirusTotal record found for {target.raw_value}."
    if exc.status_code == 401:
        return "VirusTotal rejected the API key. Check VT_API_KEY or --api-key."
    if exc.status_code == 429:
        return "VirusTotal rate limit reached. Wait and retry."
    return str(exc)


def main() -> int:
    args = parse_args()
    api_key = args.api_key or os.environ.get("VT_API_KEY")
    if not api_key:
        print("Missing API key. Set VT_API_KEY or pass --api-key.", file=sys.stderr)
        return 2

    try:
        targets = args.targets or prompt_for_targets()
    except ValueError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2

    exit_code = 0

    for index, raw_target in enumerate(targets):
        if index:
            print()

        try:
            target = classify_target(raw_target)
            payload = fetch_result(api_key, target)
        except APIError as exc:  # pragma: no cover - live API path
            if exc.status_code == 404 and args.upload_missing and target.local_path:
                print(explain_api_error(exc, target))
                try:
                    upload_payload = upload_file(api_key, target.local_path)
                except Exception as upload_exc:  # pragma: no cover - CLI error path
                    print(f"Error: Upload failed for {target.local_path}: {upload_exc}", file=sys.stderr)
                    exit_code = 1
                    continue
                print_upload_result(target.local_path, upload_payload)
                continue

            print(f"Error: {explain_api_error(exc, target)}", file=sys.stderr)
            exit_code = 1
            continue
        except Exception as exc:  # pragma: no cover - CLI error path
            print(f"Error: {exc}", file=sys.stderr)
            exit_code = 1
            continue

        if args.json:
            print(json.dumps(payload, indent=2, sort_keys=True))
        else:
            print_human_result(target, payload)

    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
