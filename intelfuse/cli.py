"""CLI parsing and command orchestration."""

from __future__ import annotations

import argparse
import json
import os
import sys

from .clients import AbuseIPDBClient, GreyNoiseClient, VirusTotalClient, encode_url_target, hash_file
from .enrichment import IPEnrichmentService
from .errors import APIClientError, InputValidationError
from .models import LookupTarget
from .output import print_human_result, print_ip_enrichment, print_upload_result


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if _is_enrichment_command(argv):
        return _run_ip_enrichment(argv)
    return _run_legacy_lookup(argv)


def _is_enrichment_command(argv: list[str]) -> bool:
    return bool(argv) and (
        argv[0] == "ip" or (len(argv) >= 2 and argv[0] == "enrich" and argv[1] == "ip")
    )


def _run_ip_enrichment(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description="Enrich an IP address with VirusTotal, GreyNoise, and AbuseIPDB.")
    parser.add_argument("--json", action="store_true", help="Print a stable machine-readable JSON report.")
    parser.add_argument("--verbose", action="store_true", help="Show additional analyst context in the summary.")
    parser.add_argument(
        "--timeout",
        type=float,
        default=15.0,
        help="Per-provider request timeout in seconds. Default: 15.",
    )
    parser.add_argument("command", choices=["ip", "enrich"])
    parser.add_argument("subcommand", nargs="?", help=argparse.SUPPRESS)
    parser.add_argument("address", nargs="?", help="IPv4 or IPv6 address to enrich.")
    args = parser.parse_args(argv)

    address = args.address
    if args.command == "enrich":
        if args.subcommand != "ip" or not address:
            parser.error("Usage: enrich ip <address>")
        address = args.address
    elif args.command == "ip":
        if args.subcommand and not address:
            address = args.subcommand
        elif args.subcommand and address:
            parser.error("Usage: ip <address>")
        elif not address:
            parser.error("Usage: ip <address>")

    service = IPEnrichmentService(
        virustotal_client=_build_vt_client(args.timeout),
        greynoise_client=_build_greynoise_client(args.timeout),
        abuseipdb_client=_build_abuseipdb_client(args.timeout),
    )

    if not any((service.virustotal_client, service.greynoise_client, service.abuseipdb_client)):
        print(
            "Missing API keys. Set at least one of VT_API_KEY, GREYNOISE_API_KEY, or ABUSEIPDB_API_KEY.",
            file=sys.stderr,
        )
        return 2

    try:
        report = service.enrich_ip(address)
    except InputValidationError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2

    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        print_ip_enrichment(report, verbose=args.verbose)

    return 0 if any(provider["ok"] for provider in report["providers"].values()) else 1


def _build_vt_client(timeout: float) -> VirusTotalClient | None:
    api_key = os.environ.get("VT_API_KEY")
    return VirusTotalClient(api_key, timeout=timeout) if api_key else None


def _build_greynoise_client(timeout: float) -> GreyNoiseClient | None:
    api_key = os.environ.get("GREYNOISE_API_KEY")
    return GreyNoiseClient(api_key, timeout=timeout)


def _build_abuseipdb_client(timeout: float) -> AbuseIPDBClient | None:
    api_key = os.environ.get("ABUSEIPDB_API_KEY")
    return AbuseIPDBClient(api_key, timeout=timeout) if api_key else None


def _run_legacy_lookup(argv: list[str]) -> int:
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
    args = parser.parse_args(argv)

    api_key = args.api_key or os.environ.get("VT_API_KEY")
    if not api_key:
        print("Missing API key. Set VT_API_KEY or pass --api-key.", file=sys.stderr)
        return 2

    try:
        targets = args.targets or _prompt_for_targets()
    except ValueError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2

    client = VirusTotalClient(api_key)
    exit_code = 0

    for index, raw_target in enumerate(targets):
        if index:
            print()

        try:
            target = _classify_target(raw_target)
            payload = client.fetch_target(target)
        except APIClientError as exc:
            if exc.status_code == 404 and args.upload_missing and target.local_path:
                print(_explain_vt_api_error(exc, target))
                try:
                    upload_payload = client.upload_file(target.local_path)
                except Exception as upload_exc:
                    print(f"Error: Upload failed for {target.local_path}: {upload_exc}", file=sys.stderr)
                    exit_code = 1
                    continue
                print_upload_result(target.local_path, upload_payload)
                continue

            print(f"Error: {_explain_vt_api_error(exc, target)}", file=sys.stderr)
            exit_code = 1
            continue
        except Exception as exc:
            print(f"Error: {exc}", file=sys.stderr)
            exit_code = 1
            continue

        if args.json:
            print(json.dumps(payload, indent=2, sort_keys=True))
        else:
            print_human_result(target, payload)

    return exit_code


def _prompt_for_targets() -> list[str]:
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


def _classify_target(value: str) -> LookupTarget:
    stripped = value.strip()
    if not stripped:
        raise ValueError("Empty target provided.")

    if os.path.isfile(stripped):
        return LookupTarget(stripped, "file", hash_file(stripped), local_path=os.path.abspath(stripped))

    try:
        from .validation import validate_ip_address

        return LookupTarget(stripped, "ip", validate_ip_address(stripped))
    except InputValidationError:
        pass

    lowered = stripped.lower()
    if lowered.startswith(("http://", "https://")):
        return LookupTarget(stripped, "url", encode_url_target(stripped))

    if all(ch in "0123456789abcdefABCDEF" for ch in stripped) and len(stripped) in {32, 40, 64}:
        return LookupTarget(stripped, "file", stripped.lower())

    raise ValueError(
        f"Unsupported target: {value!r}. Expected an IP, URL, MD5/SHA1/SHA256 hash, or local file path."
    )


def _explain_vt_api_error(exc: APIClientError, target: LookupTarget) -> str:
    if exc.status_code == 404:
        if target.local_path:
            return (
                f"No VirusTotal record found for {target.local_path} "
                f"(SHA256 {target.endpoint_value})."
            )
        return f"No VirusTotal record found for {target.raw_value}."
    if exc.category == "invalid_api_key":
        return "VirusTotal rejected the API key. Check VT_API_KEY or --api-key."
    if exc.category == "rate_limit":
        return "VirusTotal rate limit reached. Wait and retry."
    return str(exc)
