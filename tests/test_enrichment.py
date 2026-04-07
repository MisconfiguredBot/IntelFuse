from __future__ import annotations

import unittest

from intelfuse.enrichment import (
    compute_verdict,
    normalize_abuseipdb_ip,
    normalize_greynoise_ip,
    normalize_virustotal_ip,
)
from intelfuse.models import ProviderEnvelope
from intelfuse.output import format_country
from intelfuse.validation import validate_ip_address


class ValidationTests(unittest.TestCase):
    def test_validates_ipv4(self) -> None:
        self.assertEqual(validate_ip_address("8.8.8.8"), "8.8.8.8")

    def test_validates_ipv6(self) -> None:
        self.assertEqual(validate_ip_address("2001:0db8::1"), "2001:db8::1")

    def test_rejects_invalid_ip(self) -> None:
        with self.assertRaises(ValueError):
            validate_ip_address("999.999.999.999")


class NormalizationTests(unittest.TestCase):
    def test_format_country(self) -> None:
        self.assertEqual(format_country("US"), "United States")
        self.assertEqual(format_country("cn"), "China")
        self.assertEqual(format_country(None), "n/a")

    def test_normalize_virustotal(self) -> None:
        payload = {
            "data": {
                "id": "1.2.3.4",
                "attributes": {
                    "asn": 64500,
                    "country": "US",
                    "as_owner": "Example ISP",
                    "reputation": -25,
                    "last_analysis_stats": {"malicious": 7, "suspicious": 2},
                    "total_votes": {"harmless": 1, "malicious": 4},
                    "tags": ["scanner"],
                    "categories": {"Fortinet": "malicious"},
                },
            }
        }
        normalized = normalize_virustotal_ip(payload)
        self.assertEqual(normalized["community_total"], 5)
        self.assertEqual(normalized["tags"], ["scanner"])

    def test_normalize_greynoise(self) -> None:
        payload = {
            "ip": "1.2.3.4",
            "noise": True,
            "riot": False,
            "classification": "benign",
            "metadata": {"asn": 64500},
            "cve": ["CVE-2024-0001"],
        }
        normalized = normalize_greynoise_ip(payload)
        self.assertTrue(normalized["noise"])
        self.assertEqual(normalized["cves"], ["CVE-2024-0001"])

    def test_normalize_abuseipdb(self) -> None:
        payload = {"data": {"ipAddress": "1.2.3.4", "abuseConfidenceScore": 80, "totalReports": 20}}
        normalized = normalize_abuseipdb_ip(payload)
        self.assertEqual(normalized["abuseConfidenceScore"], 80)


class VerdictTests(unittest.TestCase):
    def test_malicious_verdict(self) -> None:
        verdict = compute_verdict(
            "1.2.3.4",
            ProviderEnvelope(
                provider="virustotal",
                ok=True,
                data={"reputation": -30, "last_analysis_stats": {"malicious": 10, "suspicious": 0}},
            ),
            ProviderEnvelope(provider="greynoise", ok=True, data={"noise": False, "riot": False, "classification": "malicious"}),
            ProviderEnvelope(provider="abuseipdb", ok=True, data={"abuseConfidenceScore": 95, "totalReports": 40}),
        )
        self.assertEqual(verdict.label, "malicious")
        self.assertGreaterEqual(verdict.severity, 80)

    def test_noisy_scanner_verdict(self) -> None:
        verdict = compute_verdict(
            "1.2.3.4",
            ProviderEnvelope(
                provider="virustotal",
                ok=True,
                data={"reputation": 5, "last_analysis_stats": {"malicious": 0, "suspicious": 0}},
            ),
            ProviderEnvelope(provider="greynoise", ok=True, data={"noise": True, "riot": False, "classification": "benign"}),
            ProviderEnvelope(provider="abuseipdb", ok=True, data={"abuseConfidenceScore": 10, "totalReports": 1}),
        )
        self.assertEqual(verdict.label, "noisy / opportunistic scanning")

    def test_low_signal_verdict(self) -> None:
        verdict = compute_verdict(
            "1.2.3.4",
            ProviderEnvelope(
                provider="virustotal",
                ok=True,
                data={"reputation": 20, "last_analysis_stats": {"malicious": 0, "suspicious": 0}},
            ),
            ProviderEnvelope(provider="greynoise", ok=True, data={"noise": False, "riot": False, "classification": None}),
            ProviderEnvelope(provider="abuseipdb", ok=True, data={"abuseConfidenceScore": 0, "totalReports": 0}),
        )
        self.assertEqual(verdict.label, "low-signal / unknown")


if __name__ == "__main__":
    unittest.main()
