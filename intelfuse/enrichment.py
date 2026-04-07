"""Normalization and aggregation logic for IP enrichment."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed

from .errors import APIClientError
from .models import ProviderEnvelope, Verdict
from .validation import validate_ip_address


def normalize_virustotal_ip(payload: dict) -> dict:
    data = payload.get("data", {})
    attributes = data.get("attributes", {})
    stats = attributes.get("last_analysis_stats") or {}
    votes = attributes.get("total_votes") or {}
    community_total = sum(value for value in votes.values() if isinstance(value, int))
    tags = attributes.get("tags") or []
    if isinstance(tags, str):
        tags = [tags]
    categories = attributes.get("categories") or {}
    return {
        "id": data.get("id"),
        "asn": attributes.get("asn"),
        "country": attributes.get("country"),
        "network": attributes.get("network"),
        "as_owner": attributes.get("as_owner"),
        "reputation": attributes.get("reputation"),
        "total_votes": votes,
        "community_total": community_total,
        "last_analysis_stats": stats,
        "last_analysis_date": attributes.get("last_analysis_date"),
        "tags": tags,
        "categories": categories,
    }


def normalize_greynoise_ip(payload: dict) -> dict:
    metadata = payload.get("metadata") or {}
    cve = payload.get("cve") or payload.get("cves") or []
    actor = payload.get("actor") or payload.get("actor_name")
    tags = payload.get("tags") or []
    if isinstance(tags, str):
        tags = [tags]
    if isinstance(cve, str):
        cve = [cve]
    return {
        "ip": payload.get("ip"),
        "noise": payload.get("noise"),
        "riot": payload.get("riot"),
        "classification": payload.get("classification"),
        "organization": payload.get("organization"),
        "actor": actor,
        "tags": tags,
        "metadata": metadata,
        "first_seen": payload.get("first_seen"),
        "last_seen": payload.get("last_seen"),
        "cves": cve,
        "name": payload.get("name"),
        "link": payload.get("link"),
    }


def normalize_abuseipdb_ip(payload: dict) -> dict:
    data = payload.get("data", {})
    return {
        "ipAddress": data.get("ipAddress"),
        "abuseConfidenceScore": data.get("abuseConfidenceScore"),
        "totalReports": data.get("totalReports"),
        "countryCode": data.get("countryCode"),
        "isp": data.get("isp"),
        "domain": data.get("domain"),
        "usageType": data.get("usageType"),
        "isTor": data.get("isTor"),
        "lastReportedAt": data.get("lastReportedAt"),
    }


def compute_verdict(
    ip: str,
    virustotal: ProviderEnvelope,
    greynoise: ProviderEnvelope,
    abuseipdb: ProviderEnvelope,
) -> Verdict:
    score = 10
    confidence = 20
    reasons: list[str] = []

    vt = virustotal.data or {}
    gn = greynoise.data or {}
    abuse = abuseipdb.data or {}

    vt_reputation = vt.get("reputation")
    vt_stats = vt.get("last_analysis_stats") or {}
    vt_malicious = int(vt_stats.get("malicious", 0) or 0)
    vt_suspicious = int(vt_stats.get("suspicious", 0) or 0)
    if vt_malicious >= 8:
        score += 45
        confidence += 30
        reasons.append(f"VirusTotal flagged {vt_malicious} malicious detections")
    elif vt_malicious >= 1 or vt_suspicious >= 3:
        score += 25
        confidence += 20
        reasons.append("VirusTotal shows malicious or suspicious community detections")
    if isinstance(vt_reputation, int):
        if vt_reputation <= -20:
            score += 25
            confidence += 20
            reasons.append(f"VirusTotal reputation is strongly negative ({vt_reputation})")
        elif vt_reputation >= 10:
            score -= 10
            reasons.append(f"VirusTotal reputation is positive ({vt_reputation})")

    abuse_score = abuse.get("abuseConfidenceScore")
    total_reports = abuse.get("totalReports")
    if isinstance(abuse_score, int):
        if abuse_score >= 90:
            score += 45
            confidence += 30
            reasons.append(f"AbuseIPDB confidence is very high ({abuse_score})")
        elif abuse_score >= 50:
            score += 25
            confidence += 20
            reasons.append(f"AbuseIPDB confidence is elevated ({abuse_score})")
        elif abuse_score >= 15:
            score += 10
            confidence += 10
            reasons.append(f"AbuseIPDB has some abuse history ({abuse_score})")
        elif abuse_score == 0 and total_reports == 0:
            score -= 5
            reasons.append("AbuseIPDB has no recent reports")

    classification = (gn.get("classification") or "").lower()
    noise = gn.get("noise")
    riot = gn.get("riot")
    if classification == "malicious":
        score += 35
        confidence += 25
        reasons.append("GreyNoise classifies the IP as malicious")
    elif classification in {"benign", "unknown"} and noise:
        score += 5
        reasons.append("GreyNoise sees internet background scanning activity")
    if riot:
        score -= 20
        confidence += 10
        reasons.append("GreyNoise RIOT identifies it as a known business service")
    if noise and classification != "malicious" and abuse_score is not None and abuse_score < 50 and vt_malicious == 0:
        score = min(score, 45)

    provider_successes = sum(1 for provider in (virustotal, greynoise, abuseipdb) if provider.ok)
    if provider_successes == 0:
        return Verdict(
            label="low-signal / unknown",
            severity=0,
            confidence="low",
            explanation=f"No provider returned data for {ip}.",
            reasons=["All providers failed or were unavailable"],
        )

    score = max(0, min(score, 100))
    confidence = max(0, min(confidence, 100))

    if score >= 80:
        label = "malicious"
    elif noise and classification != "malicious" and score <= 45 and not riot:
        label = "noisy / opportunistic scanning"
    elif score >= 45:
        label = "suspicious"
    else:
        label = "low-signal / unknown"

    if confidence >= 70:
        confidence_label = "high"
    elif confidence >= 40:
        confidence_label = "medium"
    else:
        confidence_label = "low"

    explanation = reasons[0] if reasons else f"Limited signal available for {ip}."
    return Verdict(label=label, severity=score, confidence=confidence_label, explanation=explanation, reasons=reasons)


class IPEnrichmentService:
    """Queries all configured providers, normalizes results, and scores the IP."""

    def __init__(
        self,
        *,
        virustotal_client=None,
        greynoise_client=None,
        abuseipdb_client=None,
    ) -> None:
        self.virustotal_client = virustotal_client
        self.greynoise_client = greynoise_client
        self.abuseipdb_client = abuseipdb_client

    def enrich_ip(self, raw_ip: str) -> dict:
        ip = validate_ip_address(raw_ip)
        providers = {
            "virustotal": (self.virustotal_client, normalize_virustotal_ip),
            "greynoise": (self.greynoise_client, normalize_greynoise_ip),
            "abuseipdb": (self.abuseipdb_client, normalize_abuseipdb_ip),
        }
        results: dict[str, ProviderEnvelope] = {}

        with ThreadPoolExecutor(max_workers=3) as executor:
            future_map = {}
            for provider_name, (client, normalizer) in providers.items():
                if client is None:
                    results[provider_name] = ProviderEnvelope(
                        provider=provider_name,
                        ok=False,
                        error="API key not configured",
                        category="missing_api_key",
                    )
                    continue
                future = executor.submit(self._fetch_provider, provider_name, client, normalizer, ip)
                future_map[future] = provider_name

            for future in as_completed(future_map):
                provider_name = future_map[future]
                results[provider_name] = future.result()

        vt_result = results["virustotal"]
        gn_result = results["greynoise"]
        abuse_result = results["abuseipdb"]
        verdict = compute_verdict(ip, vt_result, gn_result, abuse_result)

        return {
            "ip": ip,
            "summary": verdict.asdict(),
            "providers": {name: envelope.asdict() for name, envelope in results.items()},
        }

    @staticmethod
    def _fetch_provider(provider_name: str, client, normalizer, ip: str) -> ProviderEnvelope:
        try:
            payload = client.fetch_ip(ip)
            return ProviderEnvelope(provider=provider_name, ok=True, data=normalizer(payload))
        except APIClientError as exc:
            return ProviderEnvelope(
                provider=provider_name,
                ok=False,
                error=str(exc),
                category=exc.category,
                status_code=exc.status_code,
            )
        except Exception as exc:
            return ProviderEnvelope(
                provider=provider_name,
                ok=False,
                error=str(exc),
                category="unexpected_error",
            )
