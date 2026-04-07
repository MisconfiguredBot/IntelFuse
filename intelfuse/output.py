"""Human-readable rendering for enrichment and legacy VT output."""

from __future__ import annotations

from datetime import datetime, timezone

from .models import LookupTarget

COUNTRY_NAMES = {
    "AD": "Andorra", "AE": "United Arab Emirates", "AF": "Afghanistan", "AG": "Antigua and Barbuda",
    "AI": "Anguilla", "AL": "Albania", "AM": "Armenia", "AO": "Angola", "AQ": "Antarctica",
    "AR": "Argentina", "AS": "American Samoa", "AT": "Austria", "AU": "Australia", "AW": "Aruba",
    "AX": "Aland Islands", "AZ": "Azerbaijan", "BA": "Bosnia and Herzegovina", "BB": "Barbados",
    "BD": "Bangladesh", "BE": "Belgium", "BF": "Burkina Faso", "BG": "Bulgaria", "BH": "Bahrain",
    "BI": "Burundi", "BJ": "Benin", "BL": "Saint Barthelemy", "BM": "Bermuda", "BN": "Brunei Darussalam",
    "BO": "Bolivia", "BQ": "Bonaire, Sint Eustatius and Saba", "BR": "Brazil", "BS": "Bahamas",
    "BT": "Bhutan", "BV": "Bouvet Island", "BW": "Botswana", "BY": "Belarus", "BZ": "Belize",
    "CA": "Canada", "CC": "Cocos (Keeling) Islands", "CD": "Congo, the Democratic Republic of the",
    "CF": "Central African Republic", "CG": "Congo", "CH": "Switzerland", "CI": "Cote d'Ivoire",
    "CK": "Cook Islands", "CL": "Chile", "CM": "Cameroon", "CN": "China", "CO": "Colombia",
    "CR": "Costa Rica", "CU": "Cuba", "CV": "Cabo Verde", "CW": "Curacao", "CX": "Christmas Island",
    "CY": "Cyprus", "CZ": "Czechia", "DE": "Germany", "DJ": "Djibouti", "DK": "Denmark",
    "DM": "Dominica", "DO": "Dominican Republic", "DZ": "Algeria", "EC": "Ecuador", "EE": "Estonia",
    "EG": "Egypt", "EH": "Western Sahara", "ER": "Eritrea", "ES": "Spain", "ET": "Ethiopia",
    "FI": "Finland", "FJ": "Fiji", "FK": "Falkland Islands (Malvinas)", "FM": "Micronesia",
    "FO": "Faroe Islands", "FR": "France", "GA": "Gabon", "GB": "United Kingdom", "GD": "Grenada",
    "GE": "Georgia", "GF": "French Guiana", "GG": "Guernsey", "GH": "Ghana", "GI": "Gibraltar",
    "GL": "Greenland", "GM": "Gambia", "GN": "Guinea", "GP": "Guadeloupe", "GQ": "Equatorial Guinea",
    "GR": "Greece", "GS": "South Georgia and the South Sandwich Islands", "GT": "Guatemala",
    "GU": "Guam", "GW": "Guinea-Bissau", "GY": "Guyana", "HK": "Hong Kong", "HM": "Heard Island and McDonald Islands",
    "HN": "Honduras", "HR": "Croatia", "HT": "Haiti", "HU": "Hungary", "ID": "Indonesia",
    "IE": "Ireland", "IL": "Israel", "IM": "Isle of Man", "IN": "India", "IO": "British Indian Ocean Territory",
    "IQ": "Iraq", "IR": "Iran", "IS": "Iceland", "IT": "Italy", "JE": "Jersey", "JM": "Jamaica",
    "JO": "Jordan", "JP": "Japan", "KE": "Kenya", "KG": "Kyrgyzstan", "KH": "Cambodia", "KI": "Kiribati",
    "KM": "Comoros", "KN": "Saint Kitts and Nevis", "KP": "Korea, Democratic People's Republic of",
    "KR": "Korea, Republic of", "KW": "Kuwait", "KY": "Cayman Islands", "KZ": "Kazakhstan", "LA": "Lao People's Democratic Republic",
    "LB": "Lebanon", "LC": "Saint Lucia", "LI": "Liechtenstein", "LK": "Sri Lanka", "LR": "Liberia",
    "LS": "Lesotho", "LT": "Lithuania", "LU": "Luxembourg", "LV": "Latvia", "LY": "Libya", "MA": "Morocco",
    "MC": "Monaco", "MD": "Moldova", "ME": "Montenegro", "MF": "Saint Martin (French part)", "MG": "Madagascar",
    "MH": "Marshall Islands", "MK": "North Macedonia", "ML": "Mali", "MM": "Myanmar", "MN": "Mongolia",
    "MO": "Macao", "MP": "Northern Mariana Islands", "MQ": "Martinique", "MR": "Mauritania", "MS": "Montserrat",
    "MT": "Malta", "MU": "Mauritius", "MV": "Maldives", "MW": "Malawi", "MX": "Mexico", "MY": "Malaysia",
    "MZ": "Mozambique", "NA": "Namibia", "NC": "New Caledonia", "NE": "Niger", "NF": "Norfolk Island",
    "NG": "Nigeria", "NI": "Nicaragua", "NL": "Netherlands", "NO": "Norway", "NP": "Nepal", "NR": "Nauru",
    "NU": "Niue", "NZ": "New Zealand", "OM": "Oman", "PA": "Panama", "PE": "Peru", "PF": "French Polynesia",
    "PG": "Papua New Guinea", "PH": "Philippines", "PK": "Pakistan", "PL": "Poland", "PM": "Saint Pierre and Miquelon",
    "PN": "Pitcairn", "PR": "Puerto Rico", "PS": "Palestine, State of", "PT": "Portugal", "PW": "Palau",
    "PY": "Paraguay", "QA": "Qatar", "RE": "Reunion", "RO": "Romania", "RS": "Serbia", "RU": "Russian Federation",
    "RW": "Rwanda", "SA": "Saudi Arabia", "SB": "Solomon Islands", "SC": "Seychelles", "SD": "Sudan",
    "SE": "Sweden", "SG": "Singapore", "SH": "Saint Helena, Ascension and Tristan da Cunha", "SI": "Slovenia",
    "SJ": "Svalbard and Jan Mayen", "SK": "Slovakia", "SL": "Sierra Leone", "SM": "San Marino", "SN": "Senegal",
    "SO": "Somalia", "SR": "Suriname", "SS": "South Sudan", "ST": "Sao Tome and Principe", "SV": "El Salvador",
    "SX": "Sint Maarten (Dutch part)", "SY": "Syrian Arab Republic", "SZ": "Eswatini", "TC": "Turks and Caicos Islands",
    "TD": "Chad", "TF": "French Southern Territories", "TG": "Togo", "TH": "Thailand", "TJ": "Tajikistan",
    "TK": "Tokelau", "TL": "Timor-Leste", "TM": "Turkmenistan", "TN": "Tunisia", "TO": "Tonga", "TR": "Turkey",
    "TT": "Trinidad and Tobago", "TV": "Tuvalu", "TW": "Taiwan", "TZ": "Tanzania", "UA": "Ukraine", "UG": "Uganda",
    "UM": "United States Minor Outlying Islands", "US": "United States", "UY": "Uruguay", "UZ": "Uzbekistan",
    "VA": "Holy See", "VC": "Saint Vincent and the Grenadines", "VE": "Venezuela", "VG": "Virgin Islands, British",
    "VI": "Virgin Islands, U.S.", "VN": "Viet Nam", "VU": "Vanuatu", "WF": "Wallis and Futuna", "WS": "Samoa",
    "YE": "Yemen", "YT": "Mayotte", "ZA": "South Africa", "ZM": "Zambia", "ZW": "Zimbabwe",
}


def format_timestamp(value: int | None) -> str:
    if not value:
        return "n/a"
    return datetime.fromtimestamp(value, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def format_iso_timestamp(value: str | None) -> str:
    return value or "n/a"


def format_country(value: str | None) -> str:
    if not value:
        return "n/a"
    country = COUNTRY_NAMES.get(str(value).upper())
    return country or str(value)


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
        print(f"Country:       {format_country(attributes.get('country'))}")
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


def print_ip_enrichment(report: dict, *, verbose: bool = False) -> None:
    summary = report["summary"]
    print("Summary")
    print(f"IP:            {report['ip']}")
    print(f"Verdict:       {summary['label']}")
    print(f"Severity:      {summary['severity']}/100")
    print(f"Confidence:    {summary['confidence']}")
    print(f"Why:           {summary['explanation']}")
    if verbose and summary.get("reasons"):
        print(f"Signals:       {join_values(summary['reasons'], limit=8)}")

    print()
    _print_provider_section("VirusTotal", report["providers"]["virustotal"], _format_vt_lines)
    print()
    _print_provider_section("GreyNoise", report["providers"]["greynoise"], _format_gn_lines)
    print()
    _print_provider_section("AbuseIPDB", report["providers"]["abuseipdb"], _format_abuse_lines)


def _print_provider_section(title: str, provider: dict, formatter) -> None:
    print(title)
    if not provider["ok"]:
        print(f"Status:        unavailable")
        print(f"Reason:        {provider.get('error', 'Unknown error')}")
        return

    print("Status:        ok")
    for label, value in formatter(provider["data"]):
        print(f"{label:<14}{value}")


def _format_vt_lines(data: dict) -> list[tuple[str, str]]:
    return [
        ("ASN: ", str(data.get("asn") or "n/a")),
        ("Country: ", format_country(data.get("country"))),
        ("Owner: ", str(data.get("as_owner") or data.get("network") or "n/a")),
        ("Reputation: ", str(data.get("reputation") if data.get("reputation") is not None else "n/a")),
        ("Votes: ", join_values(data.get("total_votes"))),
        ("Analysis: ", join_values(data.get("last_analysis_stats"))),
        ("Tags: ", join_values(data.get("tags"))),
        ("Categories: ", join_values(data.get("categories"))),
    ]


def _format_gn_lines(data: dict) -> list[tuple[str, str]]:
    metadata = data.get("metadata") or {}
    meta_summary = ", ".join(
        f"{key}={value}"
        for key, value in (
            ("asn", metadata.get("asn")),
            ("country", metadata.get("country")),
            ("city", metadata.get("city")),
            ("tor", metadata.get("tor")),
            ("rdns", metadata.get("rdns")),
        )
        if value not in (None, "")
    )
    return [
        ("Noise: ", str(data.get("noise"))),
        ("RIOT: ", str(data.get("riot"))),
        ("Class: ", str(data.get("classification") or "n/a")),
        ("Org: ", str(data.get("organization") or "n/a")),
        ("Actor: ", str(data.get("actor") or "n/a")),
        ("Tags: ", join_values(data.get("tags"))),
        ("First seen: ", format_iso_timestamp(data.get("first_seen"))),
        ("Last seen: ", format_iso_timestamp(data.get("last_seen"))),
        ("CVEs: ", join_values(data.get("cves"))),
        ("Metadata: ", meta_summary or "n/a"),
    ]


def _format_abuse_lines(data: dict) -> list[tuple[str, str]]:
    return [
        ("Score: ", str(data.get("abuseConfidenceScore") if data.get("abuseConfidenceScore") is not None else "n/a")),
        ("Reports: ", str(data.get("totalReports") if data.get("totalReports") is not None else "n/a")),
        ("Country: ", format_country(data.get("countryCode"))),
        ("ISP: ", str(data.get("isp") or "n/a")),
        ("Domain: ", str(data.get("domain") or "n/a")),
        ("Usage: ", str(data.get("usageType") or "n/a")),
        ("Tor: ", str(data.get("isTor"))),
        ("Last report: ", str(data.get("lastReportedAt") or "n/a")),
    ]
