# IntelFuse CLI

A Python command-line tool for:

- VirusTotal lookups of IPs, hashes, URLs, and local files
- IP enrichment with VirusTotal, GreyNoise v3, and AbuseIPDB v2

## Setup

Export the API keys you want to use:

```bash
export VT_API_KEY="your_virustotal_api_key"
export GREYNOISE_API_KEY="your_greynoise_api_key"
export ABUSEIPDB_API_KEY="your_abuseipdb_api_key"
```

You can also start from the sample file in [.env.example](/home/curtis/IntelFuse/.env.example).
GreyNoise community lookups can work without `GREYNOISE_API_KEY`; if you have a key, the CLI will send it.

## Usage

Legacy VirusTotal lookups still work:

```bash
python3 lookup.py 8.8.8.8
python3 lookup.py 8.8.8.8 https://example.com
python3 lookup.py 44d88612fea8a8f36de82e1278abb02f
python3 lookup.py /path/to/sample.exe
python3 lookup.py --upload-missing /path/to/sample.exe
python3 lookup.py --json https://example.com
```

New IP enrichment commands:

```bash
python3 lookup.py ip 1.1.1.1
python3 lookup.py enrich ip 1.1.1.1
python3 lookup.py ip 2001:4860:4860::8888 --verbose
python3 lookup.py ip 8.8.8.8 --json
python3 lookup.py ip 8.8.8.8 --timeout 10
```

## Analyst Output

The enrichment command prints:

1. Summary
2. VirusTotal section
3. GreyNoise section
4. AbuseIPDB section

If one provider fails, the CLI keeps going and shows partial results.
GreyNoise community responses may expose fewer fields than the full commercial API, so some values can legitimately appear as `n/a`.

## Example Output

Suspicious IP:

```text
Summary
IP:            203.0.113.45
Verdict:       suspicious
Severity:      66/100
Confidence:    medium
Why:           AbuseIPDB confidence is elevated (72)

VirusTotal
Status:        ok
ASN:           64512
Country:       US
Owner:         Example Transit
Reputation:    -12
Votes:         harmless=1, malicious=3
Analysis:      harmless=12, malicious=4, suspicious=3, timeout=0, undetected=51
Tags:          scanner, brute-force
Categories:    Fortinet=malicious

GreyNoise
Status:        ok
Noise:         True
RIOT:          False
Class:         unknown
Org:           Example Hosting
Actor:         n/a
Tags:          ssh, telnet
First seen:    2026-03-10
Last seen:     2026-04-05
CVEs:          CVE-2024-6387
Metadata:      asn=64512, country=US

AbuseIPDB
Status:        ok
Score:         72
Reports:       29
Country:       US
ISP:           Example Transit
Domain:        example.net
Usage:         Data Center/Web Hosting/Transit
Tor:           False
Last report:   2026-04-04T18:22:11+00:00
```

Noisy scanner IP:

```text
Summary
IP:            198.51.100.88
Verdict:       noisy / opportunistic scanning
Severity:      34/100
Confidence:    medium
Why:           GreyNoise sees internet background scanning activity
```

Clean or low-signal IP:

```text
Summary
IP:            192.0.2.10
Verdict:       low-signal / unknown
Severity:      5/100
Confidence:    low
Why:           AbuseIPDB has no recent reports
```

## JSON Output

Use `--json` for a stable machine-readable report:

```bash
python3 lookup.py ip 8.8.8.8 --json
```

The JSON includes:

- `ip`
- `summary`
- `providers.virustotal`
- `providers.greynoise`
- `providers.abuseipdb`

## Verdict Logic

- Higher VirusTotal malicious or suspicious signals increase severity.
- Higher AbuseIPDB `abuseConfidenceScore` increases severity.
- GreyNoise `noise=true` can lower panic when the IP looks like broad internet scanning rather than targeted malicious behavior.
- GreyNoise `classification=malicious` increases severity.
- GreyNoise `riot=true` lowers severity because the IP may be legitimate business infrastructure.
- The severity score is an analyst-facing ranking from `0` to `100`, not a mathematical probability or certainty score.

## Testing

Run:

```bash
python3 -m unittest discover -s tests -p 'test_*.py'
```
