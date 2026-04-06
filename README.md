# VirusTotal Lookup CLI

A small command-line tool that queries the VirusTotal API for:

- IP addresses
- File hashes (`MD5`, `SHA1`, `SHA256`)
- URLs
- Local file paths

## Setup

1. Create or use an existing VirusTotal API key.
2. Export it in your shell:

```bash
export VT_API_KEY="your_api_key_here"
```

## Usage

Run one or more lookups:

```bash
python3 vt_lookup.py 8.8.8.8
python3 vt_lookup.py 8.8.8.8 https://example.com
python3 vt_lookup.py 44d88612fea8a8f36de82e1278abb02f
python3 vt_lookup.py /path/to/sample.exe
```

Run without arguments to use the interactive prompt:

```bash
python3 vt_lookup.py
```

Upload a local file if VirusTotal does not already know its hash:

```bash
python3 vt_lookup.py --upload-missing /path/to/sample.exe
```

Print the raw API payload:

```bash
python3 vt_lookup.py --json https://example.com
```

Pass the key directly if needed:

```bash
python3 vt_lookup.py --api-key "your_api_key_here" 1.1.1.1
```

## Notes

- URLs must include `http://` or `https://`.
- The tool auto-detects whether each input is an IP, file hash, URL, or local file path.
- Local files are hashed with SHA256 before lookup.
- `--upload-missing` only uploads local files, not raw hashes.
- Free VirusTotal API plans have request limits.
