# Who-Is

**Who-Is** is a Python tool that retrieves registration information for IP addresses and domain owners.

## Features

- Modern RDAP protocol – retrieves registration data via RDAP (not legacy WHOIS) for IP addresses (both IPv4 and IPv6) and domain names.
- Single or bulk lookup – query a single address with `-a` or process a list of addresses from a file with `-l`.
- Output to file – stream results to a file `-o` / `--output` in JSON Lines format (JSONL).
- Support for `.рф` domains – automatically converts Cyrillic domain names (e.g., `пример.рф`) to Punycode (`xn--e1afmkfd.xn--p1ai`) for correct RDAP queries.
- Customisable output format – pretty-printed JSON by default; use `--no-pretty` for minified output.
- Fine‑tuned pretty‑printing – control the nesting level `-md` / `--max-depth` and truncate overly long compact lines `-ml` / `--max-line-length` to keep output readable.
- Response size limit – protect against memory issues with `--max-size` (set to 0 to disable).
- Adjustable timeout – set the connection timeout with `-t` / `--timeout`.
- Silent mode – suppress the banner with `--silent`.
- Flexible configuration – override RDAP bootstrap files for DNS, IPv4, IPv6, and custom TLD mappings (`--dns`, `--ipv4`, `--ipv6`, `--tld`).
- Persistent HTTP session – uses a requests.Session with a custom User-Agent header for efficiency and compatibility.

## Installation

```bash
git clone git@github.com:qpxqp/who-is.git
```
```bash
cd who-is
```
```bash
uv sync
```

## Usage

```bash
uv run who-is.py -a <address> 
uv run who-is.py -l addresses.txt -t 5
```

### Arguments:

| Flag            | Description |
|-----------------|-------------|
| `-h` / `--help` | Show help message and exit. |
| `-a` / `--addr` | Single IP or domain. |
| `-l` / `--list` | File with list of IPs/domains. |
| `--dns` | RDAP bootstrap file for Domain Name System registrations. |
| `--ipv4` | RDAP bootstrap file for IPv4 address allocations. |
| `--ipv6` | RDAP bootstrap file for IPv6 address allocations. |
| `--tld` | YAML file containing custom RDAP providers. |
| `--silent` | Suppress banner output. |
| `--no-pretty` | Disable pretty-printed JSON output. |
| `-i` / `--indent` | Indent level for pretty-printed JSON array elements. `0` is the most compact representation. |
| `-md` / `--max-depth` | Maximum nesting depth for pretty‑printed output. Deeper levels are shown compactly as a single line. |
| `-ml` / `--max-line-length` | Maximum length of compact JSON fragments before truncation. |
| `--max-size` | Maximum allowed response size in bytes. If `0`, no limit is applied. |
| `-t` / `--timeout` | Connection timeout. |
| `-o` / `--output` | Output file (default: CLI output). |

### Example

**Basic query**

```bash
uv run who-is.py -a example.com
```

**Pretty-printed output with header**

```bash
uv run who-is.py --no-pretty -a example.com
```

**Pretty JSONL**

```bash
uv run who-is.py --no-pretty --silent -a example.com
```

**Compact JSONL (single‑line output)**

```bash
uv run who-is.py --no-pretty --silent -i 0 -a example.com
```

**Adjust timeout and response size limit**

```bash
uv run who-is.py -t 3 --max-size 2097152 -a example.com
```

**Bulk lookup from file and save output to a file**

```bash
uv run who-is.py --no-pretty -l in.txt -o out.txt
```

## Example of a custom RDAP YAML file

```yaml
tld_rdap:
  ru: "https://cctld.ru/tci-ripn-rdap/domain/"
```

## License
MIT License

## Author
**AleX.**  
GitHub: [AleX.](https://github.com/qpxqp)
