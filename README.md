# Who-Is

**Who-Is** is a Python tool that retrieves registration information for IP addresses and domain owners.

## Features

- Modern RDAP protocol – retrieves registration data via RDAP (not legacy WHOIS) for IP addresses (both IPv4 and IPv6) and domain names.
- Single or bulk lookup – query a single address with `-a` or process a list of addresses from a file with `-l`.
- Output to file – stream results to a file `-o` / `--output` in JSON Lines format (JSONL).
- Support for `.рф` domains – automatically converts Cyrillic domain names (e.g., `пример.рф`) to Punycode (`xn--e1afmkfd.xn--p1ai`) for correct RDAP queries.
- Customisable output format – pretty-printed JSON by default; use `--no-pretty` for compact (minified) output.
- Response size limit – protect against memory issues with `--max-size` (default 5 MB; set to 0 to disable).
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
| `-h` / `--help` | Show help message and exit |
| `-a` / `--addr` | Single IP or domain |
| `-l` / `--list` | File with list of IPs/domains |
| `--dns` | RDAP bootstrap file for Domain Name System registrations |
| `--ipv4` | RDAP bootstrap file for IPv4 address allocations |
| `--ipv6` | RDAP bootstrap file for IPv6 address allocations |
| `--tld` | YAML file containing custom RDAP providers |
| `--silent` | Suppress banner output |
| `--no-pretty` | Disable pretty-printing: output JSON in compact form |
| `--max-size` | Maximum allowed response size in bytes. If 0, no limit is applied |
| `-t` / `--timeout` | Connection timeout |
| `-o` / `--output` | Output file (default: CLI output) |

### Example

```bash
uv run who-is.py -a example.com
```

```bash
uv run who-is.py -t 5 --no-pretty -l in.txt -o out.txt
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
