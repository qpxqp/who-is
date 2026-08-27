# Who-Is

**Who-Is** is a Python tool that retrieves registration information for IP addresses and domain owners.

## Features

- Supports single address (`-a`) and bulk addresses processing from a file (`-l`)
- Silent mode (`--silent`) to suppress banner output

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
| `--max_size` | Maximum allowed response size in bytes. If 0, no limit is applied |
| `-t` / `--timeout` | Connection timeout |

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
