import argparse
import ipaddress
import json
import sys
from pathlib import Path
from typing import Any
from urllib.parse import urljoin

import requests
import yaml
from colorama import Fore, Style, init

IPNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network
IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address

# RDAP bootstrap URLs
# DNS_JSON_URL = 'https://data.iana.org/rdap/dns.json'
# IPV4_JSON_URL = 'https://data.iana.org/rdap/ipv4.json'
# IPV6_JSON_URL = 'https://data.iana.org/rdap/ipv6.json'

DNS_PATH = Path(__file__).parent / 'files/dns.json'
IPV4_PATH = Path(__file__).parent / 'files/ipv4.json'
IPV6_PATH = Path(__file__).parent / 'files/ipv6.json'
TLD_PATH = Path(__file__).parent / 'files/tld-rdap.yaml'

TIMEOUT = 10.0
FALLBACK_V4 = 'https://rdap.arin.net/registry/ip/'
FALLBACK_V6 = 'https://rdap.arin.net/registry/ip/'

RDAP_DOMAIN_SUFFIX = '/domain'
RDAP_IP_SUFFIX = '/ip'

DUMP_INDENT = 2
MAX_RESPONSE_SIZE = 5 * 1024 * 1024  # 5 MB
CHUNK_SIZE = 8192  # 8 KB
MAX_DEPTH = 3
MAX_LINE_LENGTH = 80
SHOW_REMAINING_CHARS = True

BANNER = (
    f'{Fore.CYAN}Who-Is — A utility for retrieving registration data on '
    f'{Fore.CYAN}IP address and domain name owners{Style.RESET_ALL}\n'
    f'{Fore.YELLOW}Author: AleX.{Style.RESET_ALL}\n'
    f'{Fore.GREEN}GitHub: github.com/qpxqp{Style.RESET_ALL}\n'
)
ADDR_PATTERN = 'Address: `{}`:'
ADDR_TEMPLATE = (
    f'{Fore.BLUE}{Style.BRIGHT}{ADDR_PATTERN}{Style.RESET_ALL}'
)

session = requests.Session()
session.headers.update({
    'User-Agent': 'Who-Is/1.0 (https://github.com/qpxqp/who-is)',
})

init(autoreset=True)


class LoadError(Exception):
    pass


def load_rdap(rdap_file):
    with open(rdap_file, encoding='utf-8') as f:
        return json.load(f)


def load_tld(tld_file):
    with open(tld_file, encoding='utf-8') as f:
        data = yaml.safe_load(f)
    return data.get('tld_rdap', {})


def safely_loader(path, loader):
    try:
        return loader(path)
    except Exception as e:
        raise LoadError(f'Failed to load data from `{path}`: {e}') from e


def build_tld_map(dns_data: dict) -> dict[str, str]:
    """Из dns.json строит dict: tld -> base RDAP URL."""
    tld_map = {}
    for entry in dns_data.get('services', []):
        tlds, urls = entry[0], entry[1]
        if not urls:
            continue
        base_url = urls[0]
        for t in tlds:
            tld_map[t.lower()] = base_url
    return tld_map


def build_cidr_map(
    ip_data: dict[str, Any],
) -> list[tuple[IPNetwork, str]]:
    """
    Строит список [(network, base_url), ...] из данных ipv4.json/ipv6.json.

    Сети сортируются по убыванию prefixlen:
    более специфичные сети идут первыми.
    """
    cidr_map = []
    for cidrs, urls, *_ in ip_data.get('services', []):
        if not urls:
            continue
        base_url = urls[0]
        for cidr in cidrs:
            network = ipaddress.ip_network(cidr)
            cidr_map.append((network, base_url))
    cidr_map.sort(key=lambda item: item[0].prefixlen, reverse=True)
    return cidr_map


def _find_base_url(
    ip: IPAddress,
    cidr_map: list[tuple[IPNetwork, str]],
) -> str:
    """
    Находит base RDAP-URL для IPv4 или IPv6.

    CIDR-мапа должна быть отсортирована по убыванию prefixlen,
    поэтому первый найденный CIDR будет самым специфичным.
    """
    for network, base_url in cidr_map:
        if ip in network:
            return base_url
    print(
        f'Warning: base url not found for `{ip}`. Use fallback address.',
        file=sys.stderr,
    )
    if ip.version == 4:
        return FALLBACK_V4
    return FALLBACK_V6


def fetch_json(url: str, timeout: float, max_size: int) -> Any:
    with session.get(url, timeout=timeout, stream=True) as response:
        response.raise_for_status()
        chunks = []
        total_size = 0
        for chunk in response.iter_content(chunk_size=CHUNK_SIZE):
            chunks.append(chunk)
            total_size += len(chunk)
            if max_size and total_size > max_size:
                raise ValueError(
                    f'Response from {url} exceeds '
                    f'size limit ({max_size} bytes), '
                    f'got {total_size} bytes'
                )
        content = b''.join(chunks)
        try:
            return json.loads(content)
        except json.JSONDecodeError as e:
            raise ValueError(f'Response is not valid JSON: {e}') from e


def _normalize_base_url(base: str, suffix: str) -> str:
    base = base.rstrip('/')
    if base.endswith(suffix):
        base = base[:-len(suffix)]
    return base + '/'


def lookup_domain(
    addr: str, tld_map: dict[str, str], timeout: float, max_size: int,
) -> Any:
    """Делает RDAP-запрос для домена."""
    domain = addr.strip().lower()
    if not domain or '.' not in domain:
        raise ValueError(f'Invalid domain: `{domain}`')
    try:
        domain = domain.encode('idna').decode('ascii')
    except UnicodeError as e:
        raise ValueError(f'Invalid domain name: `{addr}`') from e
    tld = domain.rsplit('.', 1)[-1]
    base = tld_map.get(tld)
    if not base:
        raise ValueError(f'No RDAP server configured for TLD `{tld}`')
    url = urljoin(
        _normalize_base_url(base, RDAP_DOMAIN_SUFFIX),
        f'domain/{domain}',
    )
    return fetch_json(url, timeout, max_size)


def lookup_ip(
    addr: str,
    cidr_map: list[tuple[IPNetwork, str]],
    timeout: float,
    max_size: int,
) -> Any:
    """Делает RDAP-запрос для IPv4 или IPv6."""
    ip = ipaddress.ip_address(addr)
    base = _find_base_url(ip, cidr_map)
    url = urljoin(_normalize_base_url(base, RDAP_IP_SUFFIX), f'ip/{str(ip)}')
    return fetch_json(url, timeout, max_size)


def get_truncate_string(
    str_in: str, max_length: int = 17, replacement: str = '...'
) -> str:
    """Обрезает строку и добавляет строку замены, если строка обрезана."""
    abs_truncate = abs(max_length)
    replacement_length = len(replacement)
    str_in_length = len(str_in)
    return (
        str_in
        if str_in_length <= abs_truncate or str_in_length <= replacement_length
        else str_in[:max(0, abs_truncate - replacement_length)] + replacement
    )


def format_json(
    data: Any,
    max_depth: int = MAX_DEPTH,
    indent: int = DUMP_INDENT,
    current_depth: int = 1,
    max_text_length: int = MAX_LINE_LENGTH,
    remaining_chars: bool = SHOW_REMAINING_CHARS,
    seen: set[int] | None = None,
) -> str:
    """Рекурсивное форматирование JSON с ограничением глубины."""
    if seen is None:
        seen = set()
    obj_id = id(data)
    if obj_id in seen:
        raise ValueError('Cycle detected')
    seen.add(obj_id)
    try:
        if current_depth >= max_depth:
            short = json.dumps(data, ensure_ascii=False, separators=(',', ':'))
            original_len = len(short)
            short = get_truncate_string(short, max_text_length)
            if remaining_chars and len(short) < original_len:
                short += f' [{original_len - len(short)} chars]'
            return short
        if isinstance(data, dict):
            if not data:
                return '{}'
            level_indent = ' ' * (current_depth * indent)
            closing_indent = ' ' * ((current_depth - 1) * indent)
            items = []
            for key, value in data.items():
                key_str = json.dumps(key, ensure_ascii=False)
                val_str = format_json(
                    value, max_depth, indent, current_depth+1, max_text_length,
                    remaining_chars, seen,
                )
                items.append(f'{level_indent}{key_str}: {val_str}')
            return '{\n' + ',\n'.join(items) + '\n' + closing_indent + '}'
        if isinstance(data, list):
            if not data:
                return '[]'
            level_indent = ' ' * (current_depth * indent)
            closing_indent = ' ' * ((current_depth - 1) * indent)
            items = [
                format_json(item, max_depth, indent, current_depth + 1,
                            max_text_length, remaining_chars, seen)
                for item in data
            ]
            fmtd_items = [f'{level_indent}{item}' for item in items]
            return '[\n' + ',\n'.join(fmtd_items) + '\n' + closing_indent + ']'
        if isinstance(data, str):
            original_len = len(data)
            short = get_truncate_string(data, max_text_length)
            if remaining_chars and len(short) < original_len:
                short += f' [{original_len - len(short)} chars]'
            return json.dumps(short, ensure_ascii=False)
        return json.dumps(data, ensure_ascii=False)
    finally:
        seen.remove(obj_id)


def main():
    parser = argparse.ArgumentParser(
        description=(
            'Who-Is — A utility for retrieving registration data on '
            'IP address and domain name owners.'
        )
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-a', '--addr', help='Single IP or domain')
    group.add_argument('-l', '--list', help='File with list of IPs/domains')
    parser.add_argument(
        '--dns',
        default=DNS_PATH,
        help='RDAP bootstrap file for Domain Name System registrations',
    )
    parser.add_argument(
        '--ipv4',
        default=IPV4_PATH,
        help='RDAP bootstrap file for IPv4 address allocations',
    )
    parser.add_argument(
        '--ipv6',
        default=IPV6_PATH,
        help='RDAP bootstrap file for IPv6 address allocations',
    )
    parser.add_argument(
        '--tld',
        default=TLD_PATH,
        help='YAML file containing custom RDAP providers',
    )
    parser.add_argument(
        '--silent', action='store_true', help='Suppress banner output',
    )
    parser.add_argument(
        '--no-pretty',
        action='store_true',
        help='Disable pretty-printed JSON output',
    )
    parser.add_argument(
        '-i',
        '--indent',
        type=int,
        default=DUMP_INDENT,
        help=(f'Indent level for pretty-printed JSON array elements '
              f'(default: {DUMP_INDENT}). '
              f'Use 0 for the most compact representation'),
    )
    parser.add_argument(
        '-md',
        '--max-depth',
        type=int,
        default=MAX_DEPTH,
        help=(f'Maximum nesting depth for pretty-printed output '
              f'(default: {MAX_DEPTH}). '
              f'Deeper levels are shown compactly as a single line'),
    )
    parser.add_argument(
        '-ml',
        '--max-line-length',
        type=int,
        default=MAX_LINE_LENGTH,
        help=(f'Maximum length of compact JSON fragments before truncation '
              f'(default: {MAX_LINE_LENGTH})'),
    )
    parser.add_argument(
        '--max-size',
        type=int,
        default=MAX_RESPONSE_SIZE,
        help=(f'Maximum response size in bytes (default: '
              f'{((MAX_RESPONSE_SIZE * 10 + 1023) // 1024) / 10} KB'
              f'). Use 0 for no limit (not recommended)'),
    )
    parser.add_argument(
        '-t',
        '--timeout',
        type=float,
        default=TIMEOUT,
        help=f'Connection timeout in sec (default: {TIMEOUT})',
    )
    parser.add_argument(
        '-o',
        '--output',
        help='Output file (default: CLI output)',
    )
    # parser.add_argument(
    #     '--threads',
    #     type=int,
    #     default=1,
    #     help='Number of threads (default: 1)',
    # )
    # parser.add_argument(
    #     '-u',
    #     '--update',
    #     action='store_true',
    #     help='Update RDAP bootstrap files',
    # )
    args = parser.parse_args()

    if not args.silent and sys.stdout.isatty():
        print(BANNER)

    addrs = set()
    if args.addr:
        addrs.add(args.addr)
    elif args.list:
        try:
            with open(args.list, encoding='utf-8') as f:
                addrs = {line.strip() for line in f if line.strip()}
        except OSError as e:
            print(f'Cannot read list file: {e}', file=sys.stderr)
            sys.exit(1)
    if not addrs:
        print(f'Address list `{args.list}` is empty', file=sys.stderr)
        sys.exit(1)

    try:
        rdap_dns = safely_loader(args.dns, load_rdap)
        rdap_ipv4 = safely_loader(args.ipv4, load_rdap)
        rdap_ipv6 = safely_loader(args.ipv6, load_rdap)
        custom_tld = safely_loader(args.tld, load_tld)
    except LoadError as e:
        print(f'Failed to load bootstrap data: {e}', file=sys.stderr)
        sys.exit(1)
    TLD_MAP = build_tld_map(rdap_dns) | custom_tld
    IPV4_MAP = build_cidr_map(rdap_ipv4)
    IPV6_MAP = build_cidr_map(rdap_ipv6)

    out_file = None
    try:
        if args.output:
            out_file = open(args.output, 'w', encoding='utf-8')
        for addr in addrs:
            try:
                try:
                    ip = ipaddress.ip_address(addr)
                except ValueError:
                    ip = None
                if ip is not None:
                    data = lookup_ip(
                        addr,
                        IPV4_MAP if ip.version == 4 else IPV6_MAP,
                        timeout=args.timeout,
                        max_size=args.max_size,
                    )
                else:
                    data = lookup_domain(
                        addr,
                        TLD_MAP,
                        timeout=args.timeout,
                        max_size=args.max_size,
                    )
            except KeyboardInterrupt:
                raise
            except Exception as e:
                data = {'Error': f'Error processing `{addr}`: {e}'}
            if args.no_pretty:
                result_json = json.dumps(
                    {addr: data},
                    indent=None if args.indent == 0 else args.indent,
                    ensure_ascii=False,
                )
            else:
                result_json = format_json(
                    {addr: data},
                    max_depth=args.max_depth+1,
                    indent=args.indent,
                    max_text_length=args.max_line_length,
                )
            if out_file is not None:
                out_file.write(result_json + '\n')
            else:
                if not args.silent and sys.stdout.isatty():
                    print(ADDR_TEMPLATE.format(addr))
                print(result_json)
    finally:
        if out_file is not None:
            out_file.close()


if __name__ == '__main__':
    main()
