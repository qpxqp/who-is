import argparse
import ipaddress
import json
import sys
from dataclasses import dataclass, fields
from enum import StrEnum
from functools import reduce
from pathlib import Path
from typing import Any

import requests
import yaml
from colorama import Fore, Style, init

IPNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network
IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address

# RDAP_ENDPOINTS = {
#     'dns': 'https://data.iana.org/rdap/dns.json',
#     'ipv4': 'https://data.iana.org/rdap/ipv4.json',
#     'ipv6': 'https://data.iana.org/rdap/ipv6.json',
#     'values': 'https://www.iana.org/assignments/rdap-json-values'
# }

BASE_DIR = Path(__file__).parent
FILES_DIR = BASE_DIR / 'files'

DNS_PATH = FILES_DIR / 'dns.json'
IPV4_PATH = FILES_DIR / 'ipv4.json'
IPV6_PATH = FILES_DIR / 'ipv6.json'
TLD_PATH = FILES_DIR / 'tld-rdap.yaml'
RULES_PATH = FILES_DIR / 'risk-scoring.yaml'

TLD_KEY = 'tld_rdap'
RULES_KEY = 'rules'
RULE_FIELD_DELIMITER = '.'
FILE_ENCODING = 'utf-8'

TIMEOUT = 10.0
FALLBACK_V4 = 'https://rdap.arin.net/registry/ip/'
FALLBACK_V6 = 'https://rdap.arin.net/registry/ip/'

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


class LoadFromFileError(Exception):
    pass


class LoadRulesError(Exception):
    pass


class RdapLookupError(Exception):
    pass


class RuleOperator(StrEnum):
    # CONTAINS = 'contains'  # The array contains the specified value
    ANY = 'any'  # The array contains at least one of the values
    EQ = 'equal'
    # NE = '!='
    # GT = '>'
    # LT = '<'
    # GTE = '>='
    # LTE = '<='


@dataclass
class Rule:
    field: str
    operator: RuleOperator
    value: list[Any]
    score: int
    reason: str
    index: int = -1


@dataclass
class Config:
    tld_map: dict[str, str]
    ipv4_cidr_map: list[tuple[IPNetwork, str]]
    ipv6_cidr_map: list[tuple[IPNetwork, str]]
    rules: list[Rule]


@dataclass(frozen=True, slots=True)
class AddressResult:
    address: str
    data: Any | None = None
    warning: str | None = None
    error: str | None = None


ALLOWED_OPERATORS = tuple(op.value for op in RuleOperator)
YAML_RULE_FIELDS = {f.name for f in fields(Rule)} - {'index'}


def load_rdap(path: Path, encoding: str = FILE_ENCODING) -> Any:
    with open(path, encoding=encoding) as f:
        return json.load(f)


def load_yaml(
    path: Path, keys: tuple[str, ...], encoding: str = FILE_ENCODING,
) -> dict[str, dict]:
    with open(path, encoding=encoding) as f:
        data = yaml.safe_load(f)
    return (
        {key: data.get(key, {}) for key in keys}
        if isinstance(data, dict) else
        {key: {} for key in keys}
    )


def load_addr_list(path: Path, encoding: str = FILE_ENCODING) -> set[str]:
    addrs: set[str] = set()
    with open(path, encoding=encoding) as f:
        addrs.update(line.strip() for line in f if line.strip())
    return addrs


def safely_loader(path, loader, *args, **kwargs):
    try:
        return loader(path, *args, **kwargs)
    except Exception as e:
        raise LoadFromFileError(
            f'Failed to load data from `{path}`: {e}'
        ) from e


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


def build_rules(raw_rules: Any) -> list[Rule]:
    if not isinstance(raw_rules, list):
        raise LoadRulesError(
            f'Rules must be a list, got {type(raw_rules).__name__}'
        )
    rules = []
    for idx, item in enumerate(raw_rules, start=1):
        missing = YAML_RULE_FIELDS - item.keys()
        if missing:
            raise LoadRulesError(f'Rule #{idx} missing fields: {missing}')
        op = item['operator']
        if op not in ALLOWED_OPERATORS:
            raise LoadRulesError(
                f'Rule #{idx} `operator` must be one of {ALLOWED_OPERATORS}, '
                f'got {op!r}'
            )
        if not isinstance(item['score'], int):
            raise LoadRulesError(
                f'Rule #{idx} `score` must be int, '
                f'got {type(item["score"]).__name__}'
            )
        val = item['value']
        if op == RuleOperator.ANY and not isinstance(val, list):
            raise LoadRulesError(
                f'Rule #{idx} `value` must be a list, '
                f'got {type(val).__name__}'
            )
        try:
            rules.append(Rule(**item, index=idx))
        except TypeError as e:
            raise LoadRulesError(f'Rule #{idx} invalid data: {e}') from e
    if not rules:
        raise LoadRulesError('The list of rules is empty')
    return rules


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
    raise RdapLookupError(f'Base url not found for `{ip}`')


def fetch_json(url: str, timeout: float, max_size: int) -> Any:
    try:
        with session.get(url, timeout=timeout, stream=True) as response:
            response.raise_for_status()
            chunks = []
            total_size = 0
            for chunk in response.iter_content(chunk_size=CHUNK_SIZE):
                chunks.append(chunk)
                total_size += len(chunk)
                if max_size and total_size > max_size:
                    raise RdapLookupError(
                        f'Response from {url} exceeds '
                        f'size limit ({max_size} bytes), '
                        f'got {total_size} bytes'
                    )
            content = b''.join(chunks)
    except requests.RequestException as e:
        raise RdapLookupError(
            f'RDAP request failed: {url}'
        ) from e
    try:
        return json.loads(content)
    except (json.JSONDecodeError, UnicodeDecodeError) as e:
        raise RdapLookupError(f'Response is not valid JSON: {e}') from e


def _build_rdap_url(base: str, resource: str, value: str) -> str:
    base = base.rstrip('/')
    suffix = f'/{resource}'
    if base.endswith(suffix):
        base = base[:-len(suffix)]
    return f'{base}{suffix}/{value}'


def _lookup_domain(
    addr: str, tld_map: dict[str, str], timeout: float, max_size: int,
) -> tuple[Any, str | None]:
    """Делает RDAP-запрос для домена."""
    domain = addr.strip().lower()
    if not domain or '.' not in domain:
        raise RdapLookupError(f'Invalid domain: `{domain}`')
    try:
        domain = domain.encode('idna').decode('ascii')
    except UnicodeError as e:
        raise RdapLookupError(f'Invalid domain name: `{addr}`') from e
    tld = domain.rsplit('.', 1)[-1]
    base = tld_map.get(tld)
    if not base:
        raise RdapLookupError(f'No RDAP server configured for TLD `{tld}`')
    url = _build_rdap_url(base, 'domain', domain)
    return fetch_json(url, timeout, max_size), None


def _lookup_ip(
    ip: IPAddress,
    cidr_map: list[tuple[IPNetwork, str]],
    timeout: float,
    max_size: int,
    fallback: str,
) -> tuple[Any, str | None]:
    """Делает RDAP-запрос для IPv4 или IPv6."""
    warning = None
    try:
        base = _find_base_url(ip, cidr_map)
    except RdapLookupError as e:
        base = fallback
        warning = f'Warning: {e}. Fallback was used `{base}`'
    addr = str(ip)
    url = _build_rdap_url(base, 'ip', addr)
    return fetch_json(url, timeout, max_size), warning


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


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            'Who-Is — A utility for retrieving registration data on '
            'IP address and domain name owners.'
        )
    )
    parser.add_argument(
        'addr',
        nargs='*',
        help='One or more IPs/domains (space-separated)',
    )
    parser.add_argument('-l', '--list', help='File with list of IPs/domains')
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
        '--rules',
        default=RULES_PATH,
        help='YAML file containing custom risk scoring rules',
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
    parser.add_argument('-e', action='store_true', help='Experimental')
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
    return parser.parse_args()


def load_config(
    dns_path: str,
    ipv4_path: str,
    ipv6_path: str,
    tld_path: str,
    rules_path: str,
) -> Config:
    loaders = {
        'dns': dict(path=dns_path, loader=load_rdap),
        'ipv4': dict(path=ipv4_path, loader=load_rdap),
        'ipv6': dict(path=ipv6_path, loader=load_rdap),
        'tld': dict(path=tld_path, loader=load_yaml, keys=(TLD_KEY,)),
        'rules': dict(path=rules_path, loader=load_yaml, keys=(RULES_KEY,)),
    }
    data, errors = {}, {}
    for arg, params in loaders.items():
        try:
            data[arg] = safely_loader(**params)
        except LoadFromFileError as e:
            errors.update({f'Argument --{arg}': f'{e}'})
    if errors:
        raise LoadFromFileError(errors)
    raw_rules = data['rules'].get(RULES_KEY)
    raw_tld = data['tld'].get(TLD_KEY)
    if not raw_tld or not isinstance(raw_tld, dict):
        raise LoadFromFileError(f'TLD file `{tld_path}` is invalid')
    return Config(
        tld_map=build_tld_map(data['dns']) | raw_tld,
        ipv4_cidr_map=build_cidr_map(data['ipv4']),
        ipv6_cidr_map=build_cidr_map(data['ipv6']),
        rules=build_rules(raw_rules),
    )


def _lookup_address(
    addr: str,
    config: Config,
    timeout: float,
    max_size: int,
) -> tuple[Any, str | None]:
    try:
        ip = ipaddress.ip_address(addr)
    except ValueError:
        return _lookup_domain(
            addr=addr,
            tld_map=config.tld_map,
            timeout=timeout,
            max_size=max_size,
        )
    cidr_map, fallback = (
        (config.ipv4_cidr_map, FALLBACK_V4)
        if ip.version == 4 else
        (config.ipv6_cidr_map, FALLBACK_V6)
    )
    return _lookup_ip(
        ip=ip,
        cidr_map=cidr_map,
        timeout=timeout,
        max_size=max_size,
        fallback=fallback,
    )


def query_address(
    addr: str, config: Config, timeout: float, max_size: int,
) -> AddressResult:
    try:
        data, warning = _lookup_address(addr, config, timeout, max_size)
    except RdapLookupError as e:
        return AddressResult(address=addr, error=str(e))
    return AddressResult(address=addr, data=data, warning=warning)


def _get_item(obj: Any, key: str, default: Any = None) -> Any:
    """Получить элемент из dict или list."""
    if isinstance(obj, dict):
        return obj.get(key, default)
    elif isinstance(obj, list):
        return [
            item[key] for item in obj
            if isinstance(item, dict) and key in item
        ]
    else:
        return getattr(obj, key, default)


def get_field(
    data: dict,
    field_path: str,
    delimiter: str = RULE_FIELD_DELIMITER,
    default: Any = None,
) -> Any:
    """Получение значения по пути вложенности."""
    if not field_path:
        return default
    try:
        keys = field_path.split(delimiter)
        return reduce(_get_item, keys, data)
    except (KeyError, TypeError, IndexError, AttributeError):
        return default


def matches_rule(operator: RuleOperator, got: Any, expected: Any) -> bool:
    match operator:
        case RuleOperator.ANY:
            return any(v in got for v in expected)
        case RuleOperator.EQ:
            return got == expected
        case _:  # fail-safe, см build_rules
            raise ValueError(
                f'Unsupported rule operator: {operator!r}'
            )


def evaluate_rule(
    rule: Rule,
    data: Any,
) -> dict[str, Any]:
    data_value = get_field(data, rule.field)
    if data_value is None and rule.field not in data:
        return {
            'matched': False,
            'error': f'Field `{rule.field}` not found',
            'field': rule.field,
        }
    return {
        'matched': matches_rule(rule.operator, data_value, rule.value),
    }


def main():
    args = parse_arguments()
    if not args.silent and sys.stdout.isatty():
        print(BANNER)
    args_list = None
    if (args_list_path := args.list):
        try:
            args_list = safely_loader(args_list_path, load_addr_list)
        except LoadFromFileError as e:
            print(f'Argument --list error: {e}')
            sys.exit(1)
    addrs = set(args.addr or ()) | set(args_list or ())
    if not addrs:
        print(
            'At least one source (<addr> or `-l`) must be provided',
            file=sys.stderr,
        )
        sys.exit(1)

    try:
        config = load_config(
            args.dns, args.ipv4, args.ipv6, args.tld, args.rules,
        )
    except (LoadFromFileError, LoadRulesError) as e:
        print(f'Configuration error: {e}', file=sys.stderr)
        sys.exit(1)

    out_file = None
    try:
        if args.output:
            out_file = open(args.output, 'w', encoding=FILE_ENCODING)
        for addr in addrs:
            try:
                addr_result = query_address(
                    addr, config, args.timeout, args.max_size,
                )

                if addr_result.warning:
                    print(addr_result.warning)
                data = addr_result.data or addr_result.error  # TMP

            except KeyboardInterrupt:
                raise
            except Exception as e:
                data = {'error': f'Error processing `{addr}`: {e}'}
            if args.no_pretty:
                result_json = json.dumps(
                    {addr: data},
                    indent=None if args.indent == 0 else args.indent,
                    ensure_ascii=False,
                )
            elif args.e:
                print(f'=== Experimental! `{addr}` ===')
                # rules = build_rules(raw_rules)
                total_score = 0
                absents = set()
                violations = {}
                # violations = {
                #     f'#{rule.index} {rule.reason}': evaluate_rule(rule, data)
                #     for rule in rules
                # }
                for rule in config.rules:
                    if rule.field in absents:
                        continue
                    r = evaluate_rule(rule, data)
                    if (f := r.get('field')):
                        absents.add(f)
                    if r.get('matched'):
                        total_score += rule.score
                        violations[f'Rule #{rule.index} {rule.reason}'] = (
                            {'score': rule.score}
                        )
                # print(absents)
                result_json = format_json(
                    {addr: {'Total score': total_score, 'Violations': violations}},
                    max_depth=args.max_depth+1,
                    indent=args.indent,
                    max_text_length=args.max_line_length,
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
