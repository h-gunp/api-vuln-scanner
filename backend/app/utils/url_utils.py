import ipaddress
from urllib.parse import urlsplit


def normalized_http_url(value: str) -> str:
    parsed = urlsplit(value)
    if parsed.scheme.lower() not in {"http", "https"}:
        raise ValueError("Only HTTP and HTTPS targets are allowed")
    if not parsed.hostname:
        raise ValueError("Target URL must include a hostname")
    if parsed.username or parsed.password:
        raise ValueError("Credentials in target URLs are not allowed")
    if parsed.fragment:
        raise ValueError("Target URL fragments are not allowed")
    return value


def is_blocked_ip(value: str) -> bool:
    address = ipaddress.ip_address(value)
    return any(
        (
            address.is_private,
            address.is_loopback,
            address.is_link_local,
            address.is_multicast,
            address.is_reserved,
            address.is_unspecified,
        )
    )


def path_matches(allowed_pattern: str, path: str) -> bool:
    if allowed_pattern.endswith("*"):
        return path.startswith(allowed_pattern[:-1])
    return path == allowed_pattern

