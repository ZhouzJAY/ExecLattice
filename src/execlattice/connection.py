"""Keep the trusted Controller identity separate from its approved network route."""

from __future__ import annotations

import ipaddress
from urllib.parse import urlsplit

from .security import validate_url

_PRIVATE_ROUTES = tuple(
    ipaddress.ip_network(value)
    for value in (
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "100.64.0.0/10",
        "127.0.0.0/8",
        "fc00::/7",
        "::1/128",
    )
)
_NATIVE_IPV6_UNICAST = ipaddress.ip_network("2000::/3")
_IETF_IPV6_SPECIAL = ipaddress.ip_network("2001::/23")


def validate_connection_url(url: str, *, allow_public_ipv6: bool = False) -> str:
    """Accept a private route, or native public IPv6 after explicit owner opt-in.

    The connection still validates the original Controller hostname against its
    trusted certificate. A changed network address is never a new trust anchor.
    The opt-in does not allow names, public IPv4, translated or tunnel addresses.
    """
    if type(allow_public_ipv6) is not bool:
        raise ValueError("Public IPv6 permission must be an explicit boolean")
    origin = validate_url(url)
    parsed = urlsplit(origin)
    if parsed.username is not None or parsed.password is not None or "?" in origin or "#" in origin:
        raise ValueError("Connection address must be an approved HTTPS IP origin")
    try:
        address = ipaddress.ip_address(parsed.hostname)
    except ValueError:
        raise ValueError("Connection address must use an explicit IP") from None
    private = any(address.version == network.version and address in network for network in _PRIVATE_ROUTES)
    public_ipv6 = (
        allow_public_ipv6
        and isinstance(address, ipaddress.IPv6Address)
        and address in _NATIVE_IPV6_UNICAST
        and address not in _IETF_IPV6_SPECIAL
        and address.is_global
        and not address.is_reserved
        and address.ipv4_mapped is None
        and address.sixtofour is None
        and address.teredo is None
    )
    if (
        address.is_unspecified
        or address.is_multicast
        or address.is_link_local
        or getattr(address, "scope_id", None) is not None
        or not (private or public_ipv6)
    ):
        raise ValueError("Connection address must use a private IP or explicitly approved native public IPv6")
    host = f"[{address.compressed}]" if address.version == 6 else address.compressed
    port = f":{parsed.port}" if parsed.port is not None else ""
    return f"https://{host}{port}"


def connection_origin(config: dict) -> str:
    """Return the validated route, preserving legacy configs without an override."""
    allow_public_ipv6 = config.get("allow_public_ipv6", False)
    if type(allow_public_ipv6) is not bool:
        raise ValueError("Public IPv6 permission must be an explicit boolean")
    canonical = validate_url(config["controller_url"])
    parsed = urlsplit(canonical)
    if parsed.username is not None or parsed.password is not None or "?" in canonical or "#" in canonical:
        raise ValueError("Controller URL must be an HTTPS origin without credentials or path")
    alternate = config.get("connection_url")
    return canonical if alternate is None else validate_connection_url(alternate, allow_public_ipv6=allow_public_ipv6)
