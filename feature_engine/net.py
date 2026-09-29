import ipaddress
from functools import lru_cache

# Address space an enclave uses internally. Deliberately narrower than ipaddress.is_private, which
# also counts documentation ranges (e.g. 198.51.100.0/24) that stand in for external hosts.
_INTERNAL_NETS = [ipaddress.ip_network(n) for n in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",   # RFC 1918
    "100.64.0.0/10",                                    # carrier-grade NAT
    "127.0.0.0/8", "169.254.0.0/16",                    # loopback, link-local
    "fc00::/7", "fe80::/10", "::1/128",                 # IPv6 ULA, link-local, loopback
)]


@lru_cache(maxsize=65536)
def is_broadcast_or_multicast(value: str) -> bool:
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return False
    # x.x.x.255 is treated as a subnet broadcast (the /24 case that dominates LANs)
    return ip.is_multicast or (ip.version == 4 and value.endswith(".255"))


@lru_cache(maxsize=65536)
def is_internal_ip(value: str) -> bool:
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return False
    return any(ip in net for net in _INTERNAL_NETS if net.version == ip.version)
