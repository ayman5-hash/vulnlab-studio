import ipaddress
import socket

from urllib.parse import urlparse


ALLOWED_HOSTS = {
    "127.0.0.1",
    "localhost",
}


ALLOWED_NETWORKS = [
    ipaddress.ip_network("192.168.56.0/24"),
    ipaddress.ip_network("10.10.10.0/24"),
]


def target_allowed(url: str) -> bool:

    parsed = urlparse(url)

    host = parsed.hostname

    if not host:
        return False

    if host in ALLOWED_HOSTS:
        return True

    try:
        resolved = socket.gethostbyname(host)

        ip = ipaddress.ip_address(
            resolved
        )

    except Exception:
        return False

    return any(
        ip in network
        for network in ALLOWED_NETWORKS
    )
