import ipaddress

IpNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network

# Atajos para --allow-from
NETWORK_KEYWORDS = {
    "local": ("127.0.0.0/8", "::1/128"),
    # Redes privadas (RFC 1918 y ULA): la LAN y las redes internas de Docker, nunca Internet
    "privadas": ("127.0.0.0/8", "::1/128", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7"),
    "todas": ("0.0.0.0/0", "::/0"),
}


def parse_networks(text: str) -> list[IpNetwork]:
    networks = []
    for item in (part.strip() for part in text.split(",")):
        if not item:
            continue
        # Una palabra clave se expande; lo demás debe ser una IP o un rango CIDR (192.168.1.0/24)
        for network_text in NETWORK_KEYWORDS.get(item, (item,)):
            networks.append(ipaddress.ip_network(network_text, strict=False))
    return networks


def _as_ip(text: str):
    try:
        address = ipaddress.ip_address(text)
    except ValueError:
        return None
    # Una IPv4 vista a través de un socket IPv6 llega como ::ffff:192.168.1.7
    if address.version == 6 and address.ipv4_mapped is not None:
        return address.ipv4_mapped
    return address


def host_without_port(host_header: str) -> str:
    if host_header.startswith("["):
        return host_header[1:host_header.find("]")]
    return host_header.rsplit(":", 1)[0] if host_header.count(":") == 1 else host_header


class NetworkAccessPolicy:
    def __init__(self, allowed_networks: list[IpNetwork] | None, allowed_host_names: frozenset[str]):
        self._allowed_networks = allowed_networks
        self._allowed_host_names = allowed_host_names

    def client_allowed(self, client_address: str | None) -> bool:
        # Sin lista de redes no se filtra (solo se usa en pruebas)
        if self._allowed_networks is None:
            return True
        address = _as_ip(client_address or "")
        return address is not None and any(address in network for network in self._allowed_networks)

    def host_header_allowed(self, host_header: str) -> bool:
        host = host_without_port(host_header)
        # Entrar por IP es seguro: el ataque de "DNS rebinding" necesita un nombre de dominio que cambie de IP
        if _as_ip(host) is not None:
            return True
        return host in self._allowed_host_names


def is_loopback_host(host: str) -> bool:
    address = _as_ip(host)
    return host == "localhost" if address is None else address.is_loopback
