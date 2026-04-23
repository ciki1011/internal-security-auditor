import socket
import scapy.all as scapy
from dataclasses import dataclass, field


@dataclass
class DiscoveredDevice:
    ip: str
    mac: str
    hostname: str = "N/A"
    vendor: str = "Unknown"


def _resolve_hostname(ip: str) -> str:
    """Pokušava reverse DNS lookup. Vraća 'N/A' ako ne uspe."""
    try:
        return socket.gethostbyaddr(ip)[0]
    except socket.herror:
        return "N/A"


def _get_vendor_from_mac(mac: str) -> str:
    """
    OUI lookup — prvih 8 karaktera MAC adrese identifikuju proizvođača.
    TODO: Nedelja 3 — zameniti sa lokalnom IEEE OUI bazom za potpunu pokrivenost.
    """
    OUI_MAP = {
        "b8:27:eb": "Raspberry Pi",
        "dc:a6:32": "Raspberry Pi",
        "00:1a:2b": "Cisco Systems",
        "00:50:56": "VMware",
        "08:00:27": "VirtualBox",
        "00:0c:29": "VMware",
        "ac:16:2d": "Huawei",
        "b4:fb:e4": "Mikrotik",
    }
    oui = mac[:8].lower()
    return OUI_MAP.get(oui, "Unknown Vendor")


def perform_arp_sweep(ip_range: str) -> list[DiscoveredDevice]:
    """
    Šalje ARP broadcast za zadati IP opseg i vraća listu aktivnih uređaja.

    Args:
        ip_range: CIDR notacija, npr. "192.168.1.0/24"

    Returns:
        Lista DiscoveredDevice objekata (ip, mac, hostname, vendor)

    Note:
        Zahteva root/Administrator privilegije (raw sockets).
    """
    print(f"[*] Pokrećem ARP sweep za mrežu: {ip_range}")

    arp_request = scapy.ARP(pdst=ip_range)
    broadcast_frame = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_broadcast_packet = broadcast_frame / arp_request

    answered_list = scapy.srp(arp_broadcast_packet, timeout=2, verbose=False)[0]

    active_devices = []

    for element in answered_list:
        ip = element[1].psrc
        mac = element[1].hwsrc

        device = DiscoveredDevice(
            ip=ip,
            mac=mac,
            hostname=_resolve_hostname(ip),
            vendor=_get_vendor_from_mac(mac),
        )
        active_devices.append(device)

    print(f"[+] Pronađeno {len(active_devices)} uređaja.")
    return active_devices


if __name__ == "__main__":
    test_range = "192.168.1.0/24"
    rezultati = perform_arp_sweep(test_range)

    print("\n--- REZULTATI SKENIRANJA ---")
    print(f"{'IP':<18} {'MAC':<20} {'Hostname':<30} {'Vendor'}")
    print("-" * 80)
    for r in rezultati:
        print(f"{r.ip:<18} {r.mac:<20} {r.hostname:<30} {r.vendor}")