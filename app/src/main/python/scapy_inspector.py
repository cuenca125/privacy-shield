import json


def analyze_packet_info() -> str:
    """
    Returns local interface info using scapy (no root needed).
    """
    try:
        from scapy.all import get_if_list, get_if_addr
        interfaces = []
        for iface in get_if_list():
            try:
                addr = get_if_addr(iface)
                interfaces.append({"interface": iface, "address": addr})
            except Exception:
                pass
        return json.dumps({"success": True, "interfaces": interfaces})
    except Exception as e:
        return json.dumps({"success": False, "error": str(e)})


def check_root_available() -> bool:
    """Check if root/raw socket access is available."""
    try:
        import socket
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        s.close()
        return True
    except PermissionError:
        return False
    except Exception:
        return False
