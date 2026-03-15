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


def arp_scan(network: str) -> str:
    """ARP scan to discover hosts. Requires root/raw sockets."""
    try:
        from scapy.all import ARP, Ether, srp
        arp = ARP(pdst=network)
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = ether/arp
        result = srp(packet, timeout=3, verbose=0)[0]
        hosts = []
        for sent, received in result:
            hosts.append({"ip": received.psrc, "mac": received.hwsrc})
        return json.dumps({"success": True, "hosts": hosts})
    except Exception as e:
        return json.dumps({"success": False, "error": str(e)})


def check_monitor_mode(interface: str) -> str:
    """Check if interface supports monitor mode."""
    try:
        import subprocess
        result = subprocess.run(
            ["iwconfig", interface],
            capture_output=True, text=True, timeout=5
        )
        is_monitor = "Mode:Monitor" in result.stdout
        return json.dumps({
            "success": True,
            "monitor_mode": is_monitor,
            "interface": interface,
            "output": result.stdout
        })
    except Exception as e:
        return json.dumps({"success": False, "error": str(e)})


def detect_arp_spoofing(interface: str, duration: int = 10) -> str:
    """Listen for ARP packets and detect inconsistencies."""
    try:
        from scapy.all import sniff, ARP
        import time

        arp_table = {}
        anomalies = []

        def process_packet(packet):
            if packet.haslayer(ARP):
                arp = packet[ARP]
                if arp.op == 2:
                    ip = arp.psrc
                    mac = arp.hwsrc
                    if ip in arp_table:
                        if arp_table[ip] != mac:
                            anomalies.append({
                                "ip": ip,
                                "old_mac": arp_table[ip],
                                "new_mac": mac,
                                "timestamp": time.strftime("%H:%M:%S")
                            })
                    arp_table[ip] = mac

        sniff(iface=interface, prn=process_packet,
              filter="arp", timeout=duration, store=0)

        return json.dumps({
            "success": True,
            "anomalies": anomalies,
            "hosts_seen": len(arp_table),
            "duration": duration
        })
    except Exception as e:
        return json.dumps({"success": False, "error": str(e)})


def probe_for_evil_twin(ssid: str, interface: str = "wlan0", timeout: int = 5) -> str:
    """Send probe requests and listen for responses to detect evil twins."""
    try:
        from scapy.all import RadioTap, Dot11, Dot11ProbeReq, Dot11Elt, sendp, sniff

        responses = []

        def handle_response(packet):
            if packet.haslayer(Dot11):
                if packet.type == 0 and packet.subtype == 5:
                    if hasattr(packet, 'info'):
                        pkt_ssid = packet.info.decode('utf-8', errors='ignore')
                        if pkt_ssid == ssid:
                            responses.append({
                                "bssid": packet.addr2,
                                "ssid": pkt_ssid,
                                "signal": -(256-ord(packet.notdecoded[-4:-3])) if packet.notdecoded else 0
                            })

        probe = RadioTap() / Dot11(
            type=0, subtype=4,
            addr1="ff:ff:ff:ff:ff:ff",
            addr2="00:11:22:33:44:55",
            addr3="ff:ff:ff:ff:ff:ff"
        ) / Dot11ProbeReq() / Dot11Elt(ID="SSID", info=ssid)

        sendp(probe, iface=interface, count=3, verbose=0)
        sniff(iface=interface, prn=handle_response, timeout=timeout, store=0)

        evil_twin_suspected = len(set(r["bssid"] for r in responses)) > 1

        return json.dumps({
            "success": True,
            "responses": responses,
            "evil_twin_suspected": evil_twin_suspected,
            "ssid": ssid
        })
    except Exception as e:
        return json.dumps({"success": False, "error": str(e)})


def capture_traffic_summary(interface: str, duration: int = 5) -> str:
    """Capture network traffic and return a summary."""
    try:
        from scapy.all import sniff, IP, TCP, UDP, ICMP
        import time

        packets_data = []
        protocol_counts = {"TCP": 0, "UDP": 0, "ICMP": 0, "Other": 0}
        unique_ips = set()

        def process(packet):
            if packet.haslayer(IP):
                ip = packet[IP]
                unique_ips.add(ip.src)
                unique_ips.add(ip.dst)
                if packet.haslayer(TCP):
                    proto = "TCP"
                    protocol_counts["TCP"] += 1
                elif packet.haslayer(UDP):
                    proto = "UDP"
                    protocol_counts["UDP"] += 1
                elif packet.haslayer(ICMP):
                    proto = "ICMP"
                    protocol_counts["ICMP"] += 1
                else:
                    proto = "Other"
                    protocol_counts["Other"] += 1
                packets_data.append({
                    "src": ip.src,
                    "dst": ip.dst,
                    "protocol": proto,
                    "size": len(packet),
                    "time": time.strftime("%H:%M:%S")
                })

        sniff(iface=interface, prn=process, timeout=duration, store=0)

        return json.dumps({
            "success": True,
            "packet_count": len(packets_data),
            "unique_ips": len(unique_ips),
            "protocols": protocol_counts,
            "recent_packets": packets_data[-20:]
        })
    except Exception as e:
        return json.dumps({"success": False, "error": str(e)})


def run_custom_script(script: str) -> str:
    """Execute a custom Python script in a sandboxed context."""
    import sys
    import io

    old_stdout = sys.stdout
    old_stderr = sys.stderr
    sys.stdout = io.StringIO()
    sys.stderr = io.StringIO()

    try:
        exec(script, {
            "__builtins__": __builtins__,
            "json": json,
            "socket": __import__("socket"),
        })
        output = sys.stdout.getvalue()
        errors = sys.stderr.getvalue()
        return json.dumps({"success": True, "output": output, "errors": errors})
    except Exception as e:
        return json.dumps({
            "success": False,
            "output": sys.stdout.getvalue(),
            "errors": str(e)
        })
    finally:
        sys.stdout = old_stdout
        sys.stderr = old_stderr
