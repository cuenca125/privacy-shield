import socket
import json
import concurrent.futures

def run_host_scan(target: str) -> str:
    try:
        hosts_to_scan = []
        if "/" in target:
            ip_part, prefix = target.split("/")
            prefix = int(prefix)
            ip_int = ip_to_int(ip_part)
            mask = (0xFFFFFFFF << (32 - prefix)) & 0xFFFFFFFF
            network = ip_int & mask
            start = network + 1
            end = network + min(254, (1 << (32 - prefix)) - 2)
            hosts_to_scan = [int_to_ip(i) for i in range(start, end + 1)]
        else:
            hosts_to_scan = [target]

        results = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
            future_to_ip = {executor.submit(probe_host, ip): ip for ip in hosts_to_scan}
            for future in concurrent.futures.as_completed(future_to_ip):
                ip = future_to_ip[future]
                try:
                    is_up, hostname = future.result()
                    if is_up:
                        results.append({"ip": ip, "hostname": hostname, "state": "up", "vendor": {}})
                except Exception:
                    pass

        results.sort(key=lambda x: int(x["ip"].split(".")[-1]))
        return json.dumps({"success": True, "hosts": results, "count": len(results)})
    except Exception as e:
        return json.dumps({"success": False, "error": str(e)})

def probe_host(ip: str, timeout: float = 0.5) -> tuple:
    probe_ports = [80, 443, 22, 8080, 53, 21, 23, 445]
    for port in probe_ports:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((ip, port))
            sock.close()
            if result == 0:
                hostname = ""
                try:
                    hostname = socket.gethostbyaddr(ip)[0]
                except Exception:
                    pass
                return True, hostname
        except Exception:
            pass
    return False, ""

def run_service_scan(target: str, ports: str = "22,80,443,8080,8443") -> str:
    try:
        port_list = []
        for part in ports.split(","):
            part = part.strip()
            if "-" in part:
                start, end = part.split("-")
                port_list.extend(range(int(start), int(end) + 1))
            else:
                port_list.append(int(part))
        port_list = list(set(port_list))[:200]

        results = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=30) as executor:
            future_to_port = {executor.submit(probe_port, target, port): port for port in port_list}
            for future in concurrent.futures.as_completed(future_to_port):
                port = future_to_port[future]
                try:
                    state, service = future.result()
                    results.append({"port": port, "protocol": "tcp", "state": state, "service": service, "version": "", "product": ""})
                except Exception as e:
                    results.append({"port": port, "protocol": "tcp", "state": "error", "service": "", "version": "", "product": ""})

        results.sort(key=lambda x: (0 if x["state"] == "open" else 1, x["port"]))
        return json.dumps({"success": True, "services": results, "host": target})
    except Exception as e:
        return json.dumps({"success": False, "error": str(e)})

def probe_port(ip: str, port: int, timeout: float = 1.0) -> tuple:
    service = get_service_name(port)
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((ip, port))
        sock.close()
        return ("open" if result == 0 else "closed"), service
    except socket.timeout:
        return "filtered", service
    except Exception:
        return "closed", service

def get_service_name(port: int) -> str:
    known = {
        21:"ftp",22:"ssh",23:"telnet",25:"smtp",53:"dns",80:"http",
        110:"pop3",143:"imap",443:"https",445:"smb",993:"imaps",995:"pop3s",
        1433:"mssql",3306:"mysql",3389:"rdp",5432:"postgresql",5900:"vnc",
        6379:"redis",8080:"http-alt",8443:"https-alt",8888:"jupyter",
        27017:"mongodb",9200:"elasticsearch"
    }
    return known.get(port, f"port-{port}")

def ip_to_int(ip: str) -> int:
    parts = ip.split(".")
    return (int(parts[0])<<24)|(int(parts[1])<<16)|(int(parts[2])<<8)|int(parts[3])

def int_to_ip(n: int) -> str:
    return f"{(n>>24)&0xFF}.{(n>>16)&0xFF}.{(n>>8)&0xFF}.{n&0xFF}"
