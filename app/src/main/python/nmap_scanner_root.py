import json

def run_host_scan_nmap(target: str) -> str:
    try:
        import nmap
        nm = nmap.PortScanner()
        nm.scan(hosts=target, arguments="-sn -T4")
        results = []
        for host in nm.all_hosts():
            results.append({
                "ip": host,
                "hostname": nm[host].hostname(),
                "state": nm[host].state(),
                "vendor": nm[host].get("vendor", {})
            })
        return json.dumps({"success": True, "hosts": results, "count": len(results)})
    except Exception as e:
        return json.dumps({"success": False, "error": str(e)})

def run_service_scan_nmap(target: str, ports: str = "22,80,443,8080,8443") -> str:
    try:
        import nmap
        nm = nmap.PortScanner()
        nm.scan(hosts=target, ports=ports, arguments="-sV --version-intensity 2 -T4")
        results = []
        for host in nm.all_hosts():
            for proto in nm[host].all_protocols():
                for port in nm[host][proto].keys():
                    svc = nm[host][proto][port]
                    results.append({
                        "port": port, "protocol": proto,
                        "state": svc["state"], "service": svc["name"],
                        "version": svc.get("version",""), "product": svc.get("product","")
                    })
        return json.dumps({"success": True, "services": results, "host": target})
    except Exception as e:
        return json.dumps({"success": False, "error": str(e)})
