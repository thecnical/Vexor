"""
Vexor Port Scanner
Uses python-nmap + scapy for powerful port scanning
"""
import asyncio
import socket
from urllib.parse import urlparse
from vexor.modules.base import BaseScanner, Finding


# Common ports with service names
COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
    53: "DNS", 80: "HTTP", 110: "POP3", 143: "IMAP",
    443: "HTTPS", 445: "SMB", 993: "IMAPS", 995: "POP3S",
    1433: "MSSQL", 1521: "Oracle", 2181: "Zookeeper",
    3000: "Node/Dev", 3306: "MySQL", 3389: "RDP",
    4444: "Metasploit", 5000: "Flask/Dev", 5432: "PostgreSQL",
    5900: "VNC", 6379: "Redis", 6443: "Kubernetes",
    7001: "WebLogic", 8000: "HTTP-Alt", 8080: "HTTP-Proxy",
    8443: "HTTPS-Alt", 8888: "Jupyter", 9000: "PHP-FPM",
    9090: "Prometheus", 9200: "Elasticsearch", 9300: "Elasticsearch",
    11211: "Memcached", 27017: "MongoDB", 27018: "MongoDB",
}

DANGEROUS_PORTS = {
    21: "FTP — often allows anonymous login",
    23: "Telnet — unencrypted, replace with SSH",
    445: "SMB — EternalBlue target",
    1433: "MSSQL — database exposed",
    3306: "MySQL — database exposed",
    3389: "RDP — brute force target",
    4444: "Metasploit default — backdoor?",
    5432: "PostgreSQL — database exposed",
    5900: "VNC — remote desktop exposed",
    6379: "Redis — often no auth",
    8888: "Jupyter — often no auth",
    9200: "Elasticsearch — often no auth",
    11211: "Memcached — amplification DDoS",
    27017: "MongoDB — often no auth",
}


class Scanner(BaseScanner):
    """Port Scanner"""

    MODULE_NAME = "port_scanner"
    MODULE_DESC = "TCP Port Scanner with Service Detection"

    async def scan(self) -> list[Finding]:
        parsed = urlparse(self.target)
        host = parsed.hostname or self.target

        # Try nmap first (most powerful)
        nmap_success = await self._scan_with_nmap(host)

        # Fallback to socket scan
        if not nmap_success:
            await self._scan_with_sockets(host)

        return self.findings

    async def _scan_with_nmap(self, host: str) -> bool:
        """Scan using python-nmap"""
        try:
            import nmap
            loop = asyncio.get_event_loop()

            def run_nmap():
                nm = nmap.PortScanner()
                # Fast scan of common ports
                nm.scan(host, arguments='-sV -T4 --top-ports 100 --open')
                return nm

            nm = await loop.run_in_executor(None, run_nmap)

            for host_ip in nm.all_hosts():
                for proto in nm[host_ip].all_protocols():
                    ports = nm[host_ip][proto].keys()
                    for port in ports:
                        state = nm[host_ip][proto][port]['state']
                        service = nm[host_ip][proto][port].get('name', '')
                        version = nm[host_ip][proto][port].get('version', '')
                        product = nm[host_ip][proto][port].get('product', '')

                        if state == 'open':
                            severity = "INFO"
                            desc = f"Port {port}/{proto} open — {service}"

                            if port in DANGEROUS_PORTS:
                                severity = "HIGH"
                                desc = DANGEROUS_PORTS[port]

                            self.add_finding(Finding(
                                severity=severity,
                                module=self.MODULE_NAME,
                                vuln=f"Open Port: {port}/{proto} ({service})",
                                endpoint=self.target,
                                evidence=(
                                    f"Port {port} open | "
                                    f"Service: {product} {version}".strip()
                                ),
                                description=desc,
                                remediation=(
                                    f"Review if port {port} needs to be publicly accessible. "
                                    "Use firewall to restrict access."
                                ),
                            ))
            return True

        except ImportError:
            return False
        except Exception:
            return False

    async def _scan_with_sockets(self, host: str) -> None:
        """Fallback socket-based port scan"""
        semaphore = asyncio.Semaphore(100)
        open_ports = []

        async def check_port(port: int):
            async with semaphore:
                try:
                    loop = asyncio.get_event_loop()
                    conn = asyncio.open_connection(host, port)
                    reader, writer = await asyncio.wait_for(conn, timeout=1.0)
                    writer.close()
                    await writer.wait_closed()
                    open_ports.append(port)
                except Exception:
                    pass

        tasks = [check_port(p) for p in COMMON_PORTS.keys()]
        await asyncio.gather(*tasks, return_exceptions=True)

        for port in open_ports:
            service = COMMON_PORTS.get(port, "unknown")
            severity = "HIGH" if port in DANGEROUS_PORTS else "INFO"

            self.add_finding(Finding(
                severity=severity,
                module=self.MODULE_NAME,
                vuln=f"Open Port: {port} ({service})",
                endpoint=self.target,
                evidence=f"TCP port {port} is open",
                description=DANGEROUS_PORTS.get(port, f"Port {port} ({service}) is open"),
                remediation=f"Review if port {port} needs to be publicly accessible",
            ))
