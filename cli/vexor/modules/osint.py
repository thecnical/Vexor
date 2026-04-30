"""
Vexor OSINT Module — SpiderFoot-style intelligence gathering
Collects: subdomains, emails, IPs, technologies, breaches, social media
"""
import asyncio
import re
import socket
from urllib.parse import urlparse
from vexor.modules.base import BaseScanner, Finding


class Scanner(BaseScanner):
    """
    OSINT Intelligence Gatherer
    Inspired by SpiderFoot — passive reconnaissance
    """

    MODULE_NAME = "osint"
    MODULE_DESC = "OSINT Intelligence Gathering (SpiderFoot-style)"

    async def scan(self) -> list[Finding]:
        async with self:
            parsed = urlparse(self.target)
            domain = parsed.hostname or self.target
            if domain.startswith("www."):
                domain = domain[4:]

            await asyncio.gather(
                self._gather_dns_info(domain),
                self._check_email_exposure(domain),
                self._check_certificate_transparency(domain),
                self._check_shodan_style(domain),
                self._check_pastebin_exposure(domain),
                self._gather_social_media(domain),
                self._check_breach_data(domain),
                return_exceptions=True
            )

        return self.findings

    async def _gather_dns_info(self, domain: str) -> None:
        """Gather DNS records"""
        import dns.resolver
        record_types = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"]
        dns_info = {}

        for rtype in record_types:
            try:
                answers = dns.resolver.resolve(domain, rtype, lifetime=5)
                dns_info[rtype] = [str(r) for r in answers]
            except Exception:
                pass

        if dns_info:
            evidence = "\n".join(
                f"{rtype}: {', '.join(records[:3])}"
                for rtype, records in dns_info.items()
            )
            self.add_finding(Finding(
                severity="INFO",
                module=self.MODULE_NAME,
                vuln="DNS Records Gathered",
                endpoint=self.target,
                evidence=evidence,
                description=f"DNS intelligence for {domain}",
                remediation="Review DNS records for sensitive information",
            ))

            # Check for SPF/DMARC
            txt_records = dns_info.get("TXT", [])
            has_spf = any("v=spf1" in r for r in txt_records)
            has_dmarc = False
            try:
                dmarc = dns.resolver.resolve(f"_dmarc.{domain}", "TXT", lifetime=5)
                has_dmarc = True
            except Exception:
                pass

            if not has_spf:
                self.add_finding(Finding(
                    severity="MEDIUM",
                    module=self.MODULE_NAME,
                    vuln="Missing SPF Record",
                    endpoint=self.target,
                    description="No SPF record — email spoofing possible",
                    remediation="Add SPF record to prevent email spoofing",
                ))

            if not has_dmarc:
                self.add_finding(Finding(
                    severity="MEDIUM",
                    module=self.MODULE_NAME,
                    vuln="Missing DMARC Record",
                    endpoint=self.target,
                    description="No DMARC record — phishing risk",
                    remediation="Add DMARC record",
                ))

    async def _check_certificate_transparency(self, domain: str) -> None:
        """Check certificate transparency logs for subdomains"""
        try:
            resp = await self.get(
                f"https://crt.sh/?q=%.{domain}&output=json",
                headers={"Accept": "application/json"}
            )
            if not resp or resp.status_code != 200:
                return

            data = resp.json()
            subdomains = set()
            for cert in data[:100]:
                name = cert.get("name_value", "")
                for sub in name.split("\n"):
                    sub = sub.strip().lstrip("*.")
                    if sub.endswith(domain) and sub != domain:
                        subdomains.add(sub)

            if subdomains:
                self.add_finding(Finding(
                    severity="INFO",
                    module=self.MODULE_NAME,
                    vuln=f"Certificate Transparency: {len(subdomains)} Subdomains",
                    endpoint=self.target,
                    evidence="\n".join(list(subdomains)[:20]),
                    description=f"Found {len(subdomains)} subdomains via CT logs",
                    remediation="Review all subdomains for security issues",
                ))

        except Exception:
            pass

    async def _check_email_exposure(self, domain: str) -> None:
        """Check for exposed email addresses"""
        resp = await self.get(self.target)
        if not resp:
            return

        email_pattern = re.compile(
            r'\b[A-Za-z0-9._%+-]+@' + re.escape(domain) + r'\b'
        )
        emails = set(email_pattern.findall(resp.text))

        if emails:
            self.add_finding(Finding(
                severity="LOW",
                module=self.MODULE_NAME,
                vuln="Email Addresses Exposed",
                endpoint=self.target,
                evidence=", ".join(list(emails)[:10]),
                description=f"Found {len(emails)} email address(es) on the page",
                remediation="Remove email addresses from public pages or use contact forms",
            ))

    async def _check_shodan_style(self, domain: str) -> None:
        """Basic port/service fingerprinting (Shodan-style)"""
        try:
            ip = socket.gethostbyname(domain)
        except Exception:
            return

        self.add_finding(Finding(
            severity="INFO",
            module=self.MODULE_NAME,
            vuln="IP Address Resolved",
            endpoint=self.target,
            evidence=f"{domain} → {ip}",
            description=f"Domain resolves to {ip}",
            remediation="Ensure IP is not directly accessible if behind CDN",
        ))

        # Check common ports
        interesting_ports = {
            21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
            3306: "MySQL", 5432: "PostgreSQL", 6379: "Redis",
            27017: "MongoDB", 9200: "Elasticsearch",
        }

        open_ports = []
        for port, service in interesting_ports.items():
            try:
                conn = asyncio.open_connection(ip, port)
                reader, writer = await asyncio.wait_for(conn, timeout=1.0)
                writer.close()
                open_ports.append(f"{port}/{service}")
            except Exception:
                pass

        if open_ports:
            self.add_finding(Finding(
                severity="HIGH",
                module=self.MODULE_NAME,
                vuln="Sensitive Ports Open",
                endpoint=self.target,
                evidence=f"IP: {ip} | Open: {', '.join(open_ports)}",
                description=f"Sensitive services exposed on {ip}",
                remediation="Restrict access to database/service ports via firewall",
            ))

    async def _check_pastebin_exposure(self, domain: str) -> None:
        """Check for domain mentions in paste sites"""
        try:
            resp = await self.get(
                f"https://psbdmp.ws/api/v3/search/{domain}",
                headers={"User-Agent": "Vexor/1.0"}
            )
            if resp and resp.status_code == 200:
                data = resp.json()
                count = data.get("count", 0)
                if count > 0:
                    self.add_finding(Finding(
                        severity="MEDIUM",
                        module=self.MODULE_NAME,
                        vuln=f"Domain Found in Paste Sites ({count} results)",
                        endpoint=self.target,
                        evidence=f"Found {count} paste(s) mentioning {domain}",
                        description="Domain appears in paste sites — possible data leak",
                        remediation="Review paste sites for leaked credentials or data",
                    ))
        except Exception:
            pass

    async def _gather_social_media(self, domain: str) -> None:
        """Find social media presence"""
        company = domain.split(".")[0]
        platforms = {
            "GitHub": f"https://github.com/{company}",
            "Twitter/X": f"https://twitter.com/{company}",
            "LinkedIn": f"https://linkedin.com/company/{company}",
        }

        found = []
        for platform, url in platforms.items():
            resp = await self.get(url)
            if resp and resp.status_code == 200:
                found.append(f"{platform}: {url}")

        if found:
            self.add_finding(Finding(
                severity="INFO",
                module=self.MODULE_NAME,
                vuln="Social Media Presence Found",
                endpoint=self.target,
                evidence="\n".join(found),
                description="Social media accounts found for this organization",
                remediation="Monitor social media for sensitive information disclosure",
            ))

    async def _check_breach_data(self, domain: str) -> None:
        """Check HaveIBeenPwned for domain breaches"""
        try:
            resp = await self.get(
                f"https://haveibeenpwned.com/api/v3/breachesforaccount/{domain}",
                headers={
                    "User-Agent": "Vexor-Security-Scanner",
                    "hibp-api-key": "free-check",
                }
            )
            if resp and resp.status_code == 200:
                breaches = resp.json()
                if breaches:
                    names = [b.get("Name", "") for b in breaches[:5]]
                    self.add_finding(Finding(
                        severity="HIGH",
                        module=self.MODULE_NAME,
                        vuln=f"Domain Found in {len(breaches)} Data Breach(es)",
                        endpoint=self.target,
                        evidence=f"Breaches: {', '.join(names)}",
                        description=f"Domain appears in {len(breaches)} known data breaches",
                        remediation="Force password resets, enable MFA, notify affected users",
                    ))
        except Exception:
            pass
