"""
Vexor OSINT Module v4.0.0 — Vexor Intelligence Engine
6-Phase pipeline: Discovery → Live Check → Deep Recon → Secret Extraction → Threat Intel → AI Correlation
Direct modules (no key): DNS, CT, Email, IP Geo, Ports, SPF/DMARC,
  Tech Fingerprint, Wayback, GitHub, Social Media, WHOIS, ASN/BGP,
  SSL Chain, Subdomain Takeover, Passive Subdomains,
  Live Host Check, Assetfinder*, Findomain*, Hakrawler*, nmap*, Gf Patterns
Backend-proxied (keys on Render): Shodan, VirusTotal, OTX, URLScan, Chaos
AI Correlation: World-class OSINT intelligence via Vexor AI
* = optional, auto-detected
"""
import asyncio
import re
import socket
import ssl
import datetime
from urllib.parse import urlparse
from vexor.modules.base import BaseScanner, Finding


class Scanner(BaseScanner):
    """
    Vexor Intelligence Engine v4.0.0
    6-Phase pipeline — user provides target, engine does everything
    Phase 1: Discovery (DNS, CT, WHOIS, Chaos, Assetfinder, Findomain, Passive)
    Phase 2: Live Host Check (httpx-style async check on all discovered hosts)
    Phase 3: Deep Recon (ports, SSL, tech, Wayback, Hakrawler crawl)
    Phase 4: Secret Extraction (Gf patterns on all URLs)
    Phase 5: Threat Intel (Shodan, VT, OTX, URLScan via backend)
    Phase 6: AI Correlation (world-class intelligence analysis)
    """

    MODULE_NAME = "osint"
    MODULE_DESC = "Vexor Intelligence Engine — 6-Phase Pipeline"

    # Shared state across phases
    _all_subdomains: set
    _live_hosts: list
    _all_urls: list
    _secrets_found: list

    async def scan(self) -> list[Finding]:
        async with self:
            parsed = urlparse(self.target)
            domain = parsed.hostname or self.target
            if domain.startswith("www."):
                domain = domain[4:]

            # Init shared state
            self._all_subdomains = set()
            self._live_hosts = []
            self._all_urls = []
            self._secrets_found = []

            # ── Phase 1: Discovery (parallel) ────────────────────────────────
            await asyncio.gather(
                self._module_dns_records(domain),
                self._module_certificate_transparency(domain),
                self._module_email_harvest(domain),
                self._module_ip_geolocation(domain),
                self._module_spf_dmarc(domain),
                self._module_whois(domain),
                self._module_asn_bgp(domain),
                self._module_social_media(domain),
                self._module_passive_subdomains(domain),
                self._module_assetfinder(domain),
                self._module_findomain(domain),
                return_exceptions=True,
            )

            # ── Phase 2: Live Host Check ──────────────────────────────────────
            await self._phase_live_check(domain)

            # ── Phase 3: Deep Recon (on live hosts) ──────────────────────────
            await asyncio.gather(
                self._module_port_scan(domain),
                self._module_ssl_chain(domain),
                self._module_tech_fingerprint(),
                self._module_wayback(domain),
                self._module_github_search(domain),
                self._module_hakrawler(domain),
                self._module_subdomain_takeover(domain),
                return_exceptions=True,
            )

            # ── Phase 4: Secret Extraction (Gf patterns) ─────────────────────
            await self._phase_gf_patterns(domain)

            # ── Phase 5: Threat Intel (backend) ──────────────────────────────
            await self._module_backend_osint(domain)

            # ── Phase 6: AI Correlation ───────────────────────────────────────
            await self._phase_ai_correlation(domain)

        return self.findings

    # ─── Module 1: DNS Records ────────────────────────────────────────────────

    async def _module_dns_records(self, domain: str) -> None:
        """DNS records: A, AAAA, MX, NS, TXT, CNAME, SOA"""
        try:
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
                evidence_lines = []
                for rtype, records in dns_info.items():
                    evidence_lines.append(f"{rtype}: {', '.join(records[:3])}")

                self.add_finding(Finding(
                    severity="INFO",
                    module=self.MODULE_NAME,
                    vuln="DNS Records Enumerated",
                    endpoint=self.target,
                    evidence="\n".join(evidence_lines),
                    description=(
                        f"DNS records for {domain}: "
                        f"{', '.join(dns_info.keys())}"
                    ),
                    remediation="Review DNS records for sensitive information exposure.",
                ))

                # Check for zone transfer
                ns_records = dns_info.get("NS", [])
                for ns in ns_records[:2]:
                    try:
                        ns_clean = ns.rstrip(".")
                        zone = dns.zone.from_xfr(
                            dns.query.xfr(ns_clean, domain, timeout=3)
                        )
                        if zone:
                            self.add_finding(Finding(
                                severity="CRITICAL",
                                module=self.MODULE_NAME,
                                vuln="DNS Zone Transfer Allowed",
                                endpoint=self.target,
                                evidence=f"Zone transfer from {ns_clean} succeeded",
                                description=(
                                    "DNS zone transfer is allowed — full DNS "
                                    "enumeration possible."
                                ),
                                remediation=(
                                    "Restrict zone transfers to authorized "
                                    "secondary DNS servers only."
                                ),
                            ))
                    except Exception:
                        pass

        except Exception:
            pass

    # ─── Module 2: Certificate Transparency ──────────────────────────────────

    async def _module_certificate_transparency(self, domain: str) -> None:
        """Subdomain discovery via crt.sh Certificate Transparency logs"""
        try:
            resp = await self.get(
                f"https://crt.sh/?q=%.{domain}&output=json",
                headers={"Accept": "application/json"},
            )
            if not resp or resp.status_code != 200:
                return

            data = resp.json()
            subdomains = set()
            issuers = set()

            for cert in data[:200]:
                name = cert.get("name_value", "")
                issuer = cert.get("issuer_ca_id", "")
                if issuer:
                    issuers.add(str(issuer))
                for sub in name.split("\n"):
                    sub = sub.strip().lstrip("*.")
                    if sub.endswith(domain) and sub != domain:
                        subdomains.add(sub)

            if subdomains:
                self.add_finding(Finding(
                    severity="INFO",
                    module=self.MODULE_NAME,
                    vuln=f"CT Logs: {len(subdomains)} Subdomains Found",
                    endpoint=self.target,
                    evidence="\n".join(sorted(subdomains)[:30]),
                    description=(
                        f"Certificate Transparency logs reveal "
                        f"{len(subdomains)} subdomains for {domain}."
                    ),
                    remediation=(
                        "Review all subdomains for security issues. "
                        "Decommission unused subdomains."
                    ),
                ))
                # Feed into shared subdomain pool for live check
                self._all_subdomains.update(subdomains)

        except Exception:
            pass

    # ─── Module 3: Email Harvesting ───────────────────────────────────────────

    async def _module_email_harvest(self, domain: str) -> None:
        """Harvest email addresses from page source"""
        try:
            resp = await self.get(self.target)
            if not resp:
                return

            # Match emails for this domain and generic ones
            email_pattern = re.compile(
                r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b"
            )
            all_emails = set(email_pattern.findall(resp.text))

            # Also check linked pages (one level deep)
            try:
                from bs4 import BeautifulSoup
                soup = BeautifulSoup(resp.text, "lxml")
                for link in soup.find_all("a", href=True)[:20]:
                    href = link["href"]
                    if href.startswith("/") or domain in href:
                        from urllib.parse import urljoin
                        page_url = urljoin(self.target, href)
                        sub_resp = await self.get(page_url)
                        if sub_resp:
                            all_emails.update(email_pattern.findall(sub_resp.text))
            except Exception:
                pass

            domain_emails = {e for e in all_emails if domain in e}
            other_emails = all_emails - domain_emails

            if domain_emails:
                self.add_finding(Finding(
                    severity="LOW",
                    module=self.MODULE_NAME,
                    vuln=f"Email Addresses Exposed ({len(domain_emails)} found)",
                    endpoint=self.target,
                    evidence=", ".join(sorted(domain_emails)[:15]),
                    description=(
                        f"Found {len(domain_emails)} email address(es) "
                        f"for {domain} on the website."
                    ),
                    remediation=(
                        "Remove email addresses from public pages. "
                        "Use contact forms instead."
                    ),
                ))

            if other_emails:
                self.add_finding(Finding(
                    severity="INFO",
                    module=self.MODULE_NAME,
                    vuln=f"Third-Party Emails Found ({len(other_emails)})",
                    endpoint=self.target,
                    evidence=", ".join(sorted(other_emails)[:10]),
                    description="Third-party email addresses found on the page.",
                    remediation="Review for unintended information disclosure.",
                ))

        except Exception:
            pass

    # ─── Module 4: IP Geolocation ─────────────────────────────────────────────

    async def _module_ip_geolocation(self, domain: str) -> None:
        """IP geolocation via ip-api.com (free, no key required)"""
        try:
            ip = socket.gethostbyname(domain)
        except Exception:
            return

        try:
            resp = await self.get(
                f"http://ip-api.com/json/{ip}?fields=status,country,regionName,"
                f"city,isp,org,as,hosting,proxy,mobile",
                headers={"User-Agent": "Vexor/2.0 OSINT"},
            )
            if not resp or resp.status_code != 200:
                # Fallback: just report the IP
                self.add_finding(Finding(
                    severity="INFO",
                    module=self.MODULE_NAME,
                    vuln="IP Address Resolved",
                    endpoint=self.target,
                    evidence=f"{domain} → {ip}",
                    description=f"Domain resolves to {ip}",
                    remediation="Ensure IP is not directly accessible if behind CDN.",
                ))
                return

            data = resp.json()
            if data.get("status") != "success":
                return

            is_hosting = data.get("hosting", False)
            is_proxy = data.get("proxy", False)

            evidence = (
                f"IP: {ip}\n"
                f"Country: {data.get('country', 'N/A')}\n"
                f"Region: {data.get('regionName', 'N/A')}\n"
                f"City: {data.get('city', 'N/A')}\n"
                f"ISP: {data.get('isp', 'N/A')}\n"
                f"Org: {data.get('org', 'N/A')}\n"
                f"AS: {data.get('as', 'N/A')}\n"
                f"Hosting: {is_hosting} | Proxy/VPN: {is_proxy}"
            )

            severity = "INFO"
            note = ""
            if not is_hosting:
                severity = "MEDIUM"
                note = " — IP appears to be a real server (not CDN/hosting)"

            self.add_finding(Finding(
                severity=severity,
                module=self.MODULE_NAME,
                vuln=f"IP Geolocation{note}",
                endpoint=self.target,
                evidence=evidence,
                description=(
                    f"{domain} resolves to {ip} "
                    f"({data.get('city', '')}, {data.get('country', '')}). "
                    f"ISP: {data.get('isp', 'N/A')}."
                ),
                remediation=(
                    "If behind a CDN, ensure the origin IP is not exposed. "
                    "Use firewall rules to restrict direct IP access."
                ),
            ))

        except Exception:
            pass

    # ─── Module 5: Port Scan (Top 20 Ports) ──────────────────────────────────

    async def _module_port_scan(self, domain: str) -> None:
        """Async port scan of top 20 interesting ports"""
        try:
            ip = socket.gethostbyname(domain)
        except Exception:
            return

        TOP_PORTS = {
            21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
            53: "DNS", 80: "HTTP", 110: "POP3", 143: "IMAP",
            443: "HTTPS", 445: "SMB", 993: "IMAPS", 995: "POP3S",
            1433: "MSSQL", 3306: "MySQL", 3389: "RDP",
            5432: "PostgreSQL", 5900: "VNC", 6379: "Redis",
            8080: "HTTP-Alt", 27017: "MongoDB",
        }

        HIGH_RISK_PORTS = {21, 23, 1433, 3306, 3389, 5432, 5900, 6379, 27017, 445}

        open_ports = []

        async def check_port(port: int, service: str) -> None:
            try:
                conn = asyncio.open_connection(ip, port)
                reader, writer = await asyncio.wait_for(conn, timeout=1.5)
                writer.close()
                open_ports.append((port, service))
            except Exception:
                pass

        tasks = [check_port(p, s) for p, s in TOP_PORTS.items()]
        await asyncio.gather(*tasks, return_exceptions=True)

        if open_ports:
            risky = [(p, s) for p, s in open_ports if p in HIGH_RISK_PORTS]
            safe = [(p, s) for p, s in open_ports if p not in HIGH_RISK_PORTS]

            evidence = "\n".join(
                f"{'⚠ ' if p in HIGH_RISK_PORTS else '  '}{p}/{s}"
                for p, s in sorted(open_ports)
            )

            severity = "HIGH" if risky else "INFO"
            self.add_finding(Finding(
                severity=severity,
                module=self.MODULE_NAME,
                vuln=f"Open Ports: {len(open_ports)} found"
                     + (f" ({len(risky)} high-risk)" if risky else ""),
                endpoint=self.target,
                evidence=f"IP: {ip}\n{evidence}",
                description=(
                    f"Port scan of {ip}: {len(open_ports)} open ports. "
                    + (
                        f"High-risk services: "
                        f"{', '.join(s for _, s in risky)}"
                        if risky else "No high-risk ports exposed."
                    )
                ),
                remediation=(
                    "Restrict database/service ports via firewall. "
                    "Only expose necessary services to the internet."
                ),
            ))

    # ─── Module 6: SPF / DMARC ────────────────────────────────────────────────

    async def _module_spf_dmarc(self, domain: str) -> None:
        """Check SPF and DMARC email security records"""
        try:
            import dns.resolver

            # SPF check
            has_spf = False
            spf_record = ""
            try:
                answers = dns.resolver.resolve(domain, "TXT", lifetime=5)
                for r in answers:
                    txt = str(r).strip('"')
                    if txt.startswith("v=spf1"):
                        has_spf = True
                        spf_record = txt
                        break
            except Exception:
                pass

            # DMARC check
            has_dmarc = False
            dmarc_record = ""
            dmarc_policy = "none"
            try:
                answers = dns.resolver.resolve(f"_dmarc.{domain}", "TXT", lifetime=5)
                for r in answers:
                    txt = str(r).strip('"')
                    if txt.startswith("v=DMARC1"):
                        has_dmarc = True
                        dmarc_record = txt
                        # Extract policy
                        m = re.search(r"p=(\w+)", txt)
                        if m:
                            dmarc_policy = m.group(1)
                        break
            except Exception:
                pass

            # DKIM check (common selectors)
            has_dkim = False
            for selector in ["default", "google", "mail", "dkim", "k1"]:
                try:
                    dns.resolver.resolve(
                        f"{selector}._domainkey.{domain}", "TXT", lifetime=3
                    )
                    has_dkim = True
                    break
                except Exception:
                    pass

            evidence = (
                f"SPF: {'✓ ' + spf_record[:60] if has_spf else '✗ Missing'}\n"
                f"DMARC: {'✓ ' + dmarc_record[:60] if has_dmarc else '✗ Missing'}"
                + (f" (policy={dmarc_policy})" if has_dmarc else "")
                + f"\nDKIM: {'✓ Found' if has_dkim else '✗ Not found'}"
            )

            if not has_spf:
                self.add_finding(Finding(
                    severity="MEDIUM",
                    module=self.MODULE_NAME,
                    vuln="Missing SPF Record",
                    endpoint=self.target,
                    evidence=evidence,
                    description=(
                        f"No SPF record for {domain}. "
                        "Email spoofing is possible."
                    ),
                    remediation=(
                        "Add SPF record: "
                        "v=spf1 include:_spf.google.com ~all"
                    ),
                ))

            if not has_dmarc:
                self.add_finding(Finding(
                    severity="MEDIUM",
                    module=self.MODULE_NAME,
                    vuln="Missing DMARC Record",
                    endpoint=self.target,
                    evidence=evidence,
                    description=(
                        f"No DMARC record for {domain}. "
                        "Phishing using this domain is easier."
                    ),
                    remediation=(
                        "Add DMARC record: "
                        "v=DMARC1; p=quarantine; rua=mailto:dmarc@domain.com"
                    ),
                ))
            elif dmarc_policy == "none":
                self.add_finding(Finding(
                    severity="LOW",
                    module=self.MODULE_NAME,
                    vuln="DMARC Policy Set to 'none' (Monitor Only)",
                    endpoint=self.target,
                    evidence=dmarc_record,
                    description=(
                        "DMARC exists but policy is 'none' — "
                        "no enforcement, only monitoring."
                    ),
                    remediation="Upgrade DMARC policy to 'quarantine' or 'reject'.",
                ))

            if has_spf and has_dmarc and dmarc_policy != "none":
                self.add_finding(Finding(
                    severity="INFO",
                    module=self.MODULE_NAME,
                    vuln="Email Security: SPF + DMARC Configured",
                    endpoint=self.target,
                    evidence=evidence,
                    description=f"Good email security posture for {domain}.",
                    remediation="Continue monitoring DMARC reports.",
                ))

        except Exception:
            pass

    # ─── Module 7: Technology Fingerprinting ──────────────────────────────────

    async def _module_tech_fingerprint(self) -> None:
        """Fingerprint technology stack from HTTP headers and page content"""
        try:
            resp = await self.get(self.target)
            if not resp:
                return

            tech_found = {}

            # From response headers
            headers = dict(resp.headers)
            server = headers.get("server", headers.get("Server", ""))
            powered_by = headers.get("x-powered-by", headers.get("X-Powered-By", ""))
            via = headers.get("via", "")
            cf_ray = headers.get("cf-ray", "")
            x_wp = headers.get("x-wp-total", "")

            if server:
                tech_found["Web Server"] = server
            if powered_by:
                tech_found["Backend"] = powered_by
            if via:
                tech_found["Proxy/CDN"] = via
            if cf_ray:
                tech_found["CDN"] = "Cloudflare"
            if x_wp:
                tech_found["CMS"] = "WordPress"

            # Security headers audit
            security_headers = {
                "Strict-Transport-Security": "HSTS",
                "Content-Security-Policy": "CSP",
                "X-Frame-Options": "Clickjacking Protection",
                "X-Content-Type-Options": "MIME Sniffing Protection",
                "Referrer-Policy": "Referrer Policy",
                "Permissions-Policy": "Permissions Policy",
            }
            missing_sec = []
            present_sec = []
            for h, name in security_headers.items():
                if h.lower() in {k.lower() for k in headers}:
                    present_sec.append(name)
                else:
                    missing_sec.append(name)

            # From page content
            body = resp.text
            tech_patterns = {
                "WordPress": [r"wp-content", r"wp-includes", r"/wp-json/"],
                "Drupal": [r"Drupal\.settings", r"/sites/default/files/"],
                "Joomla": [r"/components/com_", r"Joomla!"],
                "React": [r"__REACT_DEVTOOLS", r"react-root", r"_reactFiber"],
                "Angular": [r"ng-version", r"angular\.min\.js"],
                "Vue.js": [r"__vue__", r"vue\.min\.js"],
                "jQuery": [r"jquery\.min\.js", r"jQuery v"],
                "Bootstrap": [r"bootstrap\.min\.css", r"bootstrap\.min\.js"],
                "Laravel": [r"laravel_session", r"XSRF-TOKEN"],
                "Django": [r"csrfmiddlewaretoken", r"django"],
                "Rails": [r"authenticity_token", r"rails"],
            }
            for tech, patterns in tech_patterns.items():
                for pattern in patterns:
                    if re.search(pattern, body, re.IGNORECASE):
                        tech_found[f"Framework/CMS"] = tech
                        break

            evidence_lines = [f"{k}: {v}" for k, v in tech_found.items()]
            if missing_sec:
                evidence_lines.append(
                    f"Missing security headers: {', '.join(missing_sec)}"
                )

            if tech_found:
                self.add_finding(Finding(
                    severity="INFO",
                    module=self.MODULE_NAME,
                    vuln=f"Technology Stack Identified",
                    endpoint=self.target,
                    evidence="\n".join(evidence_lines),
                    description=(
                        f"Technology fingerprint: "
                        f"{', '.join(tech_found.values())}"
                    ),
                    remediation=(
                        "Remove version information from headers. "
                        "Use generic server names."
                    ),
                ))

            if missing_sec:
                self.add_finding(Finding(
                    severity="LOW",
                    module=self.MODULE_NAME,
                    vuln=f"Missing Security Headers ({len(missing_sec)})",
                    endpoint=self.target,
                    evidence=f"Missing: {', '.join(missing_sec)}\nPresent: {', '.join(present_sec)}",
                    description=(
                        f"{len(missing_sec)} security headers are missing."
                    ),
                    remediation=(
                        "Add missing security headers: "
                        + ", ".join(missing_sec[:3])
                    ),
                ))

        except Exception:
            pass

    # ─── Module 8: Wayback Machine ────────────────────────────────────────────

    async def _module_wayback(self, domain: str) -> None:
        """Check Wayback Machine URL count and interesting historical URLs"""
        try:
            resp = await self.get(
                f"https://web.archive.org/cdx/search/cdx"
                f"?url=*.{domain}/*&output=json&limit=100"
                f"&fl=original,statuscode,timestamp&collapse=urlkey",
                headers={"User-Agent": "Vexor/2.0 OSINT"},
            )
            if not resp or resp.status_code != 200:
                return

            try:
                data = resp.json()
            except Exception:
                return

            if not data or len(data) < 2:
                return

            # First row is header
            urls = data[1:]
            total = len(urls)

            # Feed into shared URL pool for Gf patterns
            for row in urls:
                if len(row) >= 1 and row[0].startswith("http"):
                    self._all_urls.append(row[0])

            # Find interesting URLs
            interesting_patterns = [
                r"admin", r"backup", r"\.sql", r"\.env", r"config",
                r"password", r"secret", r"api/", r"\.git", r"debug",
                r"test", r"dev\.", r"staging\.",
            ]
            interesting_urls = []
            for row in urls:
                if len(row) >= 1:
                    url = row[0]
                    for pattern in interesting_patterns:
                        if re.search(pattern, url, re.IGNORECASE):
                            interesting_urls.append(url)
                            break

            evidence = f"Total archived URLs: {total}\n"
            if interesting_urls:
                evidence += "Interesting URLs:\n" + "\n".join(
                    interesting_urls[:10]
                )

            severity = "MEDIUM" if interesting_urls else "INFO"
            self.add_finding(Finding(
                severity=severity,
                module=self.MODULE_NAME,
                vuln=f"Wayback Machine: {total} URLs Archived"
                     + (f" ({len(interesting_urls)} interesting)" if interesting_urls else ""),
                endpoint=self.target,
                evidence=evidence,
                description=(
                    f"Wayback Machine has {total} archived URLs for {domain}. "
                    + (
                        f"Found {len(interesting_urls)} potentially sensitive URLs."
                        if interesting_urls else ""
                    )
                ),
                remediation=(
                    "Review archived URLs for sensitive data. "
                    "Use robots.txt to prevent archiving sensitive paths."
                ),
            ))

        except Exception:
            pass

    # ─── Module 9: GitHub Search ──────────────────────────────────────────────

    async def _module_github_search(self, domain: str) -> None:
        """Search GitHub for domain mentions (public API, no key needed)"""
        try:
            resp = await self.get(
                f"https://api.github.com/search/code?q={domain}&per_page=10",
                headers={
                    "User-Agent": "Vexor/2.0 OSINT",
                    "Accept": "application/vnd.github.v3+json",
                },
            )
            if not resp:
                return

            if resp.status_code == 200:
                data = resp.json()
                total = data.get("total_count", 0)
                items = data.get("items", [])

                if total > 0:
                    repos = list({
                        item.get("repository", {}).get("full_name", "")
                        for item in items
                        if item.get("repository")
                    })

                    self.add_finding(Finding(
                        severity="MEDIUM" if total > 5 else "LOW",
                        module=self.MODULE_NAME,
                        vuln=f"GitHub: {total} Code References Found",
                        endpoint=self.target,
                        evidence=(
                            f"Total results: {total}\n"
                            f"Repositories: {', '.join(repos[:5])}"
                        ),
                        description=(
                            f"Domain {domain} appears in {total} GitHub code files. "
                            "May contain credentials, API keys, or internal URLs."
                        ),
                        remediation=(
                            "Review GitHub results for leaked credentials. "
                            "Use GitHub secret scanning alerts."
                        ),
                    ))
            elif resp.status_code == 403:
                # Rate limited — still report
                self.add_finding(Finding(
                    severity="INFO",
                    module=self.MODULE_NAME,
                    vuln="GitHub Search Rate Limited",
                    endpoint=self.target,
                    evidence="GitHub API rate limit reached",
                    description="GitHub search was rate limited. Try again later.",
                    remediation="Use GitHub token for higher rate limits.",
                ))

        except Exception:
            pass

    # ─── Module 10: Social Media Presence ────────────────────────────────────

    async def _module_social_media(self, domain: str) -> None:
        """Check social media presence for the organization"""
        try:
            company = domain.split(".")[0]

            platforms = {
                "GitHub": f"https://github.com/{company}",
                "Twitter/X": f"https://twitter.com/{company}",
                "LinkedIn": f"https://linkedin.com/company/{company}",
                "Facebook": f"https://facebook.com/{company}",
                "Instagram": f"https://instagram.com/{company}",
                "YouTube": f"https://youtube.com/@{company}",
            }

            found = []
            not_found = []

            for platform, url in platforms.items():
                try:
                    resp = await self.get(url)
                    if resp and resp.status_code == 200:
                        found.append(f"{platform}: {url}")
                    else:
                        not_found.append(platform)
                except Exception:
                    not_found.append(platform)

            if found:
                self.add_finding(Finding(
                    severity="INFO",
                    module=self.MODULE_NAME,
                    vuln=f"Social Media: {len(found)} Profiles Found",
                    endpoint=self.target,
                    evidence="\n".join(found),
                    description=(
                        f"Found {len(found)} social media profiles for '{company}'."
                    ),
                    remediation=(
                        "Monitor social media for sensitive information disclosure. "
                        "Ensure profiles are managed by authorized personnel."
                    ),
                ))

        except Exception:
            pass

    # ─── Module 11: WHOIS ────────────────────────────────────────────────────

    async def _module_whois(self, domain: str) -> None:
        """WHOIS lookup — registrar, dates, registrant info"""
        try:
            import whois as pythonwhois
            loop = asyncio.get_event_loop()
            w = await loop.run_in_executor(None, pythonwhois.whois, domain)
            if not w:
                return

            registrar    = w.registrar or "N/A"
            creation     = w.creation_date
            expiration   = w.expiration_date
            name_servers = w.name_servers or []
            status       = w.status or []
            org          = w.org or w.registrant_country or "N/A"

            # Normalize dates (can be list or single)
            def _fmt_date(d):
                if isinstance(d, list):
                    d = d[0]
                if isinstance(d, datetime.datetime):
                    return d.strftime("%Y-%m-%d")
                return str(d) if d else "N/A"

            creation_str   = _fmt_date(creation)
            expiration_str = _fmt_date(expiration)

            # Check if expiring soon (within 60 days)
            expiry_warning = ""
            try:
                exp = expiration if not isinstance(expiration, list) else expiration[0]
                if isinstance(exp, datetime.datetime):
                    days_left = (exp - datetime.datetime.utcnow()).days
                    if days_left < 60:
                        expiry_warning = f" ⚠ EXPIRES IN {days_left} DAYS"
            except Exception:
                pass

            evidence = (
                f"Registrar: {registrar}\n"
                f"Created: {creation_str}\n"
                f"Expires: {expiration_str}{expiry_warning}\n"
                f"Org: {org}\n"
                f"Name Servers: {', '.join(list(name_servers)[:4])}\n"
                f"Status: {', '.join(list(status)[:3]) if status else 'N/A'}"
            )

            severity = "MEDIUM" if expiry_warning else "INFO"
            self.add_finding(Finding(
                severity=severity,
                module=self.MODULE_NAME,
                vuln="WHOIS: Domain Registration Info" + expiry_warning,
                endpoint=self.target,
                evidence=evidence,
                description=(
                    f"WHOIS for {domain}: Registrar={registrar}, "
                    f"Created={creation_str}, Expires={expiration_str}."
                    + (f" Domain expiring soon!" if expiry_warning else "")
                ),
                remediation=(
                    "Ensure domain registration is kept up to date. "
                    "Enable auto-renew to prevent domain expiry attacks."
                    if expiry_warning else
                    "Monitor WHOIS for unauthorized registrar transfers."
                ),
            ))

        except ImportError:
            self.add_finding(Finding(
                severity="INFO",
                module=self.MODULE_NAME,
                vuln="WHOIS: Module Not Installed",
                endpoint=self.target,
                evidence="pip install python-whois",
                description="python-whois not installed — WHOIS lookup skipped.",
                remediation="Run: pip install python-whois",
            ))
        except Exception:
            pass

    # ─── Module 12: ASN / BGP ─────────────────────────────────────────────────

    async def _module_asn_bgp(self, domain: str) -> None:
        """ASN and BGP info via BGPView API (free, no key required)"""
        try:
            ip = socket.gethostbyname(domain)
        except Exception:
            return

        try:
            resp = await self.get(
                f"https://api.bgpview.io/ip/{ip}",
                headers={"User-Agent": "Vexor/3.0 OSINT"},
            )
            if not resp or resp.status_code != 200:
                return

            data = resp.json().get("data", {})
            prefixes = data.get("prefixes", [])
            if not prefixes:
                return

            prefix_info = prefixes[0]
            asn_info    = prefix_info.get("asn", {})
            asn         = asn_info.get("asn", "N/A")
            asn_name    = asn_info.get("name", "N/A")
            asn_desc    = asn_info.get("description", "N/A")
            prefix      = prefix_info.get("prefix", "N/A")
            country     = prefix_info.get("country_code", "N/A")

            # Get all IP ranges for this ASN
            asn_resp = await self.get(
                f"https://api.bgpview.io/asn/{asn}/prefixes",
                headers={"User-Agent": "Vexor/3.0 OSINT"},
            )
            ip_ranges = []
            if asn_resp and asn_resp.status_code == 200:
                asn_data = asn_resp.json().get("data", {})
                v4 = asn_data.get("ipv4_prefixes", [])
                ip_ranges = [p.get("prefix", "") for p in v4[:10] if p.get("prefix")]

            evidence = (
                f"IP: {ip}\n"
                f"ASN: AS{asn} ({asn_name})\n"
                f"Description: {asn_desc}\n"
                f"Prefix: {prefix}\n"
                f"Country: {country}"
            )
            if ip_ranges:
                evidence += f"\nASN IP Ranges ({len(ip_ranges)}): {', '.join(ip_ranges[:5])}"

            self.add_finding(Finding(
                severity="INFO",
                module=self.MODULE_NAME,
                vuln=f"ASN/BGP: AS{asn} — {asn_name}",
                endpoint=self.target,
                evidence=evidence,
                description=(
                    f"{domain} ({ip}) belongs to AS{asn} ({asn_name}). "
                    f"Network prefix: {prefix}, Country: {country}."
                ),
                remediation=(
                    "Use ASN data to identify the full IP range owned by the target. "
                    "Useful for scope expansion in authorized engagements."
                ),
            ))

        except Exception:
            pass

    # ─── Module 13: SSL Certificate Chain ────────────────────────────────────

    async def _module_ssl_chain(self, domain: str) -> None:
        """SSL certificate chain analysis — validity, SANs, issuer, expiry"""
        try:
            loop = asyncio.get_event_loop()

            def _get_cert():
                ctx = ssl.create_default_context()
                with ctx.wrap_socket(
                    __import__("socket").socket(), server_hostname=domain
                ) as s:
                    s.settimeout(5)
                    s.connect((domain, 443))
                    return s.getpeercert()

            cert = await loop.run_in_executor(None, _get_cert)
            if not cert:
                return

            subject   = dict(x[0] for x in cert.get("subject", []))
            issuer    = dict(x[0] for x in cert.get("issuer", []))
            not_after = cert.get("notAfter", "")
            not_before = cert.get("notBefore", "")
            san_list  = [
                v for t, v in cert.get("subjectAltName", []) if t == "DNS"
            ]

            # Parse expiry
            expiry_warning = ""
            days_left = None
            try:
                exp = datetime.datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                days_left = (exp - datetime.datetime.utcnow()).days
                if days_left < 0:
                    expiry_warning = " ⚠ CERTIFICATE EXPIRED"
                elif days_left < 30:
                    expiry_warning = f" ⚠ EXPIRES IN {days_left} DAYS"
            except Exception:
                pass

            cn       = subject.get("commonName", "N/A")
            issuer_o = issuer.get("organizationName", "N/A")

            evidence = (
                f"Subject CN: {cn}\n"
                f"Issuer: {issuer_o}\n"
                f"Valid From: {not_before}\n"
                f"Valid Until: {not_after}{expiry_warning}\n"
                f"Days Remaining: {days_left if days_left is not None else 'N/A'}\n"
                f"SANs ({len(san_list)}): {', '.join(san_list[:10])}"
            )

            severity = "HIGH" if "EXPIRED" in expiry_warning else (
                "MEDIUM" if expiry_warning else "INFO"
            )

            self.add_finding(Finding(
                severity=severity,
                module=self.MODULE_NAME,
                vuln=f"SSL Certificate{expiry_warning}" if expiry_warning
                     else f"SSL Certificate: Valid ({days_left} days left)",
                endpoint=self.target,
                evidence=evidence,
                description=(
                    f"SSL cert for {domain}: CN={cn}, Issuer={issuer_o}. "
                    f"Expires: {not_after}."
                    + (f" {expiry_warning}" if expiry_warning else "")
                ),
                remediation=(
                    "Renew SSL certificate immediately." if expiry_warning
                    else "Monitor certificate expiry. Enable auto-renewal."
                ),
            ))

            # SANs reveal additional domains/subdomains
            if len(san_list) > 1:
                interesting_sans = [
                    s for s in san_list
                    if not s.startswith("*") and s != domain
                ][:10]
                if interesting_sans:
                    self.add_finding(Finding(
                        severity="INFO",
                        module=self.MODULE_NAME,
                        vuln=f"SSL SANs: {len(san_list)} Domains in Certificate",
                        endpoint=self.target,
                        evidence="\n".join(san_list[:20]),
                        description=(
                            f"SSL certificate covers {len(san_list)} domains. "
                            f"Reveals additional infrastructure."
                        ),
                        remediation="Review SANs for unintended domain exposure.",
                    ))

        except Exception:
            pass

    # ─── Module 14: Subdomain Takeover Detection ──────────────────────────────

    async def _module_subdomain_takeover(self, domain: str) -> None:
        """
        Check for subdomain takeover via dangling CNAME records.
        Detects CNAMEs pointing to unclaimed cloud/SaaS services.
        """
        TAKEOVER_SIGNATURES = {
            "github.io":              "GitHub Pages",
            "amazonaws.com":          "AWS S3",
            "s3.amazonaws.com":       "AWS S3",
            "cloudfront.net":         "AWS CloudFront",
            "azurewebsites.net":      "Azure Web Apps",
            "azure.com":              "Azure",
            "herokuapp.com":          "Heroku",
            "herokudns.com":          "Heroku",
            "shopify.com":            "Shopify",
            "shopifypreview.com":     "Shopify",
            "fastly.net":             "Fastly",
            "pantheonsite.io":        "Pantheon",
            "wpengine.com":           "WP Engine",
            "ghost.io":               "Ghost",
            "surge.sh":               "Surge.sh",
            "netlify.app":            "Netlify",
            "netlify.com":            "Netlify",
            "vercel.app":             "Vercel",
            "pages.dev":              "Cloudflare Pages",
            "readthedocs.io":         "ReadTheDocs",
            "zendesk.com":            "Zendesk",
            "freshdesk.com":          "Freshdesk",
            "helpscoutdocs.com":      "HelpScout",
            "bitbucket.io":           "Bitbucket",
            "webflow.io":             "Webflow",
            "squarespace.com":        "Squarespace",
            "tumblr.com":             "Tumblr",
        }

        try:
            import dns.resolver

            # Get subdomains from CT logs first
            resp = await self.get(
                f"https://crt.sh/?q=%.{domain}&output=json",
                headers={"Accept": "application/json"},
            )
            subdomains = set()
            if resp and resp.status_code == 200:
                try:
                    for cert in resp.json()[:100]:
                        for sub in cert.get("name_value", "").split("\n"):
                            sub = sub.strip().lstrip("*.")
                            if sub.endswith(domain) and sub != domain:
                                subdomains.add(sub)
                except Exception:
                    pass

            if not subdomains:
                return

            vulnerable = []

            async def check_takeover(sub: str) -> None:
                try:
                    loop = asyncio.get_event_loop()
                    answers = await loop.run_in_executor(
                        None,
                        lambda: dns.resolver.resolve(sub, "CNAME", lifetime=3)
                    )
                    for rdata in answers:
                        cname_target = str(rdata.target).rstrip(".").lower()
                        for signature, service in TAKEOVER_SIGNATURES.items():
                            if signature in cname_target:
                                # Check if the CNAME target actually resolves
                                try:
                                    await loop.run_in_executor(
                                        None,
                                        lambda: socket.gethostbyname(cname_target)
                                    )
                                except socket.gaierror:
                                    # CNAME target doesn't resolve = potential takeover
                                    vulnerable.append(
                                        (sub, cname_target, service)
                                    )
                except Exception:
                    pass

            tasks = [check_takeover(sub) for sub in list(subdomains)[:30]]
            await asyncio.gather(*tasks, return_exceptions=True)

            if vulnerable:
                for sub, cname, service in vulnerable:
                    self.add_finding(Finding(
                        severity="CRITICAL",
                        module=self.MODULE_NAME,
                        vuln=f"Subdomain Takeover: {sub} → {service}",
                        endpoint=f"https://{sub}",
                        evidence=(
                            f"Subdomain: {sub}\n"
                            f"CNAME: {cname}\n"
                            f"Service: {service}\n"
                            f"Status: CNAME target does not resolve — TAKEOVER POSSIBLE"
                        ),
                        description=(
                            f"{sub} has a dangling CNAME pointing to {cname} ({service}). "
                            f"This subdomain may be claimable by an attacker."
                        ),
                        remediation=(
                            f"Remove the CNAME record for {sub} or claim the "
                            f"{service} resource it points to immediately."
                        ),
                    ))

        except Exception:
            pass

    # ─── Module 15: Passive Subdomains (crt.sh extended) ─────────────────────

    async def _module_passive_subdomains(self, domain: str) -> None:
        """
        Extended passive subdomain discovery combining crt.sh + HackerTarget.
        Complements Module 2 (CT logs) with additional sources.
        """
        try:
            all_subs = set()

            # Source 1: HackerTarget (free, no key)
            ht_resp = await self.get(
                f"https://api.hackertarget.com/hostsearch/?q={domain}",
                headers={"User-Agent": "Vexor/3.0 OSINT"},
            )
            if ht_resp and ht_resp.status_code == 200:
                for line in ht_resp.text.splitlines():
                    parts = line.split(",")
                    if parts and parts[0].endswith(f".{domain}"):
                        all_subs.add(parts[0].strip())

            # Source 2: RapidDNS (free, no key)
            rd_resp = await self.get(
                f"https://rapiddns.io/subdomain/{domain}?full=1",
                headers={"User-Agent": "Mozilla/5.0"},
            )
            if rd_resp and rd_resp.status_code == 200:
                found = re.findall(
                    rf'[\w\-\.]+\.{re.escape(domain)}',
                    rd_resp.text
                )
                for s in found:
                    if s.endswith(f".{domain}") and s != domain:
                        all_subs.add(s.lower())

            if not all_subs:
                return

            # Filter noise
            all_subs = {
                s for s in all_subs
                if s.endswith(f".{domain}") and len(s) < 100
            }

            if all_subs:
                interesting_patterns = [
                    "admin", "dev", "staging", "test", "api", "internal",
                    "jenkins", "gitlab", "kibana", "grafana", "db", "vpn",
                    "backup", "old", "legacy", "beta", "preprod", "uat",
                    "mail", "smtp", "ftp", "ssh", "remote",
                ]
                interesting = [
                    s for s in all_subs
                    if any(p in s.lower() for p in interesting_patterns)
                ]

                # Feed into shared pool
                self._all_subdomains.update(all_subs)

                severity = "MEDIUM" if interesting else "INFO"
                evidence = f"Total: {len(all_subs)}\n"
                evidence += "Subdomains:\n" + "\n".join(sorted(all_subs)[:25])
                if interesting:
                    evidence += f"\n\nInteresting:\n" + "\n".join(interesting[:10])

                self.add_finding(Finding(
                    severity=severity,
                    module=self.MODULE_NAME,
                    vuln=f"Passive Recon: {len(all_subs)} Subdomains (HackerTarget+RapidDNS)"
                         + (f" — {len(interesting)} interesting" if interesting else ""),
                    endpoint=self.target,
                    evidence=evidence,
                    description=(
                        f"Passive subdomain discovery found {len(all_subs)} subdomains "
                        f"for {domain} via HackerTarget and RapidDNS."
                        + (f" Interesting: {', '.join(interesting[:5])}" if interesting else "")
                    ),
                    remediation=(
                        "Review all subdomains for security issues. "
                        "Decommission unused subdomains. "
                        "Check for subdomain takeover vulnerabilities."
                    ),
                ))

        except Exception:
            pass

    # ─── Module 16–20: Backend-Proxied (Shodan, VT, OTX, URLScan, Chaos) ─────

    async def _module_backend_osint(self, domain: str) -> None:
        """
        Call Vexor backend for API-key-dependent modules.
        Backend holds Shodan, VirusTotal, OTX, URLScan, Chaos keys on Render.
        Silently skips if offline or not authenticated.
        """
        try:
            from vexor.ai.client import AIClient
            client = AIClient()

            # Check which modules are available
            status = await client.osint_status()
            if not status:
                # Backend unreachable or not logged in — skip silently
                return

            available = [k for k, v in status.items() if v]
            unavailable = [k for k, v in status.items() if not v]

            if unavailable:
                self.add_finding(Finding(
                    severity="INFO",
                    module=self.MODULE_NAME,
                    vuln=f"Backend OSINT: {len(unavailable)} modules not configured",
                    endpoint=self.target,
                    evidence=f"Not configured: {', '.join(unavailable)}\nAvailable: {', '.join(available) or 'none'}",
                    description=(
                        f"Some backend OSINT modules are not configured on the server. "
                        f"Add API keys to Render environment variables."
                    ),
                    remediation=(
                        "Add missing API keys to Render dashboard: "
                        + ", ".join(f"{k.upper()}_API_KEY" for k in unavailable)
                    ),
                ))

            if not available:
                return

            # Run available backend modules
            findings = await client.osint_scan(target=domain, modules=available)

            for f in findings:
                if not f.get("available", True):
                    continue  # Skip "not configured" notices already shown above
                self.add_finding(Finding(
                    severity=f.get("severity", "INFO"),
                    module=f"osint/{f.get('module', 'backend')}",
                    vuln=f.get("vuln", ""),
                    endpoint=self.target,
                    evidence=f.get("evidence", ""),
                    description=f.get("description", ""),
                    remediation="Review finding and apply appropriate remediation.",
                ))

        except Exception:
            pass

    # ─── Phase 2: Live Host Check ─────────────────────────────────────────────

    async def _phase_live_check(self, domain: str) -> None:
        """
        Check which discovered subdomains are alive.
        Uses async httpx — no external tool needed.
        Populates self._live_hosts for Phase 3.
        """
        try:
            # Collect all subdomains discovered so far
            candidates = set(self._all_subdomains)
            candidates.add(domain)
            candidates.add(f"www.{domain}")

            if not candidates:
                return

            live = []
            semaphore = asyncio.Semaphore(30)

            async def check_host(host: str) -> None:
                async with semaphore:
                    for scheme in ["https", "http"]:
                        try:
                            resp = await self.get(
                                f"{scheme}://{host}",
                                headers={"User-Agent": "Mozilla/5.0 Vexor/4.0"},
                            )
                            if resp and resp.status_code < 500:
                                title = ""
                                try:
                                    m = re.search(
                                        r"<title[^>]*>(.*?)</title>",
                                        resp.text[:2000],
                                        re.IGNORECASE | re.DOTALL,
                                    )
                                    if m:
                                        title = m.group(1).strip()[:60]
                                except Exception:
                                    pass
                                live.append({
                                    "host": host,
                                    "url": f"{scheme}://{host}",
                                    "status": resp.status_code,
                                    "title": title,
                                    "server": resp.headers.get("server", ""),
                                })
                                return  # https worked, skip http
                        except Exception:
                            pass

            tasks = [check_host(h) for h in list(candidates)[:50]]
            await asyncio.gather(*tasks, return_exceptions=True)

            self._live_hosts = live

            if live:
                evidence_lines = [
                    f"{h['status']} {h['url']} [{h['title'] or h['server'] or '-'}]"
                    for h in live[:20]
                ]
                self.add_finding(Finding(
                    severity="INFO",
                    module=self.MODULE_NAME,
                    vuln=f"Live Hosts: {len(live)} Responding",
                    endpoint=self.target,
                    evidence="\n".join(evidence_lines),
                    description=(
                        f"Live host check: {len(live)}/{len(candidates)} hosts responding. "
                        f"Attack surface confirmed."
                    ),
                    remediation=(
                        "Review all live hosts for security issues. "
                        "Decommission unused hosts."
                    ),
                ))

                # Flag interesting status codes
                interesting = [h for h in live if h["status"] in [401, 403, 200] and
                               any(k in h["url"].lower() for k in
                                   ["admin", "dev", "staging", "api", "internal", "jenkins"])]
                for h in interesting[:5]:
                    self.add_finding(Finding(
                        severity="MEDIUM",
                        module=self.MODULE_NAME,
                        vuln=f"Live Interesting Host: {h['url']} [{h['status']}]",
                        endpoint=h["url"],
                        evidence=f"Status: {h['status']}\nTitle: {h['title']}\nServer: {h['server']}",
                        description=f"Potentially sensitive live host: {h['url']}",
                        remediation="Investigate this host for unauthorized access.",
                    ))

        except Exception:
            pass

    # ─── Module: Assetfinder (Go binary, optional) ────────────────────────────

    async def _module_assetfinder(self, domain: str) -> None:
        """Passive subdomain discovery via Assetfinder (JS/CDN mining)"""
        try:
            from vexor.core.tool_detector import ToolDetector, run_tool
            if not ToolDetector.available("assetfinder"):
                return

            stdout, _ = await run_tool(
                ["assetfinder", "--subs-only", domain],
                timeout=60,
            )
            if not stdout:
                return

            subs = set()
            for line in stdout.splitlines():
                line = line.strip().lower()
                if line.endswith(f".{domain}") or line == domain:
                    subs.add(line)

            if subs:
                self._all_subdomains.update(subs)
                self.add_finding(Finding(
                    severity="INFO",
                    module=self.MODULE_NAME,
                    vuln=f"Assetfinder: {len(subs)} Subdomains (Passive JS/CDN)",
                    endpoint=self.target,
                    evidence="\n".join(sorted(subs)[:30]),
                    description=(
                        f"Assetfinder passive mining found {len(subs)} subdomains "
                        f"for {domain} via JS files, CDN records, and passive sources."
                    ),
                    remediation="Review all discovered subdomains for security issues.",
                ))

        except Exception:
            pass

    # ─── Module: Findomain (binary, optional) ────────────────────────────────

    async def _module_findomain(self, domain: str) -> None:
        """Subdomain discovery via Findomain (30+ passive sources)"""
        try:
            from vexor.core.tool_detector import ToolDetector, run_tool
            if not ToolDetector.available("findomain"):
                return

            stdout, _ = await run_tool(
                ["findomain", "--target", domain, "--quiet"],
                timeout=90,
            )
            if not stdout:
                return

            subs = set()
            for line in stdout.splitlines():
                line = line.strip().lower()
                if line.endswith(f".{domain}") or line == domain:
                    subs.add(line)

            if subs:
                self._all_subdomains.update(subs)
                self.add_finding(Finding(
                    severity="INFO",
                    module=self.MODULE_NAME,
                    vuln=f"Findomain: {len(subs)} Subdomains (30+ Sources)",
                    endpoint=self.target,
                    evidence="\n".join(sorted(subs)[:30]),
                    description=(
                        f"Findomain found {len(subs)} subdomains for {domain} "
                        f"via 30+ passive sources (VT, C99, FOFA, etc.)."
                    ),
                    remediation="Review all discovered subdomains for security issues.",
                ))

        except Exception:
            pass

    # ─── Module: Hakrawler (Go binary, optional) ──────────────────────────────

    async def _module_hakrawler(self, domain: str) -> None:
        """
        Live site crawling via Hakrawler.
        Discovers endpoints, forms, JS files, hidden paths.
        Feeds URLs into Gf pattern extraction.
        """
        try:
            from vexor.core.tool_detector import ToolDetector, run_tool
            if not ToolDetector.available("hakrawler"):
                return

            # Crawl main domain
            stdout, _ = await run_tool(
                ["hakrawler", "-url", f"https://{domain}", "-depth", "3",
                 "-plain", "-insecure"],
                timeout=120,
            )
            if not stdout:
                return

            urls = []
            for line in stdout.splitlines():
                line = line.strip()
                if line.startswith("http") and domain in line:
                    urls.append(line)

            if not urls:
                return

            # Add to shared URL pool for Gf patterns
            self._all_urls.extend(urls)

            # Categorize URLs
            interesting_patterns = [
                r"/admin", r"/api/", r"/v\d+/", r"\.php", r"\.asp",
                r"/login", r"/auth", r"/upload", r"/config", r"/backup",
                r"\.json", r"\.xml", r"\.env", r"\.git",
            ]
            interesting_urls = [
                u for u in urls
                if any(re.search(p, u, re.IGNORECASE) for p in interesting_patterns)
            ]

            self.add_finding(Finding(
                severity="MEDIUM" if interesting_urls else "INFO",
                module=self.MODULE_NAME,
                vuln=f"Hakrawler: {len(urls)} Endpoints Discovered"
                     + (f" ({len(interesting_urls)} interesting)" if interesting_urls else ""),
                endpoint=self.target,
                evidence=(
                    f"Total URLs: {len(urls)}\n"
                    + ("Interesting:\n" + "\n".join(interesting_urls[:15])
                       if interesting_urls else
                       "Sample:\n" + "\n".join(urls[:10]))
                ),
                description=(
                    f"Hakrawler crawled {domain} and found {len(urls)} endpoints. "
                    + (f"{len(interesting_urls)} potentially sensitive paths discovered."
                       if interesting_urls else "")
                ),
                remediation=(
                    "Review all discovered endpoints. "
                    "Ensure sensitive paths require authentication."
                ),
            ))

        except Exception:
            pass

    # ─── Phase 4: Gf Patterns (Secret Extraction) ────────────────────────────

    async def _phase_gf_patterns(self, domain: str) -> None:
        """
        Apply Gf-style regex patterns to all collected URLs.
        Extracts: API keys, JWT tokens, SQLi params, XSS params,
        open redirects, SSRF params, sensitive file extensions.
        Pure Python — no binary needed.
        """
        try:
            # Collect all URLs: Wayback + Hakrawler + live hosts
            all_urls = list(set(self._all_urls))

            # Also add Wayback URLs if not already collected
            if not all_urls:
                return

            GF_PATTERNS = {
                "api-keys": [
                    r"api[_-]?key[=:]['\"]?[\w\-]{16,}",
                    r"apikey[=:]['\"]?[\w\-]{16,}",
                    r"access[_-]?token[=:]['\"]?[\w\-]{16,}",
                    r"secret[_-]?key[=:]['\"]?[\w\-]{16,}",
                    r"client[_-]?secret[=:]['\"]?[\w\-]{16,}",
                    r"auth[_-]?token[=:]['\"]?[\w\-]{16,}",
                    r"AKIA[0-9A-Z]{16}",          # AWS Access Key
                    r"sk-[a-zA-Z0-9]{32,}",        # OpenAI key
                    r"ghp_[a-zA-Z0-9]{36}",        # GitHub PAT
                    r"glpat-[a-zA-Z0-9\-]{20}",    # GitLab PAT
                ],
                "jwt": [
                    r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}",
                ],
                "sqli-params": [
                    r"[?&]id=\d+",
                    r"[?&]page=\d+",
                    r"[?&]cat=\d+",
                    r"[?&]item=\d+",
                    r"[?&]user=\d+",
                    r"[?&]order=\d+",
                    r"[?&]num=\d+",
                ],
                "xss-params": [
                    r"[?&]q=",
                    r"[?&]search=",
                    r"[?&]query=",
                    r"[?&]s=",
                    r"[?&]keyword=",
                    r"[?&]term=",
                    r"[?&]name=",
                    r"[?&]input=",
                ],
                "open-redirect": [
                    r"[?&]url=http",
                    r"[?&]redirect=http",
                    r"[?&]next=http",
                    r"[?&]return=http",
                    r"[?&]goto=http",
                    r"[?&]dest=http",
                    r"[?&]destination=http",
                    r"[?&]redir=http",
                ],
                "ssrf-params": [
                    r"[?&]url=",
                    r"[?&]uri=",
                    r"[?&]path=",
                    r"[?&]host=",
                    r"[?&]endpoint=",
                    r"[?&]proxy=",
                    r"[?&]fetch=",
                    r"[?&]load=",
                ],
                "sensitive-files": [
                    r"\.env$",
                    r"\.git/",
                    r"\.sql$",
                    r"backup\.",
                    r"config\.",
                    r"database\.",
                    r"passwd$",
                    r"shadow$",
                    r"id_rsa$",
                    r"\.pem$",
                    r"\.key$",
                    r"wp-config\.php",
                    r"settings\.py$",
                    r"application\.properties$",
                ],
            }

            pattern_hits = {}
            for category, patterns in GF_PATTERNS.items():
                hits = []
                for url in all_urls:
                    for pattern in patterns:
                        if re.search(pattern, url, re.IGNORECASE):
                            hits.append(url)
                            break
                if hits:
                    pattern_hits[category] = hits

            if not pattern_hits:
                return

            # Report each category
            severity_map = {
                "api-keys":       "CRITICAL",
                "jwt":            "HIGH",
                "sensitive-files": "HIGH",
                "open-redirect":  "MEDIUM",
                "ssrf-params":    "MEDIUM",
                "sqli-params":    "MEDIUM",
                "xss-params":     "LOW",
            }

            for category, hits in pattern_hits.items():
                sev = severity_map.get(category, "MEDIUM")
                self._secrets_found.extend(hits[:10])

                self.add_finding(Finding(
                    severity=sev,
                    module=self.MODULE_NAME,
                    vuln=f"Gf Pattern [{category}]: {len(hits)} URLs",
                    endpoint=self.target,
                    evidence="\n".join(hits[:15]),
                    description=(
                        f"Gf pattern '{category}' matched {len(hits)} URLs. "
                        f"These may contain exploitable parameters or sensitive data."
                    ),
                    remediation=(
                        f"Review all '{category}' URLs. "
                        "Test each for the corresponding vulnerability type."
                    ),
                ))

            # Summary finding
            total_hits = sum(len(v) for v in pattern_hits.items())
            self.add_finding(Finding(
                severity="HIGH" if any(k in pattern_hits for k in ["api-keys", "jwt", "sensitive-files"]) else "MEDIUM",
                module=self.MODULE_NAME,
                vuln=f"Gf Patterns: {len(pattern_hits)} Categories Matched",
                endpoint=self.target,
                evidence="\n".join(f"{cat}: {len(hits)} URLs" for cat, hits in pattern_hits.items()),
                description=(
                    f"Secret extraction found matches in {len(pattern_hits)} categories "
                    f"across {len(all_urls)} URLs."
                ),
                remediation="Prioritize api-keys and jwt findings — rotate any exposed credentials immediately.",
            ))

        except Exception:
            pass

    # ─── Phase 6: AI Correlation ──────────────────────────────────────────────

    async def _phase_ai_correlation(self, domain: str) -> None:
        """
        World-class OSINT AI correlation.
        Sends all findings to Vexor Intelligence AI for:
        - Attack chain construction
        - Threat actor profiling
        - Prioritized action items
        - Intelligence gaps
        """
        try:
            from vexor.ai.client import AIClient
            import json

            client = AIClient()
            if not client._token:
                return  # Not logged in — skip silently

            # Build findings summary for AI
            findings_data = []
            for f in self.findings:
                findings_data.append({
                    "severity": f.severity,
                    "type": f.vuln,
                    "evidence": f.evidence[:300] if f.evidence else "",
                    "description": f.description[:200] if f.description else "",
                })

            if not findings_data:
                return

            findings_summary = json.dumps(findings_data, indent=2)

            # ── AI Task 1: Master correlation ────────────────────────────────
            ai_report = await client.osint_ai_correlate(
                domain=domain,
                findings_summary=findings_summary,
            )

            if ai_report:
                self.add_finding(Finding(
                    severity="HIGH",
                    module=f"{self.MODULE_NAME}/ai",
                    vuln="🧠 Vexor Intelligence: Attack Chain Analysis",
                    endpoint=self.target,
                    evidence=ai_report[:2000],
                    description=(
                        "Vexor AI correlated all OSINT findings and constructed "
                        "attack chains, threat profile, and prioritized action items."
                    ),
                    remediation="Follow the AI-generated action items in order of priority.",
                ))

            # ── AI Task 2: Subdomain intelligence (if many subs found) ───────
            if len(self._all_subdomains) > 5:
                sub_intel = await client.osint_ai_subdomain_intel(
                    domain=domain,
                    subdomains=list(self._all_subdomains)[:100],
                )
                if sub_intel:
                    self.add_finding(Finding(
                        severity="MEDIUM",
                        module=f"{self.MODULE_NAME}/ai",
                        vuln=f"🧠 Vexor Intelligence: Subdomain Attack Vectors",
                        endpoint=self.target,
                        evidence=sub_intel[:2000],
                        description=(
                            f"AI analyzed {len(self._all_subdomains)} subdomains "
                            f"and identified high-value attack targets."
                        ),
                        remediation="Prioritize investigation of AI-flagged high-value subdomains.",
                    ))

            # ── AI Task 3: Secret analysis (if secrets found) ─────────────────
            if self._secrets_found:
                secret_intel = await client.osint_ai_secret_analysis(
                    domain=domain,
                    secrets=self._secrets_found[:50],
                )
                if secret_intel:
                    self.add_finding(Finding(
                        severity="CRITICAL",
                        module=f"{self.MODULE_NAME}/ai",
                        vuln=f"🧠 Vexor Intelligence: Leaked Secrets Analysis",
                        endpoint=self.target,
                        evidence=secret_intel[:2000],
                        description=(
                            f"AI analyzed {len(self._secrets_found)} potential secrets/sensitive URLs. "
                            "Immediate action required."
                        ),
                        remediation="Rotate all exposed credentials immediately. Follow AI remediation steps.",
                    ))

            # ── AI Task 4: Live hosts analysis ────────────────────────────────
            if self._live_hosts:
                host_list = [
                    f"{h['status']} {h['url']} [{h['title'] or h['server']}]"
                    for h in self._live_hosts[:30]
                ]
                hosts_intel = await client.osint_ai_live_hosts(
                    domain=domain,
                    live_hosts=host_list,
                )
                if hosts_intel:
                    self.add_finding(Finding(
                        severity="HIGH",
                        module=f"{self.MODULE_NAME}/ai",
                        vuln=f"🧠 Vexor Intelligence: Attack Surface Analysis",
                        endpoint=self.target,
                        evidence=hosts_intel[:2000],
                        description=(
                            f"AI analyzed {len(self._live_hosts)} live hosts "
                            "and identified quick wins and attack vectors."
                        ),
                        remediation="Follow AI-recommended attack prioritization for authorized testing.",
                    ))

        except Exception:
            pass
