"""
Vexor OSINT Module v2.0.0 — Elite Level Intelligence Gathering
10 independent modules — one failure never stops others
"""
import asyncio
import re
import socket
import time
from urllib.parse import urlparse
from vexor.modules.base import BaseScanner, Finding


class Scanner(BaseScanner):
    """
    OSINT Intelligence Gatherer v2.0.0
    10 modules: DNS, CT logs, email harvest, IP geo, port scan,
    SPF/DMARC, tech fingerprint, Wayback, GitHub, social media
    """

    MODULE_NAME = "osint"
    MODULE_DESC = "OSINT Intelligence Gathering — Elite Level (10 modules)"

    async def scan(self) -> list[Finding]:
        async with self:
            parsed = urlparse(self.target)
            domain = parsed.hostname or self.target
            if domain.startswith("www."):
                domain = domain[4:]

            # Run all 10 modules independently — failures are isolated
            await asyncio.gather(
                self._module_dns_records(domain),
                self._module_certificate_transparency(domain),
                self._module_email_harvest(domain),
                self._module_ip_geolocation(domain),
                self._module_port_scan(domain),
                self._module_spf_dmarc(domain),
                self._module_tech_fingerprint(),
                self._module_wayback(domain),
                self._module_github_search(domain),
                self._module_social_media(domain),
                return_exceptions=True,
            )

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
