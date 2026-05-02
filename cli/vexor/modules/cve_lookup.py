"""
Vexor CVE Lookup + ExploitDB Mapping
Matches detected technologies with known CVEs.
For each CVE found, searches ExploitDB for public exploits.
"""
import asyncio
import re
from urllib.parse import urlparse
from vexor.modules.base import BaseScanner, Finding


NVD_API      = "https://services.nvd.nist.gov/rest/json/cves/2.0"
EXPLOITDB_API = "https://www.exploit-db.com/search"


class Scanner(BaseScanner):
    """CVE Lookup + ExploitDB Scanner"""

    MODULE_NAME = "cve_lookup"
    MODULE_DESC = "CVE Lookup + ExploitDB Exploit Mapping"

    async def scan(self) -> list[Finding]:
        async with self:
            tech_info = await self._fingerprint_target()

            if tech_info:
                tasks = [self._lookup_cves(tech, version)
                         for tech, version in tech_info.items()]
                await asyncio.gather(*tasks, return_exceptions=True)
            else:
                self.add_finding(Finding(
                    severity="INFO",
                    module=self.MODULE_NAME,
                    vuln="CVE Lookup — No Technology Detected",
                    endpoint=self.target,
                    description="No technology version detected. Run fingerprinter first.",
                    remediation="Use --module fingerprinter to detect technologies",
                ))

        return self.findings

    async def _fingerprint_target(self) -> dict:
        """Quick fingerprint to get tech versions"""
        response = await self.get(self.target)
        if not response:
            return {}

        tech = {}
        headers = {k.lower(): v for k, v in response.headers.items()}

        server = headers.get("server", "")
        if server:
            m = re.search(r"Apache/(\d+\.\d+\.?\d*)", server)
            if m:
                tech["apache"] = m.group(1)
            m = re.search(r"nginx/(\d+\.\d+\.?\d*)", server)
            if m:
                tech["nginx"] = m.group(1)
            m = re.search(r"Microsoft-IIS/(\d+\.\d+)", server)
            if m:
                tech["iis"] = m.group(1)

        powered = headers.get("x-powered-by", "")
        m = re.search(r"PHP/(\d+\.\d+\.?\d*)", powered)
        if m:
            tech["php"] = m.group(1)

        if "wp-content" in response.text:
            m = re.search(r"WordPress[/ ](\d+\.\d+\.?\d*)", response.text)
            if m:
                tech["wordpress"] = m.group(1)

        return tech

    async def _lookup_cves(self, technology: str, version: str) -> None:
        """Look up CVEs for a technology and search ExploitDB for each"""
        try:
            resp = await self.get(
                NVD_API,
                params={
                    "keywordSearch": f"{technology} {version}",
                    "resultsPerPage": "5",
                },
            )
            if not resp or resp.status_code != 200:
                return

            data = resp.json()
            vulnerabilities = data.get("vulnerabilities", [])

            for vuln in vulnerabilities[:3]:
                cve_obj  = vuln.get("cve", {})
                cve_id   = cve_obj.get("id", "")
                descs    = cve_obj.get("descriptions", [])
                desc     = next(
                    (d["value"] for d in descs if d.get("lang") == "en"),
                    "No description",
                )

                # CVSS score
                metrics    = cve_obj.get("metrics", {})
                cvss_score = 0.0
                for key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
                    if key in metrics and metrics[key]:
                        cvss_score = metrics[key][0].get("cvssData", {}).get("baseScore", 0.0)
                        break

                severity = (
                    "CRITICAL" if cvss_score >= 9.0 else
                    "HIGH"     if cvss_score >= 7.0 else
                    "MEDIUM"   if cvss_score >= 4.0 else
                    "LOW"
                )

                # Search ExploitDB for public exploits
                exploits = await self._search_exploitdb(cve_id, technology)

                evidence = f"{technology} {version} — CVSS: {cvss_score}"
                if exploits:
                    evidence += f"\n\n⚠ PUBLIC EXPLOITS FOUND ({len(exploits)}):\n"
                    evidence += "\n".join(exploits[:5])
                    # Upgrade severity if public exploit exists
                    if severity == "MEDIUM":
                        severity = "HIGH"
                    elif severity == "HIGH":
                        severity = "CRITICAL"

                vuln_name = f"CVE: {cve_id}"
                if exploits:
                    vuln_name += f" [PUBLIC EXPLOIT AVAILABLE]"

                self.add_finding(Finding(
                    severity=severity,
                    module=self.MODULE_NAME,
                    vuln=vuln_name,
                    endpoint=self.target,
                    cve=cve_id,
                    evidence=evidence,
                    description=desc[:300],
                    remediation=(
                        f"Update {technology} to latest version immediately. "
                        f"Public exploit exists — patch urgently. "
                        f"See: https://nvd.nist.gov/vuln/detail/{cve_id}"
                        if exploits else
                        f"Update {technology} to latest version. "
                        f"See: https://nvd.nist.gov/vuln/detail/{cve_id}"
                    ),
                ))

        except Exception:
            pass

    async def _search_exploitdb(self, cve_id: str, technology: str) -> list[str]:
        """
        Search ExploitDB for public exploits matching a CVE.
        Uses the ExploitDB search API (no key required).
        """
        exploits = []
        try:
            # ExploitDB search by CVE
            resp = await self.get(
                "https://www.exploit-db.com/search",
                params={"cve": cve_id.replace("CVE-", ""), "type": ""},
                headers={
                    "User-Agent": "Mozilla/5.0",
                    "Accept": "application/json, text/javascript",
                    "X-Requested-With": "XMLHttpRequest",
                },
            )
            if resp and resp.status_code == 200:
                try:
                    data = resp.json()
                    for item in data.get("data", [])[:5]:
                        eid   = item.get("id", "")
                        title = item.get("description", "")
                        if eid:
                            exploits.append(
                                f"EDB-{eid}: {title[:80]} — "
                                f"https://www.exploit-db.com/exploits/{eid}"
                            )
                except Exception:
                    pass

            # Also check GitHub for PoC
            if not exploits:
                gh_resp = await self.get(
                    f"https://api.github.com/search/repositories?q={cve_id}&sort=stars&per_page=3",
                    headers={
                        "User-Agent": "Vexor/4.0",
                        "Accept": "application/vnd.github.v3+json",
                    },
                )
                if gh_resp and gh_resp.status_code == 200:
                    items = gh_resp.json().get("items", [])
                    for repo in items[:3]:
                        name = repo.get("full_name", "")
                        url  = repo.get("html_url", "")
                        stars = repo.get("stargazers_count", 0)
                        if name and cve_id.lower() in name.lower():
                            exploits.append(
                                f"GitHub PoC ({stars}★): {name} — {url}"
                            )

        except Exception:
            pass
        return exploits
