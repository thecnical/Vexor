"""
Vexor CVE Lookup
Matches detected technologies with known CVEs
"""
import asyncio
import re
from urllib.parse import urlparse
from vexor.modules.base import BaseScanner, Finding


NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"


class Scanner(BaseScanner):
    """CVE Lookup Scanner"""

    MODULE_NAME = "cve_lookup"
    MODULE_DESC = "CVE Vulnerability Lookup"

    async def scan(self) -> list[Finding]:
        async with self:
            # First fingerprint the target
            tech_info = await self._fingerprint_target()

            if tech_info:
                # Look up CVEs for detected technologies
                tasks = []
                for tech, version in tech_info.items():
                    tasks.append(self._lookup_cves(tech, version))
                await asyncio.gather(*tasks, return_exceptions=True)
            else:
                self.add_finding(Finding(
                    severity="INFO",
                    module=self.MODULE_NAME,
                    vuln="CVE Lookup — No Technology Detected",
                    endpoint=self.target,
                    description="Run fingerprinter module first to detect technologies",
                    remediation="Use --module fingerprint to detect technologies",
                ))

        return self.findings

    async def _fingerprint_target(self) -> dict:
        """Quick fingerprint to get tech versions"""
        response = await self.get(self.target)
        if not response:
            return {}

        tech = {}
        headers = {k.lower(): v for k, v in response.headers.items()}

        # Server version
        server = headers.get('server', '')
        if server:
            # Apache/2.4.51
            apache_match = re.search(r'Apache/(\d+\.\d+\.?\d*)', server)
            if apache_match:
                tech['apache'] = apache_match.group(1)

            # nginx/1.21.0
            nginx_match = re.search(r'nginx/(\d+\.\d+\.?\d*)', server)
            if nginx_match:
                tech['nginx'] = nginx_match.group(1)

        # PHP version
        powered = headers.get('x-powered-by', '')
        php_match = re.search(r'PHP/(\d+\.\d+\.?\d*)', powered)
        if php_match:
            tech['php'] = php_match.group(1)

        # WordPress
        if 'wp-content' in response.text:
            wp_match = re.search(r'WordPress (\d+\.\d+\.?\d*)', response.text)
            if wp_match:
                tech['wordpress'] = wp_match.group(1)

        return tech

    async def _lookup_cves(self, technology: str, version: str) -> None:
        """Look up CVEs for a technology"""
        try:
            params = {
                'keywordSearch': f"{technology} {version}",
                'resultsPerPage': '5',
            }

            resp = await self.get(NVD_API, params=params)
            if not resp or resp.status_code != 200:
                return

            data = resp.json()
            vulnerabilities = data.get('vulnerabilities', [])

            for vuln in vulnerabilities[:3]:
                cve = vuln.get('cve', {})
                cve_id = cve.get('id', '')
                descriptions = cve.get('descriptions', [])
                desc = next(
                    (d['value'] for d in descriptions if d.get('lang') == 'en'),
                    'No description'
                )

                # Get CVSS score
                metrics = cve.get('metrics', {})
                cvss_score = 0.0
                severity = "MEDIUM"

                for metric_key in ['cvssMetricV31', 'cvssMetricV30', 'cvssMetricV2']:
                    if metric_key in metrics and metrics[metric_key]:
                        cvss_data = metrics[metric_key][0].get('cvssData', {})
                        cvss_score = cvss_data.get('baseScore', 0.0)
                        break

                if cvss_score >= 9.0:
                    severity = "CRITICAL"
                elif cvss_score >= 7.0:
                    severity = "HIGH"
                elif cvss_score >= 4.0:
                    severity = "MEDIUM"
                else:
                    severity = "LOW"

                self.add_finding(Finding(
                    severity=severity,
                    module=self.MODULE_NAME,
                    vuln=f"CVE: {cve_id}",
                    endpoint=self.target,
                    cve=cve_id,
                    evidence=f"{technology} {version} — CVSS: {cvss_score}",
                    description=desc[:300],
                    remediation=f"Update {technology} to latest version. See: https://nvd.nist.gov/vuln/detail/{cve_id}",
                ))

        except Exception:
            pass
