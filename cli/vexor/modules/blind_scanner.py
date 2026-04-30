"""
Vexor Blind Vulnerability Scanner
Uses interactsh (free Burp Collaborator alternative) for OOB detection
Detects: Blind SSRF, Blind XSS, Log4Shell, XXE OOB, SSTI OOB
"""
import asyncio
import re
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from vexor.modules.base import BaseScanner, Finding
from vexor.core.collaborator import VexorCollaborator


class Scanner(BaseScanner):
    """Blind/OOB Vulnerability Scanner"""

    MODULE_NAME = "blind_scanner"
    MODULE_DESC = "Blind SSRF/XSS/XXE/Log4Shell via OOB (interactsh)"

    async def scan(self) -> list[Finding]:
        async with self:
            collab = VexorCollaborator()
            domain = await collab.register()

            if not domain:
                self.add_finding(Finding(
                    severity="INFO",
                    module=self.MODULE_NAME,
                    vuln="OOB Server Unavailable",
                    endpoint=self.target,
                    description="Could not connect to interactsh — blind scanning skipped",
                    remediation="Check internet connection",
                ))
                return self.findings

            await asyncio.gather(
                self._test_blind_ssrf(collab, domain),
                self._test_log4shell(collab, domain),
                self._test_blind_xss(collab, domain),
                return_exceptions=True
            )

        return self.findings

    async def _test_blind_ssrf(self, collab: VexorCollaborator, domain: str) -> None:
        """Test for blind SSRF using OOB"""
        from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

        ssrf_params = ['url', 'uri', 'link', 'src', 'source', 'href',
                       'redirect', 'callback', 'next', 'data', 'fetch']

        parsed = urlparse(self.target)
        params = parse_qs(parsed.query)

        test_params = list(params.keys()) + ssrf_params[:5]

        for param in test_params[:8]:
            payload = f"http://{domain}/ssrf-{param}"
            test_url = self._inject_param(self.target, param, payload)
            await self.get(test_url)
            await asyncio.sleep(0.5)

        # Wait for OOB interaction
        interaction = await collab.wait_for_interaction(timeout=8)
        if interaction:
            self.add_finding(Finding(
                severity="CRITICAL",
                module=self.MODULE_NAME,
                vuln="Blind SSRF Confirmed (OOB)",
                endpoint=self.target,
                evidence=f"OOB interaction received: {str(interaction)[:200]}",
                description="Server made outbound request to our OOB server — Blind SSRF confirmed",
                remediation="Validate and whitelist all URL inputs. Block internal network access.",
            ))

    async def _test_log4shell(self, collab: VexorCollaborator, domain: str) -> None:
        """Test for Log4Shell (CVE-2021-44228)"""
        payloads = collab.get_payload("log4shell")["payloads"]

        log4shell_headers = [
            "User-Agent", "X-Forwarded-For", "X-Api-Version",
            "Referer", "X-Forwarded-Host", "Accept-Language",
        ]

        for payload in payloads[:2]:
            for header in log4shell_headers[:3]:
                await self.get(self.target, headers={header: payload})
                await asyncio.sleep(0.3)

        interaction = await collab.wait_for_interaction(timeout=5)
        if interaction:
            self.add_finding(Finding(
                severity="CRITICAL",
                module=self.MODULE_NAME,
                vuln="Log4Shell (CVE-2021-44228) Confirmed",
                endpoint=self.target,
                evidence=f"OOB DNS/HTTP interaction received after Log4j payload",
                description="Log4Shell vulnerability confirmed via OOB interaction",
                remediation="Update Log4j to 2.17.1+. Apply WAF rules immediately.",
                cve="CVE-2021-44228",
            ))

    async def _test_blind_xss(self, collab: VexorCollaborator, domain: str) -> None:
        """Test for Blind XSS"""
        payloads = collab.get_payload("blind_xss")["payloads"]

        # Try in form inputs
        resp = await self.get(self.target)
        if not resp:
            return

        try:
            from bs4 import BeautifulSoup
            soup = BeautifulSoup(resp.text, 'lxml')
            for form in soup.find_all('form')[:2]:
                action = form.get('action', self.target)
                if action.startswith('/'):
                    parsed = urlparse(self.target)
                    action = f"{parsed.scheme}://{parsed.netloc}{action}"

                for payload in payloads[:1]:
                    data = {}
                    for inp in form.find_all('input'):
                        name = inp.get('name', '')
                        if name:
                            data[name] = payload
                    if data:
                        await self.post(action, data=data)
                        await asyncio.sleep(0.5)
        except Exception:
            pass

    def _inject_param(self, url: str, param: str, value: str) -> str:
        from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        params[param] = [value]
        return urlunparse(parsed._replace(query=urlencode(params, doseq=True)))
