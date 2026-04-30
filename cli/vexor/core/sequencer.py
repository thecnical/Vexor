"""
Vexor Sequencer — Token Randomness Analyzer
"""
import asyncio
import math
import re
import statistics
from collections import Counter
from typing import Optional
from vexor.modules.base import BaseScanner, Finding


class TokenAnalyzer:
    """Analyzes randomness quality of tokens"""

    def analyze(self, tokens: list[str]) -> dict:
        """Analyze a list of tokens for randomness"""
        if not tokens:
            return {"error": "No tokens provided"}

        results = {
            "count": len(tokens),
            "length_stats": self._analyze_lengths(tokens),
            "entropy": self._calculate_entropy(tokens),
            "charset": self._analyze_charset(tokens),
            "patterns": self._find_patterns(tokens),
            "verdict": "UNKNOWN",
        }

        # Determine verdict
        entropy = results["entropy"]["per_token"]
        if entropy < 32:
            results["verdict"] = "WEAK — Low entropy, predictable"
        elif entropy < 64:
            results["verdict"] = "MEDIUM — Moderate entropy"
        elif entropy < 128:
            results["verdict"] = "GOOD — High entropy"
        else:
            results["verdict"] = "STRONG — Very high entropy"

        return results

    def _analyze_lengths(self, tokens: list[str]) -> dict:
        lengths = [len(t) for t in tokens]
        return {
            "min": min(lengths),
            "max": max(lengths),
            "avg": sum(lengths) / len(lengths),
            "consistent": len(set(lengths)) == 1,
        }

    def _calculate_entropy(self, tokens: list[str]) -> dict:
        all_chars = ''.join(tokens)
        char_counts = Counter(all_chars)
        total = len(all_chars)

        entropy = 0
        for count in char_counts.values():
            p = count / total
            if p > 0:
                entropy -= p * math.log2(p)

        return {
            "bits_per_char": round(entropy, 2),
            "per_token": round(entropy * len(tokens[0]) if tokens else 0, 2),
            "unique_chars": len(char_counts),
        }

    def _analyze_charset(self, tokens: list[str]) -> dict:
        all_chars = set(''.join(tokens))
        return {
            "has_lowercase": bool(all_chars & set('abcdefghijklmnopqrstuvwxyz')),
            "has_uppercase": bool(all_chars & set('ABCDEFGHIJKLMNOPQRSTUVWXYZ')),
            "has_digits": bool(all_chars & set('0123456789')),
            "has_special": bool(all_chars - set('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789')),
            "charset_size": len(all_chars),
        }

    def _find_patterns(self, tokens: list[str]) -> list[str]:
        patterns = []

        # Check for sequential tokens
        if len(tokens) >= 2:
            numeric_tokens = []
            for t in tokens:
                try:
                    numeric_tokens.append(int(t, 16))
                except ValueError:
                    try:
                        numeric_tokens.append(int(t))
                    except ValueError:
                        pass

            if len(numeric_tokens) == len(tokens):
                diffs = [numeric_tokens[i+1] - numeric_tokens[i]
                        for i in range(len(numeric_tokens)-1)]
                if len(set(diffs)) == 1:
                    patterns.append(f"SEQUENTIAL — increment of {diffs[0]}")

        # Check for timestamp-based tokens
        import time
        current_ts = int(time.time())
        for token in tokens[:3]:
            try:
                val = int(token[:10])
                if abs(val - current_ts) < 86400 * 365:  # Within 1 year
                    patterns.append("TIMESTAMP-BASED — predictable")
                    break
            except ValueError:
                pass

        # Check for common prefixes
        if len(tokens) >= 3:
            prefix_len = 0
            for i in range(min(len(t) for t in tokens)):
                if len(set(t[i] for t in tokens)) == 1:
                    prefix_len += 1
                else:
                    break
            if prefix_len > 4:
                patterns.append(f"COMMON PREFIX — first {prefix_len} chars identical")

        return patterns


class Scanner(BaseScanner):
    """Token Sequencer/Analyzer"""

    MODULE_NAME = "sequencer"
    MODULE_DESC = "Token Randomness Analysis"

    async def scan(self) -> list[Finding]:
        async with self:
            tokens = await self._collect_tokens()
            if tokens:
                analyzer = TokenAnalyzer()
                results = analyzer.analyze(tokens)
                self._report_results(results, tokens)
        return self.findings

    async def _collect_tokens(self) -> list[str]:
        """Collect session tokens from multiple requests"""
        tokens = []
        for _ in range(10):
            resp = await self.get(self.target)
            if resp:
                # Extract session cookies
                for name, value in resp.cookies.items():
                    if any(s in name.lower() for s in ['session', 'sess', 'token', 'sid']):
                        tokens.append(value)
                        break
            await asyncio.sleep(0.2)
        return tokens

    def _report_results(self, results: dict, tokens: list[str]) -> None:
        verdict = results.get("verdict", "")
        entropy = results.get("entropy", {}).get("per_token", 0)
        patterns = results.get("patterns", [])

        if "WEAK" in verdict or patterns:
            severity = "HIGH"
        elif "MEDIUM" in verdict:
            severity = "MEDIUM"
        else:
            severity = "INFO"

        self.add_finding(Finding(
            severity=severity,
            module=self.MODULE_NAME,
            vuln=f"Token Analysis: {verdict}",
            endpoint=self.target,
            evidence=(
                f"Entropy: {entropy} bits | "
                f"Patterns: {', '.join(patterns) if patterns else 'None'} | "
                f"Sample: {tokens[0][:20] if tokens else 'N/A'}..."
            ),
            description=f"Session token analysis: {verdict}",
            remediation=(
                "Use cryptographically secure random token generation. "
                "Minimum 128 bits of entropy recommended."
            ),
        ))
