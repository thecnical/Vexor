"""
Vexor Intruder — Advanced HTTP Fuzzer
Mirrors Burp Suite Intruder with all 4 attack modes:
  • Sniper         — One payload position at a time, single wordlist
  • Battering Ram  — Same payload into all positions simultaneously
  • Pitchfork      — Multiple wordlists, one per position, parallel
  • Cluster Bomb   — All combinations of multiple wordlists (Cartesian product)

Each attack result is logged with status code, response length, time, and diff flag.
"""
import asyncio
import ssl
import time
import re
import itertools
from dataclasses import dataclass, field
from typing import Optional, Callable
from urllib.parse import urlparse, urlencode, parse_qs


# ─── Position markers ─────────────────────────────────────────────────────────
MARKER_OPEN  = "§"
MARKER_CLOSE = "§"
MARKER_RE    = re.compile(r"§([^§]*)§")


# ─── Data classes ──────────────────────────────────────────────────────────────

@dataclass
class IntruderResult:
    attack_type:  str
    position_idx: int
    payload:      str | list[str]
    status_code:  int
    response_length: int
    elapsed_ms:   float
    response_body: bytes = b""
    is_interesting: bool = False   # marked if length/status differs from baseline
    error: str = ""


@dataclass
class IntruderConfig:
    host:        str
    port:        int
    use_https:   bool
    raw_request: str          # Full raw HTTP request with §markers§
    attack_type: str          # "sniper" | "battering_ram" | "pitchfork" | "cluster_bomb"
    wordlists:   list[list[str]] = field(default_factory=list)  # one per position
    threads:     int = 10
    timeout:     int = 30
    grep_extract: str = ""    # regex to extract from response
    follow_redirects: bool = False
    max_results: int = 10000


# ─── Intruder Engine ──────────────────────────────────────────────────────────

class Intruder:
    """
    Vexor Intruder — payload-based HTTP fuzzer with 4 attack modes.
    """

    def __init__(self, on_result: Optional[Callable] = None):
        self._on_result = on_result
        self._running   = False
        self._results:  list[IntruderResult] = []
        self._stop_flag = False

    @property
    def results(self) -> list[IntruderResult]:
        return list(self._results)

    def stop(self) -> None:
        self._stop_flag = True

    async def run(self, config: IntruderConfig) -> list[IntruderResult]:
        """Run an Intruder attack. Returns list of results."""
        self._results  = []
        self._running  = True
        self._stop_flag = False

        positions = self._find_positions(config.raw_request)

        if not positions:
            raise ValueError(
                "No §marker§ positions found in request. "
                "Wrap injection points with §like this§."
            )

        # Build payload iterator based on attack type
        payload_iter = self._build_payload_iter(config, positions)

        # Run with semaphore for concurrency control
        sem = asyncio.Semaphore(config.threads)

        # Get baseline first
        baseline = await self._send(config, config.raw_request)
        baseline_length = len(baseline.response_body) if baseline else 0

        tasks = []
        for idx, (attack_idx, payload_combo) in enumerate(payload_iter):
            if self._stop_flag or idx >= config.max_results:
                break

            # Build the request with payload injected
            injected = self._inject(config.raw_request, positions, payload_combo)
            tasks.append(
                self._run_single(sem, config, attack_idx, payload_combo, injected, baseline_length)
            )

        results = await asyncio.gather(*tasks, return_exceptions=True)

        for r in results:
            if isinstance(r, IntruderResult):
                self._results.append(r)
                if self._on_result:
                    try:
                        self._on_result(r)
                    except Exception:
                        pass

        self._running = False
        return self._results

    async def _run_single(
        self,
        sem: asyncio.Semaphore,
        config: IntruderConfig,
        attack_idx: int,
        payload: str | list[str],
        raw_request: str,
        baseline_length: int,
    ) -> Optional[IntruderResult]:
        async with sem:
            if self._stop_flag:
                return None
            result = await self._send(config, raw_request)
            if result:
                # Mark as interesting if length deviates significantly from baseline
                length_diff = abs(result.response_length - baseline_length)
                result.attack_type   = config.attack_type
                result.position_idx  = attack_idx
                result.payload       = payload
                result.is_interesting = (
                    result.status_code in (200, 500, 302, 403)
                    and (
                        result.status_code != 200
                        or length_diff > 50
                    )
                )

                # Grep extract
                if config.grep_extract:
                    try:
                        m = re.search(config.grep_extract, result.response_body.decode("utf-8", errors="ignore"))
                        if m:
                            result.is_interesting = True
                    except Exception:
                        pass

                return result
        return None

    async def _send(self, config: IntruderConfig, raw_request: str) -> Optional[IntruderResult]:
        """Send a single HTTP(S) request from raw text, return IntruderResult."""
        start = time.time()
        try:
            if config.use_https:
                ctx = ssl.create_default_context()
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(config.host, config.port, ssl=ctx, server_hostname=config.host),
                    timeout=config.timeout,
                )
            else:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(config.host, config.port),
                    timeout=config.timeout,
                )

            writer.write(raw_request.encode("utf-8", errors="replace"))
            await writer.drain()

            # Read status line
            status_line = await asyncio.wait_for(reader.readline(), timeout=config.timeout)
            status_parts = status_line.decode("utf-8", errors="replace").strip().split(" ", 2)
            status_code  = int(status_parts[1]) if len(status_parts) > 1 else 0

            # Read headers
            content_length = 0
            transfer_encoding = ""
            while True:
                h_line = await asyncio.wait_for(reader.readline(), timeout=5)
                if h_line in (b"\r\n", b"\n", b""):
                    break
                if b":" in h_line:
                    k, v = h_line.decode("utf-8", errors="replace").split(":", 1)
                    k = k.strip().lower()
                    if k == "content-length":
                        content_length = int(v.strip())
                    elif k == "transfer-encoding":
                        transfer_encoding = v.strip().lower()

            # Read body
            if "chunked" in transfer_encoding:
                resp_body = await self._read_chunked(reader)
            elif content_length > 0:
                resp_body = await asyncio.wait_for(reader.read(content_length), timeout=config.timeout)
            else:
                resp_body = await asyncio.wait_for(reader.read(256 * 1024), timeout=config.timeout)

            writer.close()
            elapsed = (time.time() - start) * 1000

            return IntruderResult(
                attack_type="",
                position_idx=0,
                payload="",
                status_code=status_code,
                response_length=len(resp_body),
                elapsed_ms=elapsed,
                response_body=resp_body,
            )

        except asyncio.TimeoutError:
            elapsed = (time.time() - start) * 1000
            return IntruderResult(
                attack_type="", position_idx=0, payload="",
                status_code=0, response_length=0, elapsed_ms=elapsed,
                error="timeout",
            )
        except Exception as e:
            elapsed = (time.time() - start) * 1000
            return IntruderResult(
                attack_type="", position_idx=0, payload="",
                status_code=0, response_length=0, elapsed_ms=elapsed,
                error=str(e)[:100],
            )

    @staticmethod
    async def _read_chunked(reader: asyncio.StreamReader) -> bytes:
        body = b""
        while True:
            try:
                size_line = await asyncio.wait_for(reader.readline(), timeout=5)
                size = int(size_line.strip(), 16)
                if size == 0:
                    break
                chunk = await asyncio.wait_for(reader.read(size), timeout=10)
                body += chunk
                await reader.readline()
            except Exception:
                break
        return body

    # ─── Position & Payload Logic ─────────────────────────────────────────────

    @staticmethod
    def _find_positions(raw_request: str) -> list[tuple[int, int, str]]:
        """
        Find all §marker§ positions in the raw request.
        Returns list of (start, end, default_value).
        """
        positions = []
        for m in MARKER_RE.finditer(raw_request):
            positions.append((m.start(), m.end(), m.group(1)))
        return positions

    @staticmethod
    def _inject(raw_request: str, positions: list, payload_combo: list[str]) -> str:
        """Replace §markers§ with payload values."""
        result = raw_request
        offset = 0
        for i, (start, end, _) in enumerate(positions):
            payload = payload_combo[i] if i < len(payload_combo) else ""
            s = start + offset
            e = end + offset
            result = result[:s] + payload + result[e:]
            offset += len(payload) - (end - start)
        return result

    def _build_payload_iter(self, config: IntruderConfig, positions: list):
        """Build the payload iteration strategy based on attack type."""
        wordlists = config.wordlists
        n_pos = len(positions)

        if not wordlists:
            wordlists = [["FUZZ"]]

        if config.attack_type == "sniper":
            # Each position gets each payload, one at a time
            for pos_idx, (start, end, default) in enumerate(positions):
                wl = wordlists[0] if wordlists else ["FUZZ"]
                for payload in wl:
                    combo = [default] * n_pos
                    combo[pos_idx] = payload
                    yield (pos_idx, combo)

        elif config.attack_type == "battering_ram":
            # Same payload into ALL positions simultaneously
            wl = wordlists[0] if wordlists else ["FUZZ"]
            for payload in wl:
                combo = [payload] * n_pos
                yield (0, combo)

        elif config.attack_type == "pitchfork":
            # Multiple wordlists, zipped (stops at shortest)
            lists = [wordlists[i] if i < len(wordlists) else [""] for i in range(n_pos)]
            for i, combo in enumerate(zip(*lists)):
                yield (i, list(combo))

        elif config.attack_type == "cluster_bomb":
            # Cartesian product of all wordlists
            lists = [wordlists[i] if i < len(wordlists) else [""] for i in range(n_pos)]
            for i, combo in enumerate(itertools.product(*lists)):
                yield (i, list(combo))

        else:
            raise ValueError(f"Unknown attack type: {config.attack_type!r}. "
                             "Use: sniper, battering_ram, pitchfork, cluster_bomb")

    # ─── Built-in Wordlists ───────────────────────────────────────────────────

    @staticmethod
    def wordlist_sqli() -> list[str]:
        return [
            "'", "''", "' OR '1'='1", "' OR 1=1--", "\" OR \"1\"=\"1",
            "' OR 'x'='x", "1 OR 1=1", "1' OR '1'='1'--",
            "admin'--", "' UNION SELECT NULL--", "' UNION SELECT NULL,NULL--",
            "' UNION SELECT NULL,NULL,NULL--", "'; DROP TABLE users--",
            "1; SELECT SLEEP(5)--", "1 AND SLEEP(5)--",
        ]

    @staticmethod
    def wordlist_xss() -> list[str]:
        return [
            "<script>alert(1)</script>",
            "<img src=x onerror=alert(1)>",
            "'><script>alert(1)</script>",
            "\"><script>alert(1)</script>",
            "<svg onload=alert(1)>",
            "javascript:alert(1)",
            "<details open ontoggle=alert(1)>",
            "<%2fscript><%2fscript>",
        ]

    @staticmethod
    def wordlist_common_passwords() -> list[str]:
        return [
            "password", "123456", "admin", "letmein", "qwerty",
            "welcome", "monkey", "dragon", "master", "sunshine",
            "password1", "admin123", "test", "root", "toor",
        ]

    @staticmethod
    def wordlist_paths() -> list[str]:
        return [
            "/admin", "/admin/", "/login", "/dashboard", "/.git/config",
            "/.env", "/api/v1/users", "/api/admin", "/wp-admin",
            "/phpmyadmin", "/backup", "/config", "/debug",
        ]


# ─── Global singleton ──────────────────────────────────────────────────────────

_intruder = Intruder()


def get_intruder() -> Intruder:
    return _intruder


def new_intruder(on_result: Optional[Callable] = None) -> Intruder:
    """Create a new Intruder instance (e.g., for concurrent attacks)."""
    return Intruder(on_result=on_result)
