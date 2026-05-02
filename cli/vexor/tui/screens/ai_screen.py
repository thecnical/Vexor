"""
Vexor AI Panel Screen v2.0.0 — More Powerful
Auto Exploit · Risk Score · Translate · Provider Info · Chat History
"""
from textual.app import ComposeResult
from textual.widget import Widget
from textual.widgets import Static, Input, Button, TextArea, Log, Select
from textual.containers import Horizontal, Vertical, Container, ScrollableContainer
from textual import work
import asyncio
import time


AI_ACTIONS = [
    ("analyze", "🔍 Analyze Vulnerability"),
    ("explain", "💡 Explain Request/Response"),
    ("suggest", "⚡ Suggest Next Attack"),
    ("payload", "🎯 Generate Payloads"),
    ("filter", "🧹 Filter False Positives"),
    ("report", "📄 Write Report Section"),
    ("auto_exploit", "🔥 Auto Exploit"),
    ("risk_score", "📊 Risk Score (CVSS)"),
    ("translate", "🌐 Translate Report"),
]

TRANSLATE_LANGS = [
    ("en", "English"),
    ("es", "Spanish"),
    ("fr", "French"),
    ("de", "German"),
    ("zh", "Chinese"),
    ("ar", "Arabic"),
    ("pt", "Portuguese"),
    ("ru", "Russian"),
    ("ja", "Japanese"),
    ("hi", "Hindi"),
]


class AIScreen(Widget):

    DEFAULT_CSS = """
    AIScreen {
        background: #0a0a0f;
        padding: 0 1;
        overflow-y: auto;
        height: auto;
    }
    .ai-title {
        height: 2;
        color: #00ffff;
        text-style: bold;
    }
    .controls-section {
        border: solid #1a1a2e;
        padding: 1;
        margin-bottom: 1;
        height: auto;
    }
    .action-row {
        height: 3;
        margin-bottom: 1;
    }
    .meta-row {
        height: 2;
        margin-bottom: 1;
    }
    .input-section {
        border: solid #00ffff;
        padding: 1;
        margin-bottom: 1;
        height: auto;
    }
    .input-textarea {
        height: 8;
    }
    .output-section {
        border: solid #ff00ff;
        padding: 1;
        margin-bottom: 1;
        height: auto;
    }
    .output-scroll {
        height: 14;
    }
    .history-section {
        border: solid #1a1a2e;
        padding: 1;
        height: auto;
        margin-bottom: 1;
    }
    .history-scroll {
        height: 10;
    }
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # Chat history: list of (action, input_snippet, result_snippet, provider, tokens, elapsed)
        self._chat_history: list[dict] = []

    def compose(self) -> ComposeResult:
        yield Static(
            "[bold bright_cyan]◈ AI PANEL v2.0[/]  "
            "[dim]Auto Exploit · Risk Score · Translate · Chat History[/]",
            classes="ai-title"
        )

        with Container(classes="controls-section"):
            with Horizontal(classes="action-row"):
                yield Select(
                    [(label, val) for val, label in AI_ACTIONS],
                    id="ai-action",
                    value="analyze"
                )
                yield Select(
                    [(label, val) for val, label in TRANSLATE_LANGS],
                    id="translate-lang",
                    value="en"
                )
                yield Button("🤖 Run AI", id="btn-run-ai", classes="success")
                yield Button("⊘ Clear", id="btn-clear-ai")
                yield Button("📋 History", id="btn-show-history")

            with Horizontal(classes="meta-row"):
                yield Static(
                    "[dim]Provider: —[/]",
                    id="ai-provider-status"
                )
                yield Static(
                    "[dim]Tokens: — · Time: —[/]",
                    id="ai-meta-status"
                )

        with Container(classes="input-section"):
            yield Static(
                "[bold bright_cyan]INPUT[/]  "
                "[dim](Paste request, response, finding, or vulnerability details)[/]"
            )
            yield TextArea(
                "Paste your HTTP request/response or vulnerability details here...",
                id="ai-input-text",
                classes="input-textarea"
            )

        with Container(classes="output-section"):
            yield Static("[bold bright_magenta]AI ANALYSIS[/]", id="output-title")
            with ScrollableContainer(classes="output-scroll"):
                yield Static(
                    "[dim]AI analysis will appear here...[/]\n\n"
                    "[bright_cyan]• 🔍 Analyze vulnerabilities[/]\n"
                    "[bright_cyan]• 💡 Explain HTTP headers[/]\n"
                    "[bright_cyan]• ⚡ Suggest attack steps[/]\n"
                    "[bright_cyan]• 🎯 Generate smart payloads[/]\n"
                    "[bright_cyan]• 🧹 Filter false positives[/]\n"
                    "[bright_cyan]• 📄 Write professional reports[/]\n"
                    "[bright_cyan]• 🔥 Auto Exploit — full chain[/]\n"
                    "[bright_cyan]• 📊 Risk Score — CVSS-like[/]\n"
                    "[bright_cyan]• 🌐 Translate reports[/]",
                    id="ai-output-text"
                )

        with Container(classes="history-section"):
            yield Static(
                "[bold bright_magenta]◈ CHAT HISTORY[/]  "
                "[dim](Last 5 exchanges)[/]"
            )
            with ScrollableContainer(classes="history-scroll"):
                yield Static(
                    "[dim]No history yet — run an AI action to start[/]",
                    id="ai-history-display"
                )

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn-run-ai":
            self.run_ai()
        elif event.button.id == "btn-clear-ai":
            try:
                self.query_one("#ai-input-text", TextArea).clear()
                self.query_one("#ai-output-text", Static).update("[dim]Cleared.[/]")
                self.query_one("#ai-provider-status", Static).update("[dim]Provider: —[/]")
                self.query_one("#ai-meta-status", Static).update("[dim]Tokens: — · Time: —[/]")
            except Exception:
                pass
        elif event.button.id == "btn-show-history":
            self._render_history()

    @work(exclusive=True)
    async def run_ai(self) -> None:
        action = self.query_one("#ai-action", Select).value
        lang = self.query_one("#translate-lang", Select).value
        input_text = self.query_one("#ai-input-text", TextArea).text
        output = self.query_one("#ai-output-text", Static)
        output_title = self.query_one("#output-title", Static)
        provider_status = self.query_one("#ai-provider-status", Static)
        meta_status = self.query_one("#ai-meta-status", Static)

        if not input_text.strip():
            self.notify("Enter some input first", severity="error")
            return

        # Update title based on action
        action_labels = {v: l for l, v in AI_ACTIONS}
        title_label = action_labels.get(action, "AI ANALYSIS")
        output_title.update(f"[bold bright_magenta]{title_label}[/]")
        output.update("[bright_yellow]⟳ AI analyzing...[/]")
        provider_status.update("[dim]Provider: connecting...[/]")
        meta_status.update("[dim]Tokens: — · Time: —[/]")

        t_start = time.time()

        try:
            from vexor.ai.client import AIClient
            client = AIClient()

            result = ""
            provider_used = "Unknown"

            if action == "analyze":
                result = await client.analyze(request=input_text)
            elif action == "explain":
                result = await client.explain(content=input_text)
            elif action == "suggest":
                result = await client.suggest_attack(context=input_text)
            elif action == "payload":
                payloads = await client.generate_payloads(target=input_text)
                result = "\n".join(payloads) if payloads else "No payloads generated"
            elif action == "filter":
                result = await client.filter_false_positives(findings=input_text)
            elif action == "report":
                result = await client.write_report_section(findings=input_text)
            elif action == "auto_exploit":
                result = await self._run_auto_exploit(client, input_text)
            elif action == "risk_score":
                result = await self._run_risk_score(client, input_text)
            elif action == "translate":
                result = await self._run_translate(client, input_text, lang)
            else:
                result = "Unknown action"

            elapsed = time.time() - t_start

            # Try to get provider info
            try:
                provider_used = getattr(client, "_last_provider", "AI Provider")
            except Exception:
                provider_used = "AI Provider"

            # Estimate token count (rough: ~4 chars per token)
            token_estimate = (len(input_text) + len(result)) // 4

            provider_status.update(
                f"[bright_green]Provider: {provider_used}[/]"
            )
            meta_status.update(
                f"[dim]Tokens: ~{token_estimate} · "
                f"Time: {elapsed:.1f}s[/]"
            )

            formatted = (
                f"[bold bright_cyan]◈ {title_label}[/]\n"
                f"[dim]─────────────────────────────[/]\n\n"
                f"{result}\n\n"
                f"[dim]Provider: {provider_used} · "
                f"~{token_estimate} tokens · {elapsed:.1f}s[/]"
            )
            output.update(formatted)

            # Add to chat history
            self._chat_history.append({
                "action": title_label,
                "input": input_text[:80].replace("\n", " "),
                "result": result[:120].replace("\n", " "),
                "provider": provider_used,
                "tokens": token_estimate,
                "elapsed": elapsed,
            })
            # Keep last 5
            self._chat_history = self._chat_history[-5:]
            self._render_history()

        except Exception as e:
            elapsed = time.time() - t_start
            output.update(f"[bright_red]Error: {str(e)}[/]")
            provider_status.update("[bright_red]Provider: Error[/]")
            meta_status.update(f"[dim]Time: {elapsed:.1f}s[/]")

    async def _run_auto_exploit(self, client, input_text: str) -> str:
        """Generate full exploit chain for a finding"""
        prompt = (
            "You are an expert penetration tester. Analyze this vulnerability finding "
            "and generate a COMPLETE exploit chain:\n\n"
            f"{input_text}\n\n"
            "Provide:\n"
            "1. VULNERABILITY SUMMARY\n"
            "2. PREREQUISITES (what attacker needs)\n"
            "3. STEP-BY-STEP EXPLOIT CHAIN\n"
            "4. PROOF OF CONCEPT (working payload/code)\n"
            "5. IMPACT ASSESSMENT\n"
            "6. DETECTION EVASION tips\n"
            "7. REMEDIATION\n\n"
            "Be specific and technical. Include actual payloads."
        )
        try:
            result = await client.analyze(request=prompt)
            return result
        except Exception as e:
            return (
                "🔥 AUTO EXPLOIT CHAIN\n"
                "─────────────────────\n\n"
                f"[Error generating exploit chain: {str(e)}]\n\n"
                "Manual analysis required. Key steps:\n"
                "1. Identify injection point\n"
                "2. Confirm vulnerability type\n"
                "3. Craft proof-of-concept payload\n"
                "4. Escalate privileges if possible\n"
                "5. Document impact"
            )

    async def _run_risk_score(self, client, input_text: str) -> str:
        """Generate CVSS-like risk score"""
        prompt = (
            "You are a security expert. Analyze this vulnerability and provide "
            "a CVSS v3.1-style risk assessment:\n\n"
            f"{input_text}\n\n"
            "Provide:\n"
            "1. CVSS BASE SCORE (0.0-10.0) with justification\n"
            "2. CVSS VECTOR STRING (AV:/AC:/PR:/UI:/S:/C:/I:/A:)\n"
            "3. SEVERITY RATING (None/Low/Medium/High/Critical)\n"
            "4. ATTACK VECTOR analysis\n"
            "5. IMPACT analysis (Confidentiality/Integrity/Availability)\n"
            "6. EXPLOITABILITY analysis\n"
            "7. RISK PRIORITY recommendation\n\n"
            "Be precise and follow CVSS v3.1 methodology."
        )
        try:
            result = await client.analyze(request=prompt)
            return result
        except Exception as e:
            return (
                "📊 RISK SCORE ASSESSMENT\n"
                "─────────────────────────\n\n"
                f"[Error: {str(e)}]\n\n"
                "Manual CVSS scoring required.\n"
                "Use: https://www.first.org/cvss/calculator/3.1"
            )

    async def _run_translate(self, client, input_text: str, lang: str) -> str:
        """Translate report/finding to target language"""
        lang_names = {v: l for l, v in TRANSLATE_LANGS}
        lang_name = lang_names.get(lang, lang)

        prompt = (
            f"Translate the following security report/finding to {lang_name}. "
            "Maintain all technical terms, CVE numbers, and code snippets as-is. "
            "Only translate the natural language portions:\n\n"
            f"{input_text}"
        )
        try:
            result = await client.analyze(request=prompt)
            return f"🌐 TRANSLATED TO {lang_name.upper()}\n{'─'*40}\n\n{result}"
        except Exception as e:
            return f"[Translation error: {str(e)}]"

    def _render_history(self) -> None:
        """Render last 5 chat exchanges"""
        try:
            history_display = self.query_one("#ai-history-display", Static)
            if not self._chat_history:
                history_display.update("[dim]No history yet[/]")
                return

            lines = []
            for i, entry in enumerate(reversed(self._chat_history), 1):
                lines.append(
                    f"[bold bright_cyan][{i}] {entry['action']}[/]  "
                    f"[dim]{entry['provider']} · ~{entry['tokens']} tokens · "
                    f"{entry['elapsed']:.1f}s[/]"
                )
                lines.append(f"[dim]  IN:[/] {entry['input'][:70]}...")
                lines.append(f"[dim]  OUT:[/] {entry['result'][:70]}...")
                lines.append("")

            history_display.update("\n".join(lines))
        except Exception:
            pass
