"""
Vexor AI Panel Screen
"""
from textual.app import ComposeResult
from textual.widget import Widget
from textual.widgets import Static, Input, Button, TextArea, Log, Select
from textual.containers import Horizontal, Vertical, Container, ScrollableContainer
from textual import work
import asyncio


AI_ACTIONS = [
    ("analyze", "🔍 Analyze Vulnerability"),
    ("explain", "💡 Explain Request/Response"),
    ("suggest", "⚡ Suggest Next Attack"),
    ("payload", "🎯 Generate Payloads"),
    ("filter", "🧹 Filter False Positives"),
    ("report", "📄 Write Report Section"),
]


class AIScreen(Widget):
    """AI Analysis Panel"""

    DEFAULT_CSS = """
    AIScreen {
        background: #0a0a0f;
        padding: 1;
    }
    .ai-controls {
        height: 8;
        border: solid #1a1a2e;
        padding: 1;
        margin-bottom: 1;
    }
    .ai-input {
        height: 12;
        border: solid #00ffff;
        padding: 1;
        margin-bottom: 1;
    }
    .ai-output {
        height: 20;
        border: solid #ff00ff;
        padding: 1;
    }
    .ai-history {
        height: 10;
        border: solid #1a1a2e;
        margin-top: 1;
    }
    """

    def compose(self) -> ComposeResult:
        yield Static(
            "[bold bright_cyan]◈ AI PANEL[/]  "
            "[dim]Powered by Groq → NVIDIA → OpenRouter → HuggingFace[/]"
        )

        # Controls
        with Container(classes="ai-controls"):
            yield Static("[bold bright_magenta]AI Action[/]")
            with Horizontal():
                yield Select(
                    [(label, val) for val, label in AI_ACTIONS],
                    id="ai-action",
                    value="analyze"
                )
                yield Button("🤖 Run AI", id="btn-run-ai", classes="success")
                yield Button("⊘ Clear", id="btn-clear-ai")
            yield Static(
                "[dim]AI Provider: Auto (Groq → NVIDIA NIM → OpenRouter → HuggingFace)[/]",
                id="ai-provider-status"
            )

        # Input
        with Container(classes="ai-input"):
            yield Static("[bold bright_cyan]INPUT[/]  [dim](Paste request, response, or vulnerability details)[/]")
            yield TextArea(
                "Paste your HTTP request/response or vulnerability details here...",
                id="ai-input-text"
            )

        # Output
        with Container(classes="ai-output"):
            yield Static("[bold bright_magenta]AI ANALYSIS[/]")
            yield ScrollableContainer(
                Static(
                    "[dim]AI analysis will appear here...[/]\n\n"
                    "[dim]Vexor AI can:[/]\n"
                    "[bright_cyan]• Analyze vulnerabilities in depth[/]\n"
                    "[bright_cyan]• Explain HTTP headers and responses[/]\n"
                    "[bright_cyan]• Suggest next attack steps[/]\n"
                    "[bright_cyan]• Generate smart payloads[/]\n"
                    "[bright_cyan]• Filter false positives[/]\n"
                    "[bright_cyan]• Write professional reports[/]",
                    id="ai-output-text"
                )
            )

        # History
        yield Static("[bold bright_magenta]◈ AI HISTORY[/]")
        yield Log(classes="ai-history", id="ai-history-log")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn-run-ai":
            self.run_ai()
        elif event.button.id == "btn-clear-ai":
            self.query_one("#ai-input-text", TextArea).clear()
            self.query_one("#ai-output-text", Static).update("[dim]Cleared.[/]")

    @work(exclusive=True)
    async def run_ai(self) -> None:
        """Run AI analysis"""
        action = self.query_one("#ai-action", Select).value
        input_text = self.query_one("#ai-input-text", TextArea).text
        output = self.query_one("#ai-output-text", Static)
        log = self.query_one("#ai-history-log", Log)

        if not input_text.strip():
            self.notify("Enter some input first", severity="error")
            return

        output.update("[bright_yellow]⟳ AI is analyzing...[/]")
        log.write_line(f"[*] Running AI action: {action}")

        try:
            from vexor.ai.client import AIClient
            client = AIClient()

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
            else:
                result = "Unknown action"

            # Format output beautifully
            formatted = (
                f"[bold bright_cyan]◈ AI ANALYSIS RESULT[/]\n"
                f"[dim]─────────────────────────────────[/]\n\n"
                f"{result}\n\n"
                f"[dim]─────────────────────────────────[/]\n"
                f"[dim]Action: {action} | Provider: Auto[/]"
            )
            output.update(formatted)
            log.write_line(f"[+] AI analysis complete")

        except Exception as e:
            output.update(f"[bright_red]AI Error: {str(e)}[/]")
            log.write_line(f"[!] AI error: {str(e)}")
