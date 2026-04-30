"""
Vexor AI Panel Screen — Fixed responsive layout
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

    DEFAULT_CSS = """
    AIScreen {
        background: #0a0a0f;
        padding: 0 1;
        overflow-y: auto;
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
    .input-section {
        border: solid #00ffff;
        padding: 1;
        margin-bottom: 1;
        height: 12;
    }
    .input-textarea {
        height: 8;
    }
    .output-section {
        border: solid #ff00ff;
        padding: 1;
        margin-bottom: 1;
        height: 16;
    }
    .output-scroll {
        height: 12;
    }
    .history-log {
        height: 6;
        border: solid #1a1a2e;
    }
    """

    def compose(self) -> ComposeResult:
        yield Static(
            "[bold bright_cyan]◈ AI PANEL[/]  [dim]Groq → NVIDIA → OpenRouter → HuggingFace[/]",
            classes="ai-title"
        )

        with Container(classes="controls-section"):
            with Horizontal(classes="action-row"):
                yield Select(
                    [(label, val) for val, label in AI_ACTIONS],
                    id="ai-action",
                    value="analyze"
                )
                yield Button("🤖 Run AI", id="btn-run-ai", classes="success")
                yield Button("⊘ Clear", id="btn-clear-ai")
            yield Static(
                "[dim]Auto: Groq → NVIDIA NIM → OpenRouter → HuggingFace[/]",
                id="ai-provider-status"
            )

        with Container(classes="input-section"):
            yield Static("[bold bright_cyan]INPUT[/]  [dim](Paste request, response, or details)[/]")
            yield TextArea(
                "Paste your HTTP request/response or vulnerability details here...",
                id="ai-input-text",
                classes="input-textarea"
            )

        with Container(classes="output-section"):
            yield Static("[bold bright_magenta]AI ANALYSIS[/]")
            with ScrollableContainer(classes="output-scroll"):
                yield Static(
                    "[dim]AI analysis will appear here...[/]\n\n"
                    "[bright_cyan]• Analyze vulnerabilities[/]\n"
                    "[bright_cyan]• Explain HTTP headers[/]\n"
                    "[bright_cyan]• Suggest attack steps[/]\n"
                    "[bright_cyan]• Generate smart payloads[/]\n"
                    "[bright_cyan]• Filter false positives[/]\n"
                    "[bright_cyan]• Write professional reports[/]",
                    id="ai-output-text"
                )

        yield Static("[bold bright_magenta]◈ AI HISTORY[/]")
        yield Log(classes="history-log", id="ai-history-log")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn-run-ai":
            self.run_ai()
        elif event.button.id == "btn-clear-ai":
            try:
                self.query_one("#ai-input-text", TextArea).clear()
                self.query_one("#ai-output-text", Static).update("[dim]Cleared.[/]")
            except Exception:
                pass

    @work(exclusive=True)
    async def run_ai(self) -> None:
        action = self.query_one("#ai-action", Select).value
        input_text = self.query_one("#ai-input-text", TextArea).text
        output = self.query_one("#ai-output-text", Static)
        log = self.query_one("#ai-history-log", Log)

        if not input_text.strip():
            self.notify("Enter some input first", severity="error")
            return

        output.update("[bright_yellow]⟳ AI analyzing...[/]")
        log.write_line(f"[*] Running: {action}")

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

            formatted = (
                f"[bold bright_cyan]◈ AI RESULT[/]\n"
                f"[dim]─────────────────────────────[/]\n\n"
                f"{result}\n\n"
                f"[dim]Action: {action}[/]"
            )
            output.update(formatted)
            log.write_line(f"[+] Done")

        except Exception as e:
            output.update(f"[bright_red]Error: {str(e)}[/]")
            log.write_line(f"[!] Error: {str(e)}")
