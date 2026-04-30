"""
Vexor Decoder Screen
"""
from textual.app import ComposeResult
from textual.widget import Widget
from textual.widgets import Static, Button, TextArea, Select
from textual.containers import Horizontal, Vertical, Container


FORMATS = [
    ("base64", "Base64"),
    ("url", "URL Encode"),
    ("html", "HTML Entities"),
    ("hex", "Hex"),
    ("binary", "Binary"),
    ("md5", "MD5 Hash"),
    ("sha1", "SHA1 Hash"),
    ("sha256", "SHA256 Hash"),
    ("rot13", "ROT13"),
    ("reverse", "Reverse"),
]


class DecoderScreen(Widget):

    DEFAULT_CSS = """
    DecoderScreen {
        background: #0a0a0f;
        padding: 0 1;
    }
    .decoder-title { height: 2; color: #00ffff; text-style: bold; }
    .controls-row { height: 3; margin-bottom: 1; }
    .input-section { border: solid #00ffff; padding: 1; height: 12; margin-bottom: 1; }
    .output-section { border: solid #ff00ff; padding: 1; height: 12; margin-bottom: 1; }
    .text-area { height: 8; }
    .auto-section { border: solid #1a1a2e; padding: 1; height: 8; }
    """

    def compose(self) -> ComposeResult:
        yield Static(
            "[bold bright_cyan]◈ DECODER[/]  [dim]Encode / Decode / Hash[/]",
            classes="decoder-title"
        )

        with Horizontal(classes="controls-row"):
            yield Select(
                [(label, val) for val, label in FORMATS],
                id="decode-format", value="base64"
            )
            yield Button("▶ Encode", id="btn-encode", classes="success")
            yield Button("◀ Decode", id="btn-decode")
            yield Button("🔍 Auto Detect", id="btn-auto")
            yield Button("⊘ Clear", id="btn-clear")

        with Container(classes="input-section"):
            yield Static("[bold bright_cyan]INPUT[/]")
            yield TextArea("Paste text here...", id="decoder-input", classes="text-area")

        with Container(classes="output-section"):
            yield Static("[bold bright_magenta]OUTPUT[/]")
            yield TextArea("Result will appear here...", id="decoder-output", classes="text-area")

        with Container(classes="auto-section"):
            yield Static("[bold bright_magenta]◈ AUTO DETECT RESULTS[/]")
            yield Static("[dim]Click 'Auto Detect' to identify encoding...[/]", id="auto-results")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        from vexor.core.decoder import Decoder
        d = Decoder()
        inp = self.query_one("#decoder-input", TextArea).text.strip()
        fmt = self.query_one("#decode-format", Select).value
        out = self.query_one("#decoder-output", TextArea)
        auto = self.query_one("#auto-results", Static)

        if event.button.id == "btn-encode":
            result = d.encode(inp, fmt)
            out.load_text(result)
        elif event.button.id == "btn-decode":
            result = d.decode(inp, fmt)
            out.load_text(result)
        elif event.button.id == "btn-auto":
            results = d.auto_detect(inp)
            if results:
                text = "\n".join(
                    f"[bright_cyan]{r['format']}[/]: {r['result'][:80]}"
                    for r in results
                )
                auto.update(text)
            else:
                auto.update("[dim]Could not auto-detect encoding[/]")
        elif event.button.id == "btn-clear":
            self.query_one("#decoder-input", TextArea).clear()
            out.clear()
            auto.update("[dim]Cleared[/]")
