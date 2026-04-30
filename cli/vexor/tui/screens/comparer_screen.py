"""
Vexor Comparer Screen
"""
from textual.app import ComposeResult
from textual.widget import Widget
from textual.widgets import Static, Button, TextArea
from textual.containers import Horizontal, Vertical, Container, ScrollableContainer


class ComparerScreen(Widget):

    DEFAULT_CSS = """
    ComparerScreen {
        background: #0a0a0f;
        padding: 0 1;
    }
    .comparer-title { height: 2; color: #00ffff; text-style: bold; }
    .btn-row { height: 3; margin-bottom: 1; }
    .panels-row { height: 18; margin-bottom: 1; }
    .left-panel { border: solid #00ffff; padding: 1; }
    .right-panel { border: solid #ff00ff; padding: 1; }
    .text-area { height: 13; }
    .diff-section { border: solid #1a1a2e; padding: 1; height: 14; }
    .diff-scroll { height: 10; }
    .stats-row { height: 3; margin-top: 1; }
    """

    def compose(self) -> ComposeResult:
        yield Static(
            "[bold bright_cyan]◈ COMPARER[/]  [dim]Diff two responses[/]",
            classes="comparer-title"
        )

        with Horizontal(classes="btn-row"):
            yield Button("🔍 Compare", id="btn-compare", classes="success")
            yield Button("⊘ Clear All", id="btn-clear")
            yield Button("↕ Swap", id="btn-swap")

        with Horizontal(classes="panels-row"):
            with Container(classes="left-panel"):
                yield Static("[bold bright_cyan]RESPONSE 1[/]")
                yield TextArea(
                    "Paste first response here...",
                    id="compare-left",
                    classes="text-area"
                )

            with Container(classes="right-panel"):
                yield Static("[bold bright_magenta]RESPONSE 2[/]")
                yield TextArea(
                    "Paste second response here...",
                    id="compare-right",
                    classes="text-area"
                )

        with Container(classes="diff-section"):
            yield Static("[bold bright_magenta]◈ DIFF RESULT[/]", id="diff-stats")
            with ScrollableContainer(classes="diff-scroll"):
                yield Static(
                    "[dim]Click Compare to see differences...[/]",
                    id="diff-output"
                )

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn-compare":
            self._do_compare()
        elif event.button.id == "btn-clear":
            self.query_one("#compare-left", TextArea).clear()
            self.query_one("#compare-right", TextArea).clear()
            self.query_one("#diff-output", Static).update("[dim]Cleared[/]")
            self.query_one("#diff-stats", Static).update("[bold bright_magenta]◈ DIFF RESULT[/]")
        elif event.button.id == "btn-swap":
            left = self.query_one("#compare-left", TextArea)
            right = self.query_one("#compare-right", TextArea)
            l_text = left.text
            r_text = right.text
            left.load_text(r_text)
            right.load_text(l_text)

    def _do_compare(self) -> None:
        from vexor.core.comparer import Comparer
        c = Comparer()
        text1 = self.query_one("#compare-left", TextArea).text
        text2 = self.query_one("#compare-right", TextArea).text

        result = c.compare_text(text1, text2)
        similarity = int(result["similarity"] * 100)

        stats = (
            f"[bold bright_magenta]◈ DIFF RESULT[/]  "
            f"[bright_green]+{result['added_lines']} added[/]  "
            f"[bright_red]-{result['removed_lines']} removed[/]  "
            f"[dim]Similarity: {similarity}%[/]"
        )
        self.query_one("#diff-stats", Static).update(stats)

        if result["identical"]:
            self.query_one("#diff-output", Static).update(
                "[bright_green]✓ Responses are identical[/]"
            )
        else:
            highlighted = c.highlight_diff(text1, text2)
            self.query_one("#diff-output", Static).update(highlighted[:3000])
