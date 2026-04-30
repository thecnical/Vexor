"""
Vexor Comparer — Response Diff Tool
"""
import difflib
from typing import Optional


class Comparer:
    """Compare two HTTP responses"""

    def compare_text(self, text1: str, text2: str, context_lines: int = 3) -> dict:
        """Compare two text responses"""
        lines1 = text1.splitlines(keepends=True)
        lines2 = text2.splitlines(keepends=True)

        diff = list(difflib.unified_diff(
            lines1, lines2,
            fromfile='Response 1',
            tofile='Response 2',
            n=context_lines
        ))

        added = sum(1 for line in diff if line.startswith('+') and not line.startswith('+++'))
        removed = sum(1 for line in diff if line.startswith('-') and not line.startswith('---'))

        return {
            "diff": ''.join(diff),
            "added_lines": added,
            "removed_lines": removed,
            "similarity": difflib.SequenceMatcher(None, text1, text2).ratio(),
            "identical": text1 == text2,
        }

    def compare_headers(self, headers1: dict, headers2: dict) -> dict:
        """Compare response headers"""
        only_in_1 = {k: v for k, v in headers1.items() if k not in headers2}
        only_in_2 = {k: v for k, v in headers2.items() if k not in headers1}
        different = {
            k: (headers1[k], headers2[k])
            for k in headers1
            if k in headers2 and headers1[k] != headers2[k]
        }

        return {
            "only_in_first": only_in_1,
            "only_in_second": only_in_2,
            "different_values": different,
            "identical": not (only_in_1 or only_in_2 or different),
        }

    def highlight_diff(self, text1: str, text2: str) -> str:
        """Generate highlighted diff for TUI display"""
        result = []
        matcher = difflib.SequenceMatcher(None, text1.splitlines(), text2.splitlines())

        for tag, i1, i2, j1, j2 in matcher.get_opcodes():
            if tag == 'equal':
                for line in text1.splitlines()[i1:i2]:
                    result.append(f"  {line}")
            elif tag == 'replace':
                for line in text1.splitlines()[i1:i2]:
                    result.append(f"[bright_red]- {line}[/]")
                for line in text2.splitlines()[j1:j2]:
                    result.append(f"[bright_green]+ {line}[/]")
            elif tag == 'delete':
                for line in text1.splitlines()[i1:i2]:
                    result.append(f"[bright_red]- {line}[/]")
            elif tag == 'insert':
                for line in text2.splitlines()[j1:j2]:
                    result.append(f"[bright_green]+ {line}[/]")

        return '\n'.join(result)
