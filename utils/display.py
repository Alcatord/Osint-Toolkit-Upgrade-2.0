#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import sys
import os


class Colors:
    RED     = '\033[91m'
    GREEN   = '\033[92m'
    YELLOW  = '\033[93m'
    BLUE    = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN    = '\033[96m'
    WHITE   = '\033[97m'
    BOLD    = '\033[1m'
    DIM     = '\033[2m'
    RESET   = '\033[0m'


class Display:
    def __init__(self, no_color=False):
        if sys.platform == "win32":
            os.system("color")
            try:
                import ctypes
                kernel32 = ctypes.windll.kernel32
                kernel32.SetConsoleMode(kernel32.GetStdHandle(-11), 7)
            except Exception:
                pass
        self.no_color = no_color

    def _c(self, color, text):
        if self.no_color:
            return str(text)
        return f"{color}{text}{Colors.RESET}"

    def banner(self, text):
        print(self._c(Colors.CYAN + Colors.BOLD, text))

    def info(self, msg):
        print(f"{self._c(Colors.BLUE, '[*]')} {msg}")

    def success(self, msg):
        print(f"{self._c(Colors.GREEN, '[+]')} {msg}")

    def warning(self, msg):
        print(f"{self._c(Colors.YELLOW, '[!]')} {msg}")

    def error(self, msg):
        print(f"{self._c(Colors.RED, '[-]')} {msg}")

    def found(self, msg):
        print(f"{self._c(Colors.GREEN + Colors.BOLD, '[✓]')} {self._c(Colors.GREEN, msg)}")

    def not_found(self, msg):
        print(f"{self._c(Colors.DIM, '[✗]')} {self._c(Colors.DIM, msg)}")

    def section(self, title):
        print()
        pad = max(0, 50 - len(title))
        print(self._c(Colors.MAGENTA + Colors.BOLD, f"┌─ {title} {'─' * pad}"))

    def section_end(self):
        print(self._c(Colors.MAGENTA, f"└{'─' * 55}"))

    def separator(self):
        print(self._c(Colors.DIM, "─" * 60))

    def key_value(self, key, value, indent=0):
        pad = "  " * indent
        print(f"{pad}{self._c(Colors.CYAN, key + ':')} {value}")

    def table(self, headers, rows):
        if not rows:
            print(self._c(Colors.DIM, "  (no results)"))
            return

        widths = [len(str(h)) for h in headers]
        for row in rows:
            for i, cell in enumerate(row):
                if i < len(widths):
                    widths[i] = max(widths[i], len(str(cell)))

        # Header
        header_parts = []
        for i, h in enumerate(headers):
            w   = widths[i] if i < len(widths) else 10
            txt = self._c(Colors.BOLD + Colors.WHITE, str(h).ljust(w))
            header_parts.append(txt)
        print("  " + " │ ".join(header_parts))

        # Separator
        sep = "  " + "─┼─".join("─" * w for w in widths)
        print(self._c(Colors.DIM, sep))

        # Rows
        for row in rows:
            parts = []
            for i, cell in enumerate(row):
                w = widths[i] if i < len(widths) else 10
                s = str(cell)
                if s.lower() in ("found", "open", "yes", "active", "✓"):
                    parts.append(self._c(Colors.GREEN, s.ljust(w)))
                elif s.lower() in ("not found", "closed", "no", "inactive", "✗"):
                    parts.append(self._c(Colors.RED, s.ljust(w)))
                elif s.lower() in ("unknown", "error", "?"):
                    parts.append(self._c(Colors.YELLOW, s.ljust(w)))
                else:
                    parts.append(s.ljust(w))
            print("  " + " │ ".join(parts))

    def progress(self, current, total, prefix="Progress"):
        if total == 0:
            return
        bar_len = 25
        filled  = int(bar_len * current / total)
        pct     = int(100 * current / total)
        bar     = (self._c(Colors.GREEN, "█" * filled) +
                   self._c(Colors.DIM,   "░" * (bar_len - filled)))
        print(f"\r  {prefix} [{bar}] {pct:3d}% ({current}/{total})  ",
              end="", flush=True)
        if current >= total:
            print()

    def highlight(self, text):
        return self._c(Colors.YELLOW + Colors.BOLD, text)

    def bold(self, text):
        return self._c(Colors.BOLD, text)

    def dim(self, text):
        return self._c(Colors.DIM, text)