#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
╔══════════════════════════════════════════════════════════╗
║              OSINT ANALYZER v2.0                          ║
║      Open Source Intelligence Tool — No API Keys         ║
╚══════════════════════════════════════════════════════════╝
"""

import argparse
import sys
import os
from datetime import datetime

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, BASE_DIR)

from utils.display           import Display
from utils.reporter          import Reporter
from modules.detector        import InputDetector
from modules.username        import UsernameAnalyzer
from modules.email_analyzer  import EmailAnalyzer
from modules.domain_analyzer import DomainAnalyzer
from modules.person_analyzer import PersonAnalyzer
from modules.ip_analyzer     import IPAnalyzer

BANNER = r"""
  ██████╗ ███████╗██╗███╗   ██╗████████╗
 ██╔═══██╗██╔════╝██║████╗  ██║╚══██╔══╝
 ██║   ██║███████╗██║██╔██╗ ██║   ██║
 ██║   ██║╚════██║██║██║╚██╗██║   ██║
 ╚██████╔╝███████║██║██║ ╚████║   ██║
  ╚═════╝ ╚══════╝╚═╝╚═╝  ╚═══╝   ╚═╝
      Open Source Intelligence Tool v2.0
        No API Keys — No Registration
"""


def parse_args():
    parser = argparse.ArgumentParser(
        description="OSINT Analyzer — Open Source Intelligence Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python osint.py -t johndoe
  python osint.py -t user@example.com
  python osint.py -t example.com
  python osint.py -t "John Doe"
  python osint.py -t 8.8.8.8
  python osint.py -t johndoe -o report.html
  python osint.py -t johndoe --threads 30
        """
    )
    parser.add_argument("-t", "--target", required=True,
                        help="Target: username / email / domain / IP / full name")
    parser.add_argument("--type", choices=["auto","username","email","domain","person","ip","url"],
                        default="auto", help="Input type (default: auto-detect)")
    parser.add_argument("-o", "--output", default=None,
                        help="Save report: report.json / report.html / report.txt")
    parser.add_argument("-m", "--modules", default=None,
                        help="Run specific modules only (comma-separated)")
    parser.add_argument("--timeout",  type=int, default=10,
                        help="Request timeout in seconds (default: 10)")
    parser.add_argument("--threads",  type=int, default=15,
                        help="Parallel threads (default: 15)")
    parser.add_argument("--proxy",    default=None,
                        help="Proxy: socks5://127.0.0.1:9050")
    parser.add_argument("--no-color", action="store_true",
                        help="Disable terminal colors")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Show extra details")
    return parser.parse_args()


def main():
    args    = parse_args()
    display = Display(no_color=args.no_color)

    display.banner(BANNER)
    display.info(f"Target   : {args.target}")
    display.info(f"Time     : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    if args.proxy:
        display.info(f"Proxy    : {args.proxy}")
    display.separator()

    detector    = InputDetector()
    target_type = detector.detect(args.target) if args.type == "auto" else args.type
    display.info(f"Detected type : {target_type}")
    display.separator()

    config = {
        "timeout": args.timeout,
        "threads": args.threads,
        "verbose": args.verbose,
        "proxy":   args.proxy,
        "modules": args.modules.split(",") if args.modules else None,
    }

    results = {
        "target":    args.target,
        "type":      target_type,
        "timestamp": datetime.now().isoformat(),
        "modules":   {}
    }

    try:
        if target_type == "username":
            results["modules"].update(UsernameAnalyzer(display, config).analyze(args.target))
        elif target_type == "email":
            results["modules"].update(EmailAnalyzer(display, config).analyze(args.target))
        elif target_type in ("domain", "url"):
            results["modules"].update(DomainAnalyzer(display, config).analyze(args.target))
        elif target_type == "person":
            results["modules"].update(PersonAnalyzer(display, config).analyze(args.target))
        elif target_type == "ip":
            results["modules"].update(IPAnalyzer(display, config).analyze(args.target))
        else:
            display.warning(f"Unknown type: {target_type} — treating as username")
            results["modules"].update(UsernameAnalyzer(display, config).analyze(args.target))

    except KeyboardInterrupt:
        display.warning("\n[!] Interrupted by user (Ctrl+C)")
        sys.exit(0)
    except Exception as e:
        display.error(f"Unexpected error: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)

    reporter = Reporter(display)
    reporter.print_summary(results)

    if args.output:
        reporter.save(results, args.output)
        display.success(f"Report saved : {args.output}")

    display.separator()
    display.success("Analysis complete!")
    print()


if __name__ == "__main__":
    main()