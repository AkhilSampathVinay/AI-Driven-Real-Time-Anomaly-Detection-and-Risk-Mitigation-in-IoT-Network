"""Command line entry point.

    iot-guard demo                 GUI with simulated IoT network + attacks (no root needed)
    iot-guard live                 GUI on your real network (needs root / Administrator)
    iot-guard analyze FILE.pcap    headless threat report for a capture file
    iot-guard generate FILE.pcap   write the synthetic attack scenario to a PCAP
    iot-guard evaluate             precision / recall on labelled synthetic traffic
"""

import argparse
import logging
import sys

from . import __version__


def _cmd_demo(args):
    from .gui.app import run_demo
    run_demo(speed=args.speed)


def _cmd_live(args):
    from .gui.app import run_live
    run_live(enforce=args.enforce)


def _cmd_analyze(args):
    from .report import analyze_pcap
    print(analyze_pcap(args.pcap, use_ml=not args.no_ml).render())


def _cmd_generate(args):
    from .simulator import Scenario, write_pcap
    n = write_pcap(args.out, Scenario(attacks=not args.benign_only, seed=args.seed))
    print(f"Wrote {n:,} packets to {args.out}")


def _cmd_evaluate(args):
    from .report import evaluate
    print(evaluate(seed=args.seed))


def main(argv=None) -> int:
    p = argparse.ArgumentParser(
        prog="iot-guard",
        description="AI-driven real-time anomaly detection and risk mitigation for IoT networks")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    p.add_argument("-v", "--verbose", action="store_true")
    sub = p.add_subparsers(dest="command", required=True)

    s = sub.add_parser("demo", help="GUI with a simulated network (safe, no root)")
    s.add_argument("--speed", type=float, default=2.0, help="replay speed multiplier")
    s.set_defaults(func=_cmd_demo)

    s = sub.add_parser("live", help="GUI on the real network (root/admin)")
    s.add_argument("--enforce", action="store_true",
                   help="actually change firewall rules (default: dry-run, log only)")
    s.set_defaults(func=_cmd_live)

    s = sub.add_parser("analyze", help="threat report for a PCAP file")
    s.add_argument("pcap")
    s.add_argument("--no-ml", action="store_true", help="rules only (faster)")
    s.set_defaults(func=_cmd_analyze)

    s = sub.add_parser("generate", help="write synthetic traffic to a PCAP")
    s.add_argument("out")
    s.add_argument("--benign-only", action="store_true")
    s.add_argument("--seed", type=int, default=7)
    s.set_defaults(func=_cmd_generate)

    s = sub.add_parser("evaluate", help="measure detection accuracy")
    s.add_argument("--seed", type=int, default=7)
    s.set_defaults(func=_cmd_evaluate)

    args = p.parse_args(argv)
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.WARNING,
                        format="%(levelname)s %(name)s: %(message)s")
    logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
    args.func(args)
    return 0


if __name__ == "__main__":
    sys.exit(main())
