"""
Entry point: ``python -m dashboard``

Usage
-----
    python -m dashboard                          # localhost:5000
    python -m dashboard --host 0.0.0.0 --port 8080
    python -m dashboard --no-demo               # disable synthetic events
    python -m dashboard --debug
"""

from __future__ import annotations

import argparse
import sys

from .app import create_app


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="python -m dashboard",
        description="SentinelWeave live threat-metrics web dashboard",
    )
    parser.add_argument("--host",    default="127.0.0.1", help="Bind host (default: 127.0.0.1)")
    parser.add_argument("--port",    default=5000, type=int, help="Bind port (default: 5000)")
    parser.add_argument("--debug",   action="store_true",   help="Enable Flask debug mode")
    parser.add_argument("--no-demo", action="store_true",   help="Disable background demo simulator")
    args = parser.parse_args()

    demo = not args.no_demo
    app  = create_app(demo_mode=demo)

    print(f"SentinelWeave Dashboard  →  http://{args.host}:{args.port}/")
    if demo:
        print("Demo mode active — synthetic events are being generated.")
    print("Press Ctrl+C to stop.\n")

    app.run(host=args.host, port=args.port, debug=args.debug, threaded=True)


if __name__ == "__main__":
    main()
