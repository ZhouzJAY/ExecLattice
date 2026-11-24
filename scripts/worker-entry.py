"""Entry for the standalone Windows worker used in LAN acceptance."""

import sys

from execlattice.cli import main

if len(sys.argv) == 1 or sys.argv[1] in {"--help", "-h"}:
    print("ExecLattice LAN Worker")
    print("Commands: init-worker, pair, worker. Add --help after a command for options.")
    raise SystemExit(0)
if sys.argv[1] not in {"init-worker", "pair", "worker"}:
    raise SystemExit("Use init-worker, pair, or worker.")

raise SystemExit(main())
