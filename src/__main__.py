"""Allow running the scanner as ``python -m src`` (development) or ``python -m mcp_sentinel_scanner`` (installed)."""
from __future__ import annotations

import sys

from scripts.sentinel_cli import main

sys.exit(main())
