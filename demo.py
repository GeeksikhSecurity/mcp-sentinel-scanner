"""Demonstration entry point for the MCP Sentinel Scanner."""
from __future__ import annotations

from pathlib import Path

from src import MCPSentinelScanner


def main() -> None:
    target = Path("tests")
    scanner = MCPSentinelScanner()
    result = scanner.scan(target)
    print(scanner.to_markdown(result))


if __name__ == "__main__":
    main()
