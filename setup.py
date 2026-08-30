from pathlib import Path
from setuptools import find_packages, setup

README = Path("README.md").read_text(encoding="utf-8")

setup(
    name="mcp-sentinel-scanner",
    version="1.5.0",
    description="Security scanner for Model Context Protocol services",
    long_description=README,
    long_description_content_type="text/markdown",
    author="MCP Security Team",
    # Only ship the project's own packages: an unqualified find_packages(where=".")
    # would also install the "tests" directory as a top-level importable package.
    packages=find_packages(where=".", exclude=["tests", "tests.*"]),
    package_dir={"": "."},
    python_requires=">=3.9",
    install_requires=["colorama>=0.4.6", "tabulate>=0.9.0"],
    entry_points={
        "console_scripts": [
            # NOTE: do not register a "mcp-scan" console script here. That name
            # collides with Invariant Labs' unrelated MCP protocol scanner
            # (https://github.com/invariantlabs-ai/mcp-scan); whichever package
            # is installed last silently shadows the other's binary. Use
            # "mcp-sentinel" instead.
            "mcp-sentinel=scripts.sentinel_cli:main",
            "unified-scanner=scripts.sentinel_cli:main",
        ]
    },
    include_package_data=True,
)
