from pathlib import Path
from setuptools import find_packages, setup

README = Path("README.md").read_text(encoding="utf-8")

setup(
    name="mcp-sentinel-scanner",
    version="1.0.0",
    description="Security scanner for Model Context Protocol services",
    long_description=README,
    long_description_content_type="text/markdown",
    author="MCP Security Team",
    packages=find_packages(where="."),
    package_dir={"": "."},
    python_requires=">=3.9",
    install_requires=["colorama>=0.4.6", "tabulate>=0.9.0"],
    entry_points={
        "console_scripts": [
            "mcp-scan=scripts.sentinel_cli:main",
        ]
    },
    include_package_data=True,
)
