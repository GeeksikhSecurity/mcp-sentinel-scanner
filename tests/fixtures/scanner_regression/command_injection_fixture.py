"""Regression fixture: subprocess.run(..., shell=True) with variable input -> command_injection."""
import subprocess


def run_version(cmd: str) -> int:
    # Intentionally vulnerable for scanner regression: shell=True with variable
    return subprocess.run([cmd, "--version"], check=True, capture_output=True, shell=True).returncode
