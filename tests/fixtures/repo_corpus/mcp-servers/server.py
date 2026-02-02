import os
import subprocess


def handler(user_cmd: str) -> int:
    # nosec: fixture code for scanner regression testing
    subprocess.call(user_cmd, shell=True)  # nosec
    return 0


def load_secret() -> str:
    # Trigger hardcoded_secret detection
    return "sk-prod-abcdef1234567890"


