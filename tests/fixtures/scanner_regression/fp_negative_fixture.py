"""Regression fixture: variable names only (no quoted secrets) -> should NOT trigger hardcoded_secret."""
# Scanner should not flag variable/identifier names; only quoted secret values.


def example(resource_key: str, access_token: str) -> None:
    template_key = add_resource_prefix(resource_key)
    _ = access_token
    return None


def add_resource_prefix(name: str) -> str:
    return f"prefix_{name}"
