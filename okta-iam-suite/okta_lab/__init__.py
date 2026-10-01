"""Local Okta IAM lab configuration and API factory."""

from .config import OktaConfig, load_config


def create_app(*args, **kwargs):
    """Load the Flask API only when requested, avoiding CLI module side effects."""
    from .api import create_app as factory

    return factory(*args, **kwargs)


__all__ = ["OktaConfig", "create_app", "load_config"]
