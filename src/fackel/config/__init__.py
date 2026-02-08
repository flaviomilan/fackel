"""Configuration module for Fackel.

Centralizes all YAML configs, environment settings, and default values.
"""

from pathlib import Path

CONFIG_DIR = Path(__file__).parent

# Paths to config files
PLAYBOOKS_PATH = CONFIG_DIR / "playbooks.yaml"

__all__ = ["CONFIG_DIR", "PLAYBOOKS_PATH"]
