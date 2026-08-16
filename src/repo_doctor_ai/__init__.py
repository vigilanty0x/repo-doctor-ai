"""Repo Doctor AI public API."""

from .config import Config, ConfigError, load_config
from .baseline import Baseline, BaselineEntry, BaselineError, load_baseline
from .models import Finding, Report, SuppressedFinding
from .registry import RegistryError, RulePlugin, RuleRegistry
from .scanner import Scanner

__all__ = [
    "Baseline",
    "BaselineEntry",
    "BaselineError",
    "Config",
    "ConfigError",
    "Finding",
    "RegistryError",
    "Report",
    "RulePlugin",
    "RuleRegistry",
    "Scanner",
    "SuppressedFinding",
    "load_baseline",
    "load_config",
]
__version__ = "0.2.0"
