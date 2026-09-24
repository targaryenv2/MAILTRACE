"""Deterministic detection rules and log-odds scoring."""

from .engine import (  # noqa: F401
    build_verdict, check_relay, confidence, levenshtein, logistic, ml_signal,
    risk_level, run_rules, score, skeleton,
)
