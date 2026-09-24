"""Alerting and incident notification package for MailTrace."""

from .notifier import dispatch_alert, send_discord_alert, send_test_alert

__all__ = ["dispatch_alert", "send_discord_alert", "send_test_alert"]
