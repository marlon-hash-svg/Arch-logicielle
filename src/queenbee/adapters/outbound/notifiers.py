"""Notificateurs : diffusion des alertes, derrière le port `Notifier`."""

from __future__ import annotations

import logging

from queenbee.domain.model import Alert

_alerts_log = logging.getLogger("queenbee.alerts")


class MemoryNotifier:
    """Garde les alertes reçues en mémoire : famille « test »."""

    def __init__(self) -> None:
        self.received: list[Alert] = []

    def notify(self, alert: Alert) -> None:
        """Mémorise l'alerte."""
        self.received.append(alert)


class LogNotifier:
    """Publie l'alerte dans le journal `queenbee.alerts`, relayé vers le SIEM : famille « prod »."""

    def notify(self, alert: Alert) -> None:
        """Journalise l'alerte, sans contenu brut issu des journaux surveillés."""
        _alerts_log.warning(
            "alerte rule=%s ip=%s severity=%s", alert.rule, alert.source_ip, alert.severity.name
        )
