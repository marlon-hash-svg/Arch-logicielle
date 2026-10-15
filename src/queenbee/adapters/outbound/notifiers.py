"""Notificateurs : diffusion des alertes, derrière le port `Notifier`."""

from __future__ import annotations

import logging
import time
from collections.abc import Callable

from queenbee.application.ports import Notifier
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


_audit = logging.getLogger("queenbee.audit")


class AuditedNotifier:
    """Décorateur : trace chaque alerte dans `queenbee.audit` avant de la transmettre."""

    def __init__(self, inner: Notifier) -> None:
        self._inner = inner

    def notify(self, alert: Alert) -> None:
        """Journalise l'alerte (preuve), puis délègue."""
        _audit.info(
            "alerte rule=%s ip=%s severity=%s", alert.rule, alert.source_ip, alert.severity.name
        )
        self._inner.notify(alert)


class RateLimitedNotifier:
    """Décorateur : au plus `max_per_window` alertes par fenêtre ; l'excédent est compté."""

    def __init__(
        self,
        inner: Notifier,
        max_per_window: int,
        window_s: float,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        if isinstance(max_per_window, bool) or max_per_window < 1 or window_s <= 0:
            raise ValueError("limite et fenêtre doivent être strictement positives")
        self._inner = inner
        self._max = max_per_window
        self._window_s = window_s
        self._clock = clock
        self._window_start = clock()
        self._sent_in_window = 0
        self.dropped = 0

    def notify(self, alert: Alert) -> None:
        """Transmet l'alerte si le quota de la fenêtre le permet, sinon la compte comme rejetée."""
        now = self._clock()
        if now - self._window_start >= self._window_s:
            self._window_start, self._sent_in_window = now, 0
        if self._sent_in_window >= self._max:
            self.dropped += 1
            if self.dropped == 1 or self.dropped % 100 == 0:  # visible sans inonder le journal
                _audit.warning("alertes écartées par le limiteur total=%d", self.dropped)
            return
        self._sent_in_window += 1
        self._inner.notify(alert)
