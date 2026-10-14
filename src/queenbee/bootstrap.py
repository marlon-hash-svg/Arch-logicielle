"""Composition root : le seul endroit qui connaît les classes concrètes et les assemble.

Remplace le Singleton et les globales du script hérité : `build_app` crée chaque objet
une fois et le passe explicitement à qui en a besoin.
"""

from __future__ import annotations

from collections.abc import Sequence

from queenbee.application.services import DetectionService
from queenbee.config import Settings
from queenbee.domain.model import Incident, SecurityEvent
from queenbee.domain.rules import BruteForceRule
from queenbee.factories import ComponentFactory, ProdFactory


class QueenBee:
    """Façade : une seule porte d'entrée vers les cas d'usage."""

    def __init__(self, detection: DetectionService) -> None:
        self._detection = detection

    def ingest(self, events: Sequence[SecurityEvent]) -> list[Incident]:
        """Analyse un lot d'événements validés et renvoie les incidents ouverts."""
        return self._detection.ingest(events)


def build_app(settings: Settings, factory: ComponentFactory | None = None) -> QueenBee:
    """Assemble Queen Bee à partir de réglages validés et d'une famille de composants."""
    components = factory if factory is not None else ProdFactory(settings.db_path)
    detection = DetectionService(
        BruteForceRule(settings.bf_threshold),
        components.repository(),
        [components.notifier()],
    )
    return QueenBee(detection)
