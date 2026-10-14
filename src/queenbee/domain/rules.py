"""Règles de détection : Strategy (règle interchangeable), Composite (N règles = une), Factory.

La fabrique ne crée que des règles enregistrées : jamais de getattr ni d'importlib sur une chaîne
reçue de l'extérieur.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from typing import ClassVar, Final, Protocol

from queenbee.domain.model import Alert, DomainError, SecurityEvent, Severity


class DetectionRule(Protocol):
    """Contrat d'une règle de détection : des événements en entrée, des alertes en sortie."""

    def evaluate(self, events: Sequence[SecurityEvent]) -> list[Alert]:
        """Renvoie une alerte par source qui enfreint la règle."""
        ...


def _check_threshold(value: object) -> int:
    # bool est un sous-type d'int : True passerait pour 1 sans ce test explicite.
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise DomainError("seuil invalide : entier >= 1 attendu")
    return value


def _count_by_ip(events: Sequence[SecurityEvent], action: str) -> Counter[str]:
    return Counter(e.source_ip for e in events if e.action == action)


@dataclass(frozen=True, slots=True)
class BruteForceRule:
    """Alerte quand une même IP cumule au moins `threshold` échecs de connexion."""

    threshold: int = 5
    name: ClassVar[str] = "brute_force"

    def __post_init__(self) -> None:
        _check_threshold(self.threshold)

    def evaluate(self, events: Sequence[SecurityEvent]) -> list[Alert]:
        """Une alerte HIGH par IP ayant atteint le seuil d'échecs."""
        return [
            Alert(self.name, ip, Severity.HIGH, f"{n} échecs de connexion")
            for ip, n in _count_by_ip(events, "login_failed").items()
            if n >= self.threshold
        ]


@dataclass(frozen=True, slots=True)
class PortScanRule:
    """Alerte quand une même IP sonde au moins `threshold` ports."""

    threshold: int = 10
    name: ClassVar[str] = "port_scan"

    def __post_init__(self) -> None:
        _check_threshold(self.threshold)

    def evaluate(self, events: Sequence[SecurityEvent]) -> list[Alert]:
        """Une alerte MEDIUM par IP ayant atteint le seuil de sondes."""
        return [
            Alert(self.name, ip, Severity.MEDIUM, f"{n} ports sondés")
            for ip, n in _count_by_ip(events, "port_probe").items()
            if n >= self.threshold
        ]


@dataclass(frozen=True, slots=True)
class RuleSet:
    """Composite : un ensemble de règles se comporte comme une seule ; aucune n'est sautée."""

    rules: tuple[DetectionRule, ...]

    def evaluate(self, events: Sequence[SecurityEvent]) -> list[Alert]:
        """Concatène les alertes de toutes les règles."""
        return [alert for rule in self.rules for alert in rule.evaluate(events)]


_REGISTRY: Final[Mapping[str, Callable[[int], DetectionRule]]] = {
    "brute_force": BruteForceRule,
    "port_scan": PortScanRule,
}
_SPEC_KEYS: Final = frozenset({"kind", "threshold"})


def build_rule(spec: Mapping[str, object]) -> DetectionRule:
    """Fabrique une règle depuis une configuration externe ; tout nom non enregistré est refusé."""
    if set(spec) != _SPEC_KEYS:
        raise DomainError("spécification de règle : champs 'kind' et 'threshold' attendus")
    kind, threshold = spec["kind"], spec["threshold"]
    if not isinstance(kind, str) or kind not in _REGISTRY:
        raise DomainError("type de règle inconnu")
    return _REGISTRY[kind](_check_threshold(threshold))
