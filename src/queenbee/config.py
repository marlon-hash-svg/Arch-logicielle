"""Configuration : Builder qui valide tout dans `build()` et rend des `Settings` figés.

Les secrets ne viennent que de l'environnement, n'ont jamais de valeur par défaut et
n'apparaissent jamais dans `repr()`, `print()` ni les journaux.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Final, Self

MIN_KEY_BYTES: Final = 32
DEFAULT_DB: Final = "queenbee.db"
DEFAULT_BF_THRESHOLD: Final = 5


class ConfigError(Exception):
    """Configuration absente ou invalide : l'application refuse de démarrer."""


@dataclass(frozen=True, slots=True)
class Settings:
    """Configuration validée et figée de Queen Bee."""

    agent_hmac_key: bytes = field(repr=False)
    db_path: str = DEFAULT_DB
    bf_threshold: int = DEFAULT_BF_THRESHOLD


class SettingsBuilder:
    """Monteur : on assemble pièce par pièce, `build()` contrôle l'ensemble d'un coup."""

    def __init__(self) -> None:
        self._key: bytes | None = None
        self._db_path = DEFAULT_DB
        self._bf_threshold: object = DEFAULT_BF_THRESHOLD

    def __repr__(self) -> str:
        return "SettingsBuilder(<secret masqué>)"

    def hmac_key(self, key: bytes) -> Self:
        """Clé HMAC partagée avec les agents."""
        self._key = key
        return self

    def db_path(self, path: str) -> Self:
        """Chemin de la base des incidents."""
        self._db_path = path
        return self

    def bf_threshold(self, threshold: object) -> Self:
        """Seuil de la règle de force brute."""
        self._bf_threshold = threshold
        return self

    def build(self) -> Settings:
        """Valide l'ensemble et rend des `Settings` figés, ou lève ConfigError."""
        if self._key is None:
            raise ConfigError("clé HMAC des agents absente")
        if len(self._key) < MIN_KEY_BYTES:
            raise ConfigError(f"clé HMAC trop courte : {MIN_KEY_BYTES} octets minimum")
        if not self._db_path:
            raise ConfigError("chemin de base vide")
        threshold = self._bf_threshold
        if isinstance(threshold, bool) or not isinstance(threshold, int) or threshold < 1:
            raise ConfigError("seuil de force brute : entier >= 1 attendu")
        return Settings(self._key, self._db_path, threshold)


def settings_from_env(env: Mapping[str, str]) -> Settings:
    """Construit les `Settings` depuis un environnement (os.environ en production)."""
    raw_key = env.get("QUEENBEE_AGENT_KEY")
    if not raw_key:
        raise ConfigError("QUEENBEE_AGENT_KEY non défini")
    try:
        key = bytes.fromhex(raw_key)
    except ValueError:
        # from None : la trace ne doit rien exposer qui touche au secret.
        raise ConfigError("QUEENBEE_AGENT_KEY doit être en hexadécimal") from None
    raw_threshold = env.get("QUEENBEE_BF_THRESHOLD", str(DEFAULT_BF_THRESHOLD))
    try:
        threshold = int(raw_threshold)
    except ValueError as exc:
        raise ConfigError("QUEENBEE_BF_THRESHOLD doit être un entier") from exc
    return (
        SettingsBuilder()
        .hmac_key(key)
        .db_path(env.get("QUEENBEE_DB", DEFAULT_DB))
        .bf_threshold(threshold)
        .build()
    )
