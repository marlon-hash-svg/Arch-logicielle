# Note de rendu J1 — ce qui est vert, ce qui reste rouge et pourquoi

- **Date** : 14/10/2026 · **Étiquette** : `j1-rendu`
- Environnement : Windows (sans `make`), Python 3.12, commandes du guide pratique J1 lancées une par une.

## Vert sur le périmètre J1

| Porte | Commande | Résultat |
|---|---|---|
| Style | `ruff check src tests/test_domain.py tests/test_creational.py tests/test_legacy_characterization.py tests/test_creational_abuse.py` et `ruff format --check .` | aucune erreur |
| Typage | `mypy` (strict) | 0 erreur, 14 fichiers |
| Tests | `pytest tests/test_domain.py tests/test_creational.py tests/test_legacy_characterization.py tests/test_creational_abuse.py --cov=src/queenbee --cov-fail-under=90` | 52 tests verts, couverture 100 % |
| Sécurité du code | `bandit -q -r src -c pyproject.toml` | aucune alerte |
| Dépendances | `pip-audit` | aucune vulnérabilité connue (après mise à jour de `pip` dans `.venv`) |
| Architecture | `PYTHONPATH=src lint-imports` | 1 kept, 0 broken |

## Rouge, et pourquoi c'est attendu

`make check` sur **tout** le dépôt (et donc la CI GitHub) reste rouge jusqu'au J2 :

- `tests/test_services.py` et `tests/test_adapters.py` importent des modules qui sont le travail du **J2**
  (`application/access.py`, `IncidentService`, `Principal`, notificateurs audité et limité, `adapters/inbound/*`,
  pare-feu et commandes) : erreur de collecte `ModuleNotFoundError`.
- Pour la même raison, `ruff` signale `I001` (ordre des imports) sur ces deux fichiers de tests : tant qu'un
  module n'existe pas, ruff le classe comme bibliothèque externe. **On ne corrige pas en modifiant les tests**
  (règle du module) : l'erreur disparaît d'elle-même quand le module est créé, comme vérifié sur
  `test_domain.py` et `test_creational.py`.
- `python -m pytest -k secret` sur tout le dépôt s'interrompt à la collecte de `test_adapters.py` (même cause) ;
  `python -m pytest -k secret tests/test_creational_abuse.py` est vert.

## Dette assumée

- `SqliteIncidentRepository` crée sa table (`CREATE TABLE IF NOT EXISTS`) : le compte applicatif a donc des droits DDL.
  À déplacer dans un script de migration au J3 (compte applicatif sans DDL).
- `legacy/log_watcher.py` est corrigé (SQL, secret, regex) mais garde ses autres défauts (P4 à P12 de
  `docs/refactoring_legacy.md`) : il est remplacé par `src/queenbee`, pas destiné à être maintenu.
- Le faux mot de passe `Sup3rS3cret!` du code de départ reste dans l'historique Git : dans un vrai projet, il serait révoqué.
