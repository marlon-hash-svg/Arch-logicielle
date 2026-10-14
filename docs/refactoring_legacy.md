# Refactoring du script hérité `legacy/log_watcher.py` (J1-A2)

- **Statut** : J1-A2 — 14/10/2026
- **Filet de sécurité** : `tests/test_legacy_characterization.py` (5 échecs depuis la même IP → 1 alerte ;
  en dessous du seuil ou IP dispersées → aucune alerte), écrit **avant** toute modification.

## 1. Relevé des problèmes

| # | Ligne(s) (version d'origine, commit `b1e0359`) | Problème | Type | Conséquence | Correction |
|---|---|---|---|---|---|
| P1 | 10 | `SMTP_PASSWORD = "Sup3rS3cret!"` en dur | Sécurité (CWE-798) · I | secret versionné dans Git = secret compromis, identique sur tous les postes | lu dans l'environnement au moment de l'usage ; jamais de valeur par défaut |
| P2 | 26 | `f"INSERT INTO incidents VALUES ('{ip}', '{user}')"` | Sécurité (injection SQL, CWE-89) · T, I | `ip` et `user` viennent du journal, donc de l'attaquant : il peut écrire dans la base ou la corrompre | requête paramétrée `execute("... VALUES (?, ?)", (ip, user))` ; à terme, port `IncidentRepository` |
| P3 | 20 | regex `Failed password for (.*) from (.*)`, gourmande, non ancrée, `re.search` | Sécurité (validation d'entrée) · T | capture `10.0.0.66 port 22 ssh2` comme « IP » (prouvé par la caractérisation) ; accepte n'importe quoi en nom | motif ancré et précis + `fullmatch`, puis revalidation par `SecurityEvent` (`ipaddress`) |
| P4 | 13-40 | `LogWatcher` lit, analyse, compte, détecte, stocke **et** alerte | SOLID · **S** (SRP) | six raisons de changer dans une seule classe ; impossible à tester sans fichier, base et SMTP | `SecurityEvent` (donnée), `BruteForceRule` (détection), `IncidentRepository` / `Notifier` (sorties) |
| P5 | 11, 30 | `DB = sqlite3.connect(...)` global à l'import ; `smtplib.SMTP("mail.local")` créé dans la méthode | SOLID · **D** (inversion de dépendances) | l'import crée un fichier ; aucun moyen d'injecter une doublure ; le test doit bricoler le module | dépendances reçues par le constructeur, typées par des `Protocol` (ports) |
| P6 | 34-40 | `report(kind)` : `if/elif` par format | SOLID · **O** (ouvert-fermé) | chaque nouveau format modifie la classe et risque de casser les autres | une stratégie de rendu par format (enregistrée dans un dictionnaire) |
| P7 | 38 | sortie HTML sans échappement | Sécurité (XSS, CWE-79) · T, I | une IP ou un nom piégé (`<script>`) s'exécute dans le navigateur de l'analyste | `html.escape`, ou mieux : rendu par un gabarit qui échappe |
| P8 | 19 | `open(self.path)` jamais fermé, lu sans limite de taille | Sécurité (DoS) · D | fuite de descripteurs ; une ligne géante consomme toute la mémoire | `with open(...)`, longueur de ligne bornée avant la regex |
| P9 | 24 | `== 5` codé en dur | SOLID · **O** / conception | seuil non configurable ; au-delà de 5 échecs, plus jamais d'alerte pour cette IP | `BruteForceRule(threshold)` validé (entier ≥ 1, pas un booléen) |
| P10 | 16, 23 | `self.counts` : dictionnaire mutable partagé, aucune donnée typée ni validée | Conception · T | un événement invalide (IP impossible, date sans fuseau) circule partout | objets immuables validés à la construction (`@dataclass(frozen=True, slots=True)`) |
| P11 | 40 | `report("json")` renvoie `str(dict)` | Correction | ce n'est pas du JSON valide (guillemets simples) | `json.dumps` |
| P12 | 30-32 | aucun `quit()`, aucune gestion d'erreur SMTP, connexion en clair | Sécurité · C, D | mot de passe envoyé sans TLS ; une panne SMTP fait planter toute la détection | notificateur derrière un port, TLS (`starttls`), erreur levée et journalisée |

## 2. Où est passé chaque morceau

| Responsabilité du script hérité | Nouvelle place | Couche |
|---|---|---|
| ligne → (user, ip) | `parse_sshd_line` (J2) | adapters/inbound |
| donnée d'un échec de connexion | `SecurityEvent` | domain |
| compter et comparer à 5 | `BruteForceRule.evaluate` | domain |
| ligne en base `incidents` | `Incident` + port `IncidentRepository` | domain + application |
| e-mail au SOC | `Alert` + port `Notifier` | domain + application |
| `report(kind)` | adaptateur de restitution (J2) | adapters/outbound |

## 3. Correctifs appliqués au script hérité (commits `fix:` séparés du refactoring)

1. SQL paramétré (P2).
2. Secret lu dans l'environnement `QUEENBEE_SMTP_PASSWORD` (P1).
3. Regex ancrée et précise (P3) : la caractérisation est mise à jour **dans le même commit**,
   car ce changement de comportement est voulu (l'IP capturée devient `10.0.0.66`).
