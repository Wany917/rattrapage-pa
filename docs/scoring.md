# Corrélation et scoring (Phase 5)

## Corrélation (`correlation.py`)

Un même défaut est souvent remonté par plusieurs analyses. On les fusionne par
**fonction**, en réconciliant les classes : deux findings d'une même fonction
fusionnent si leur classe est identique, ou si l'une est `UNKNOWN`. Ce dernier
cas est essentiel pour le **format string** : le dynamique n'y voit qu'un SEGV
non typé, alors que le statique lui donne sa classe. Le finding fusionné :

- garde la **confiance la plus haute** (un crash CONFIRMED l'emporte sur un
  indice statique) ;
- conserve l'**offset statique** connu (le dynamique n'en fournit pas) ;
- récupère l'**exploitabilité** dynamique ;
- combine **sources** et **preuves**.

Exemple réel : sur `01`, `dangerous_funcs` (POSSIBLE) + `taint` (PROBABLE) +
`casr` (CONFIRMED) donnent **une seule** entrée CONFIRMED, source
`dangerous_funcs+taint+casr`.

## Scoring (`scoring.py`)

Décision de projet : règles -> niveau + score 0-100. Formule documentée :

    score = impact(classe) x confiance x exploitabilité(CASR) x mitigations(protections)

| Facteur | Valeurs |
|---------|---------|
| impact(classe) | stack BOF 90, format string 85, heap BOF 80, UAF 80, double free 70, int overflow 60, unknown 40 |
| confiance | POSSIBLE 0.6, PROBABLE 0.8, CONFIRMED 1.0 |
| exploitabilité (CASR) | EXPLOITABLE 1.0, PROBABLY 0.85, NOT 0.6, UNKNOWN 0.8 |
| mitigations | réduction par protection active pertinente pour la classe (voir table) |

Table de mitigation (réduction soustraite, plancher du facteur = 0.3) :

| Classe | Protections qui réduisent |
|--------|---------------------------|
| stack BOF | canary -0.35, fortify -0.25, pie -0.10, nx -0.10 |
| format string | fortify -0.40, relro -0.15, pie -0.10 |
| heap BOF | nx -0.10, fortify -0.10 |
| use-after-free | nx -0.10, pie -0.10 |
| double free | nx -0.05 |
| integer overflow | canary -0.15, fortify -0.15 |

Niveaux : CRITICAL >= 85, HIGH >= 65, MEDIUM >= 40, LOW >= 20, INFO sinon.

## Résultats (profils `_vuln`)

| Vuln | Sévérité | Classe |
|------|----------|--------|
| 01_stack_bof | CRITICAL 90 | stack_buffer_overflow |
| 02_heap_bof | HIGH 80 | heap_buffer_overflow |
| 03_format_string | MEDIUM 51 | format_string |
| 04_integer_overflow | HIGH 80 | heap_buffer_overflow |
| 05_use_after_free | MEDIUM 48 | use_after_free |
| 06_double_free | MEDIUM 42 | double_free |

Impact des protections (même vulnérabilité `01`, deux profils) :

| Profil | Protections actives | Score |
|--------|---------------------|-------|
| `_vuln` | aucune | CRITICAL 90 |
| `_prot` | nx, canary, pie, fortify, relro:full | LOW 27 |

C'est le cœur de l'étude de la Phase 7 : la même primitive vaut CRITICAL sans
mitigations et LOW avec.

## Limites (à documenter au rapport)

- **CASR sous-évalue le format string** : il n'observe qu'un SEGV (écriture `%n`
  ratée) et le classe NOT_EXPLOITABLE, d'où un score MEDIUM alors que la
  primitive (lecture/écriture arbitraires) est grave. La classe reste correcte
  (fournie par le statique) ; c'est l'exploitabilité mesurée qui est prudente.
- **Fusion par fonction** : deux vulnérabilités distinctes de classes différentes
  dans une même fonction restent séparées (bien), mais un `UNKNOWN` dynamique
  fusionne avec le premier finding compatible de la fonction (heuristique
  raisonnable sur un code où chaque fonction porte une vuln).
- Le barème (poids, seuils) est un **choix documenté**, pas une norme ; il est
  calibré pour être cohérent et défendable, non pour reproduire un CVSS exact.
