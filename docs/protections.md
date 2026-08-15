# Étude des protections (Phase 7)

## Détection

Les protections sont lues directement dans l'ELF par l'ingestion (voir
`docs/ingestion.md`) et recoupées avec `checksec` : NX (segment `PT_GNU_STACK`),
canary (import `__stack_chk_fail`), PIE (`e_type == ET_DYN`), RELRO (segment
`PT_GNU_RELRO` + `BIND_NOW` pour « full »), FORTIFY (imports `__*_chk`).

## Effet de chaque protection sur l'exploitabilité

- **NX (No-eXecute)** : la pile et le tas ne sont plus exécutables. Le shellcode
  injecté ne peut plus être exécuté ; l'attaquant doit réutiliser du code
  existant (ROP, ret2libc). Ne corrige pas le débordement, augmente le coût.
- **Stack canary** : une valeur aléatoire est placée avant l'adresse de retour
  et vérifiée à la sortie de fonction. Un débordement séquentiel naïf l'écrase
  et provoque un `abort` (`__stack_chk_fail`) au lieu d'un contrôle de RIP.
  Contournement : fuiter le canary, ou écrire sans le traverser.
- **ASLR / PIE** : les adresses (bibliothèques, et exécutable si PIE) sont
  randomisées à chaque exécution. Les adresses en dur ne fonctionnent plus ;
  il faut d'abord une fuite d'adresse (leak).
- **RELRO** : `partial` mappe une partie des sections en lecture seule après
  relocation ; `full` (avec `BIND_NOW`) rend la **GOT en lecture seule**, ce qui
  tue l'écrasement d'entrée GOT (technique classique de détournement de flux).
- **FORTIFY (`_FORTIFY_SOURCE`)** : remplace certaines fonctions par des versions
  bornées (`__strcpy_chk`, `__memcpy_chk`, `__read_chk`) qui `abort` en cas de
  débordement détectable, et **interdit `%n`** dans une chaîne de format située
  en mémoire inscriptible (`__printf_chk`).

## Tableau comparatif `_vuln` vs `_prot`

Même vulnérabilité (même primitive et même exploitabilité mesurée), scorée contre
les protections de chaque profil. Table générée par
`scripts/comparatif_protections.py`.

| Binaire | Classe | Exploitabilité | Sévérité `_vuln` | Sévérité `_prot` |
|---------|--------|----------------|------------------|------------------|
| 01_stack_bof | stack_buffer_overflow | EXPLOITABLE | CRITICAL 90.0 | LOW 27.0 |
| 02_heap_bof | heap_buffer_overflow | EXPLOITABLE | HIGH 80.0 | MEDIUM 64.0 |
| 03_format_string | format_string | NOT_EXPLOITABLE | MEDIUM 51.0 | INFO 17.8 |
| 04_integer_overflow | heap_buffer_overflow | EXPLOITABLE | HIGH 80.0 | MEDIUM 64.0 |
| 05_use_after_free | use_after_free | NOT_EXPLOITABLE | MEDIUM 48.0 | LOW 38.4 |
| 06_double_free | double_free | NOT_EXPLOITABLE | MEDIUM 42.0 | LOW 39.9 |

Rappel : sur `_prot`, les cinq protections sont actives (NX, canary, PIE,
RELRO full, FORTIFY).

## Analyse par vulnérabilité

- **Stack BOF (01)** : c'est la classe la plus sensible aux mitigations de pile.
  Canary + FORTIFY (`__strcpy_chk`) transforment le débordement en `abort`
  contrôlé, PIE impose un leak. On passe de CRITICAL à LOW.
- **Heap BOF (02) et integer overflow (04)** : bugs de **tas**. Le canary, PIE et
  RELRO ne protègent pas le tas ; seuls NX (un peu) et FORTIFY (partiellement)
  jouent. La sévérité baisse peu (HIGH -> MEDIUM), ce qui illustre que les
  protections de pile n'aident pas contre les corruptions de tas.
- **Format string (03)** : c'est FORTIFY qui est décisif (il interdit `%n`),
  d'où la chute la plus forte (MEDIUM -> INFO). RELRO renforce en verrouillant la
  GOT (cible d'écriture privilégiée d'un `%n`).
- **UAF (05) et double free (06)** : corruptions de tas, peu affectées par les
  protections présentes (léger effet de NX). Sévérité MEDIUM -> LOW.

## Conclusion défendable

Les protections ne « corrigent » aucun bug : elles augmentent le coût d'une
exploitation. Leur efficacité dépend de la **classe** : les mitigations de pile
(canary, PIE) sont très efficaces sur les débordements de pile mais inopérantes
sur le tas, tandis que FORTIFY et RELRO ciblent respectivement les fonctions
bornées / `%n` et l'intégrité de la GOT. C'est exactement ce que le scoring du
pipeline modélise via sa table de mitigation par classe (voir `docs/scoring.md`).
