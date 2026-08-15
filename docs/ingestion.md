# Ingestion ELF (Phase 2)

## Objectif

Première étape du pipeline, en **vrai black-box** : elle ne lit que le binaire
(aucune source). Elle produit un objet `ELFInfo` : architecture, type
(exécutable ou PIE), point d'entrée, protections en place, et inventaire des
fonctions. Ces données alimentent le moteur statique (Phase 3) et le scoring
(Phase 5, croisement primitive / protections).

## Détection des protections : où chaque protection se lit dans l'ELF

On détecte tout nous-mêmes avec pyelftools, sans dépendre de checksec, pour
maîtriser le résultat et pouvoir l'expliquer. Le tableau donne le signal exact.

| Protection | Signal lu dans l'ELF | Règle |
|------------|----------------------|-------|
| **NX** | Segment de programme `PT_GNU_STACK` | activé si le flag `X` (exécution) est absent ; pas de segment = pile exécutable (convention checksec) |
| **PIE** | Champ d'en-tête `e_type` | activé si `ET_DYN` (sinon `ET_EXEC`) |
| **Canary** | Import `__stack_chk_fail` | présent = canary activé |
| **RELRO** | Segment `PT_GNU_RELRO` (+ table dynamique) | `none` si pas de segment ; `partial` si segment seul ; `full` si segment + résolution immédiate (`DT_BIND_NOW`, ou `DF_BIND_NOW`, ou `DF_1_NOW`) |
| **FORTIFY** | Imports en `__*_chk` | présent = au moins une fonction bornée (`__strcpy_chk`, `__printf_chk`, `__read_chk`...) |

### Pseudocode

```
NX      : pour chaque segment, si PT_GNU_STACK -> NX = non(flag X)
          si aucun PT_GNU_STACK -> NX = faux
PIE     : NX = (e_type == ET_DYN)
Canary  : "__stack_chk_fail" dans les imports
RELRO   : has = il existe un segment PT_GNU_RELRO
          si non has -> "none"
          sinon -> "full" si BIND_NOW (DT_BIND_NOW / DF_BIND_NOW / DF_1_NOW) sinon "partial"
FORTIFY : il existe un import commençant par "__" et finissant par "_chk"
```

## Inventaire des fonctions

- **Imports** : symboles `FUNC`/`NOTYPE` non définis (`SHN_UNDEF`) de la
  `.dynsym`. Ce sont les fonctions résolues via la PLT ; c'est là que se
  trouvent les sinks potentiels (`gets`, `strcpy`, `printf`...). Les suffixes de
  version GNU (`fgets@GLIBC_2.2.5`) sont normalisés en `fgets` pour éviter les
  doublons et fiabiliser le matching de la Phase 3.
- **Fonctions définies** : symboles `FUNC` définis de la `.symtab` (ou de la
  `.dynsym` si le binaire est strippé), avec leur adresse. Elles servent de
  points d'entrée au désassemblage ciblé du moteur statique.

## Recoupement avec checksec

Si `checksec` est installé, on lance `checksec --no-banner -o json file <bin>` et
on compare son verdict au nôtre (champ `protections["checksec"]`). Sur tout le
corpus, les deux **concordent**. C'est une validation, pas la source de vérité :
le résultat principal reste notre lecture de l'ELF.

## Résultat sur le corpus (01_stack_bof)

| Protection | `_vuln` | `_prot` |
|------------|---------|---------|
| NX | non | oui |
| Canary | non | oui |
| PIE | non (`ET_EXEC`, entry `0x401060`) | oui (`ET_DYN`, entry `0x10f0`) |
| RELRO | none | full |
| FORTIFY | non | oui |

## Limites et nuances (à mentionner au rapport)

- **PIE via `ET_DYN`** : une bibliothèque partagée est aussi `ET_DYN`. Pour un
  exécutable, la présence d'un `PT_INTERP` lève l'ambiguïté ; on pourrait
  raffiner avec le flag `DF_1_PIE`. Sur nos cibles (des exécutables), `ET_DYN`
  suffit et concorde avec checksec.
- **Adresses des stubs PLT** : l'ingestion liste les imports par nom. La
  résolution précise `stub PLT -> nom` (utile pour identifier la cible d'un
  `call`) est faite au désassemblage, en Phase 3.
