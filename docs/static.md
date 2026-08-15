# Moteur statique (Phase 3)

## Objectif

Analyse en **vrai black-box** (le binaire seul, aucune source). Trois analyses
complémentaires produisent des `Finding`, qu'un pilote déduplique. But : localiser
les vulnérabilités « de forme » (fonction dangereuse, taille de copie) sans
exécuter le programme, avec fonction concernée et offset.

## Socle de désassemblage (`disasm.py`)

Capstone en mode détaillé. Point délicat : résoudre la cible d'un `call` vers le
nom de la fonction importée. On lit **réellement** le saut du stub PLT
(`jmp [rip+GOT]`) puis on associe l'entrée GOT à son nom via les relocations
(`.rela.plt`). Avantage : robuste à la PLT classique **comme** à `.plt.sec`
(stubs précédés d'`endbr64`, CET activé par défaut sur gcc 16), et aux appels
directs par la GOT (`call [rip+x]`, binaires -fno-plt). Fournit aussi
l'itération des fonctions (nom/adresse/taille via `.symtab`) et la normalisation
des sous-registres (edi -> rdi...).

## Analyse 1 : fonctions dangereuses (`dangerous_funcs.py`)

- **Sinks intrinsèques** (`gets`, `strcpy`, `strcat`, `sprintf`, `scanf`,
  `system`, `popen`, `alloca`) : chaque appel résolu donne un finding avec la
  fonction appelante et l'offset.
- **Chaînes de format** : on ne signale `printf`/`fprintf`/`syslog`... que si le
  format n'est **pas** constant. On suit la constance des registres par
  propagation légère (`lea reg, [rip+rodata]` = constant ; `mov reg, reg`
  propage ; immédiat vers .rodata = constant). Indispensable car, à -O0, gcc
  charge le format via un intermédiaire (`lea rax,[rip+fmt]; mov rdi,rax`). Le
  format est en rdi (printf) ou rsi (fprintf) selon l'ABI SysV.

## Analyse 2 : taille de buffer vs taille de copie (`buffer_sizing.py`)

Retrouve l'allocation d'un buffer et la compare à la taille de la copie :

- **Pile** : `sub rsp, 0xNN` (cadre) et `lea [rbp-D]` (buffer de D octets) ;
- **Tas** : retour de `malloc(K)` (buffer de K octets) ;
- **Suivi mémoire** : les pointeurs sauvés dans une variable locale sont suivis à
  travers store/reload. Indispensable à -O0 (les variables vivent en mémoire) :
  c'est ce qui permet de suivre `a = malloc(64)` jusqu'à `read(a, 4096)`.

On signale une copie constante `> capacité` (PROBABLE) ou de taille non constante,
donc potentiellement contrôlée (POSSIBLE). Registres destination/taille selon
l'ABI (ex. `read` : buf=rsi, count=rdx ; `fgets` : buf=rdi, size=rsi).

## Analyse 3 : taint tracking (`taint.py`)

Intra-procédural, un saut. On donne à chaque buffer une identité stable
(`('stack', D)` ou `('global', adresse)`). Une **source** (`fgets`, `read`,
`recv`, `gets`, `fread`) contamine le buffer qu'elle remplit ; un **sink**
(`strcpy`, `strcat`, `printf`, `fprintf`, `system`) qui lit un buffer contaminé
déclenche un finding PROBABLE (flux source -> sink confirmé). Détail : en no-PIE,
l'adresse d'un buffer global est chargée en **immédiat** (`mov edi, 0x404060`),
en PIE via `lea [rip+...]` ; les deux sont gérés.

## Pilote et déduplication (`engine.py`)

On agrège les trois analyses puis on fusionne par site `(fonction, offset,
classe)` : une seule entrée, à la confiance la plus haute, sources combinées.
Ainsi `strcpy` (POSSIBLE, dangerous_funcs) + flux `fgets->strcpy` (PROBABLE,
taint) donnent une seule entrée PROBABLE. La corrélation avec le moteur dynamique
(Phase 5) prolongera cette logique.

## Résultats sur le corpus (profils `_vuln`)

| Binaire | Finding | Confiance | Origine |
|---------|---------|-----------|---------|
| 01_stack_bof | stack_buffer_overflow (strcpy) | probable | dangerous_funcs + taint |
| 02_heap_bof | heap_buffer_overflow (read 4096 vs tas 64) | probable | buffer_sizing |
| 03_format_string | format_string (printf) | probable | dangerous_funcs + taint |
| 04_integer_overflow | (rien) | | moteur dynamique |
| 05_use_after_free | (rien) | | moteur dynamique |
| 06_double_free | (rien) | | moteur dynamique |

## Faux positifs / faux négatifs (complémentarité statique/dynamique)

- **Faux positifs : 0** sur le corpus. La détection de format string ne se
  déclenche pas sur un format constant ; le buffer sizing ne se déclenche pas sur
  une copie bornée (fgets de taille = taille du buffer).
- **Faux négatifs assumés** : 04 (integer overflow : la taille du malloc est
  variable, donc non comparable statiquement), 05 (use-after-free) et 06
  (double free) sont des bugs **temporels/sémantiques**, non détectables sur la
  seule forme du code. Ils relèvent du moteur dynamique (ASan/CASR). C'est
  précisément la répartition statique (formes) / dynamique (comportements).

## Limites (à documenter au rapport)

- Analyse **intra-procédurale** : pas de suivi inter-fonctions ; taint à un seul
  saut (pas de chaîne de copies).
- Pas de modèle d'alias mémoire complet ; le tas n'est pas suivi par le taint
  (identité instable après réallocation).
- La résolution des noms de fonctions appelantes dépend des symboles (`.symtab`).
  Sur un binaire strippé, on retombe sur des offsets sans nom de fonction.
