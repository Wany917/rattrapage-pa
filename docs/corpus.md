# Corpus de test (Phase 1)

## Objectif

Fournir six binaires C, un par classe de vulnérabilité imposée, servant à la
fois de cibles pour le pipeline (statique et dynamique) et de support
pédagogique pour la soutenance. Chaque programme :

- isole **une seule** vulnérabilité, clairement commentée (où, pourquoi, comment
  la déclencher) ;
- lit son entrée sur **stdin**, ce qui le rend directement fuzzable (AFL++
  injecte ses cas de test sur stdin) ;
- a un déclencheur **déterministe**, pour une démo reproductible.

## Les trois profils de compilation

Chaque source est compilée en trois variantes (voir `corpus/Makefile`) :

| Profil  | Intention | Options clés |
|---------|-----------|--------------|
| `_vuln` | Toutes les protections **désactivées** (cible d'exploitation, PoC) | `-O0 -fno-stack-protector -fno-pie -no-pie -D_FORTIFY_SOURCE=0 -z norelro -z execstack` |
| `_prot` | Toutes les protections **activées** (étude de l'impact des mitigations) | `-O2 -fstack-protector-all -fPIE -pie -D_FORTIFY_SOURCE=2 -Wl,-z,relro -Wl,-z,now` |
| `_asan` | Instrumenté AddressSanitizer (triage exact des crashes en Phase 4) | `-O1 -g -fsanitize=address -fno-omit-frame-pointer` |

Remarque : `-D_FORTIFY_SOURCE=2` n'a d'effet qu'à partir de `-O1`, d'où le `-O2`
du profil `_prot`. FORTIFY remplace certaines fonctions par leurs versions
bornées (`__strcpy_chk`, `__printf_chk`, `__read_chk`...).

## Les six vulnérabilités

| Fichier | Classe | Source -> Sink | Déclencheur | Type ASan attendu |
|---------|--------|----------------|-------------|-------------------|
| `01_stack_bof.c` | Stack buffer overflow | `fgets` -> `strcpy` | ligne > 64 octets | `stack-buffer-overflow` |
| `02_heap_bof.c` | Heap buffer overflow | `read` -> chunk 64 o | entrée > 64 octets | `heap-buffer-overflow` |
| `03_format_string.c` | Format string | `fgets` -> `printf(buf)` | `%p` (leak), `%n` (write) | SEGV (ASan ne type pas) |
| `04_integer_overflow.c` | Integer overflow | `fread(count)` -> boucle | `count` qui fait wrapper `count*8` | `heap-buffer-overflow` |
| `05_use_after_free.c` | Use-after-free | `fread` -> `c->handler()` | ligne + 40 octets (réécrit le pointeur) | `heap-use-after-free` |
| `06_double_free.c` | Double free | `fgets` -> `free`/`free` | toute entrée (inconditionnel) | `attempting double-free` |

## Vérification du déclenchement

Contrôle exécuté sur les binaires `_asan` (type de bug) et `_vuln` (signal de
crash) :

| Fichier | ASan (`_asan`) | Signal (`_vuln`) |
|---------|----------------|------------------|
| `01_stack_bof` | stack-buffer-overflow | SIGSEGV (139) |
| `02_heap_bof` | heap-buffer-overflow | SIGABRT (134) |
| `03_format_string` | DEADLYSIGNAL (SEGV) | SIGSEGV (139) |
| `04_integer_overflow` | heap-buffer-overflow | SIGABRT (134) |
| `05_use_after_free` | heap-use-after-free | SIGSEGV (139) |
| `06_double_free` | double-free | SIGABRT (134) |

Contrôle des protections (`readelf` et `checksec`), identique pour les six :

| | `_vuln` | `_prot` |
|---|---|---|
| PIE | EXEC (non) | DYN (oui) |
| NX (GNU_STACK) | RWE (désactivé) | RW (activé) |
| RELRO | absent | Full RELRO (+ BIND_NOW) |
| Stack canary | absent | présent |
| FORTIFY | non | oui (2 fonctions fortifiées) |

## Choix de conception à défendre

- **`01_stack_bof` : source dans un buffer statique.** Une première version
  lisait dans une variable de pile voisine de la destination : source et
  destination se chevauchaient, et ASan signalait `strcpy-param-overlap` au lieu
  de `stack-buffer-overflow` ; de plus le débordement n'atteignait pas l'adresse
  de retour. En plaçant la source dans le segment de données (buffer `static`),
  le débordement vise bien le saved RIP et le crash est un SIGSEGV « propre »,
  idéal pour le PoC (Phase 9).

- **`04_integer_overflow` : wrap multiplicatif plutôt que `read(size négatif)`.**
  Le classique « taille signée négative passée à `read` » ne fonctionne pas ici :
  le noyau refuse un `count` proche de `SIZE_MAX` (EFAULT) et ne copie rien. On
  utilise donc le débordement de la multiplication `count * 8` sur 32 bits, qui
  produit une allocation sous-dimensionnée puis un débordement de tas fiable et
  correctement typé par ASan.

- **Déterminisme et stdin.** Tous les programmes lisent stdin et crashent sur une
  entrée connue. Cela sert trois usages : démonstration reproductible, seeds de
  fuzzing (Phase 4), et génération de PoC (Phase 9).

## Limites connues (à documenter dans le rapport)

- Le **format string** n'est pas typé par ASan (ASan ne modélise pas ce bug) ;
  sa détection repose sur l'analyse statique (`printf` avec format non constant,
  taint `fgets -> printf`) et sur le signal de crash côté dynamique.
- Les débordements de **tas** sont difficiles à détecter en statique pur sur un
  binaire ; on s'appuie surtout sur le moteur dynamique (ASan) pour ces cas, et
  l'analyse statique fournit des indices (fonctions dangereuses, tailles).
