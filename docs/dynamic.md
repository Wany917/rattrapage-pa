# Moteur dynamique (Phase 4)

## Objectif

Complète le moteur statique : on **exécute** la cible pour *découvrir* des
crashes (fuzzing) et les *classer* (triage). Un crash reproductible est la preuve
la plus forte, d'où une confiance CONFIRMED.

## Le point « binaire vs sources »

Le moteur statique est un vrai black-box (binaire seul). Le moteur dynamique, lui,
**recompile** le corpus en cibles instrumentées (ASan, AFL++). C'est légitime :
l'étudiant écrit les sources du corpus. Sans sources, le dynamique est sauté
(le fuzzing black-box en mode QEMU est un bonus séparé).

## Chaîne : builder -> fuzzer -> triage

### builder (`builder.py`)
- **Cible de fuzzing** : `afl-cc` + `AFL_USE_ASAN=1` -> instrumentée pour la
  couverture (guidage d'AFL) et détectant les corruptions mémoire (ASan).
- **Cible de triage** : `gcc -fsanitize=address` -> rapport ASan propre, rejoué
  par CASR.

### fuzzer (`fuzzer.py`, AFL++)
- `afl-fuzz -i in -o out -m none -V <timeout> -- cible`, entrée sur **stdin**.
- `AFL_BENCH_UNTIL_CRASH=1` : arrêt au premier crash (démo rapide) ; à retirer
  pour explorer plus longtemps.
- Variables d'environnement pour éviter les blocages : `AFL_SKIP_CPUFREQ`,
  `AFL_NO_AFFINITY`, `AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES` (tolère un
  `core_pattern` « piped » sans droits root), `ASAN_OPTIONS=abort_on_error=1`.
- Crashes récupérés dans `out/default/crashes/id:*`.

### triage (`triage.py`, ASan / CASR)
- `casr-san` exécute la cible ASan, donne le **type** exact, l'**exploitabilité**
  (EXPLOITABLE / PROBABLY / NOT_EXPLOITABLE) et la pile ; repli sur la lecture
  ASan brute si CASR est absent. Findings CONFIRMED, dédupliqués par
  (classe, fonction).

## Installation d'AFL++ (contournement important)

Le paquet AUR `aflplusplus-git` **échoue** : son auto-test d'instrumentation
LLVM-PCGUARD ne passe pas, car la machine a **LLVM/clang 22**, trop récent pour
l'instrumentation LLVM d'AFL++. Solution retenue, sans sudo : compilation depuis
les sources en **mode GCC plugin, LLVM désactivé**
(`make LLVM_CONFIG=... NO_NYX=1`), dans `~/.local/opt/AFLplusplus`. Le pipeline
localise AFL++ via `AFL_PATH` puis cet emplacement. Point défendable à l'oral :
les deux backends d'instrumentation d'AFL++ (LLVM vs GCC plugin).

## Résultats

- Fuzzing de `02_heap_bof` : crash découvert en ~0,3 s, triage
  `heap-buffer-overflow` / **EXPLOITABLE** / CONFIRMED.
- Triage des six crashes (types exacts + exploitabilité) : voir le tableau de
  `docs/` (01 stack BOF, 02 heap BOF, 03 SEGV/format, 04 heap BOF, 05 UAF,
  06 double free). Le dynamique confirme les 6.

## Limites (à documenter au rapport)

- **Fuzzing borné en temps** : les crashes « faciles » (longueur, double free)
  tombent en secondes ; les « difficiles » (03 format string qui exige des `%n`,
  04 valeur d'entier précise qui fait wrapper) demandent plus de temps, un
  dictionnaire ou des seeds ciblés. Le statique et le triage sur entrées connues
  couvrent ces cas.
- Nécessite les sources (sinon mode QEMU black-box, bonus).
- Démo sur un cœur, arrêt au premier crash par cible ; pour une campagne longue,
  retirer `AFL_BENCH_UNTIL_CRASH` et augmenter le timeout.
