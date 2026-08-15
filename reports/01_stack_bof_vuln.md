# Rapport argus : `/home/jinshi/dev/ecole/rattrapage-pa/corpus/build/01_stack_bof_vuln`

## Cible

- Architecture : x64 (64 bits, little-endian)
- Type : exécutable non-PIE (entry 0x401060)
- Symboles : présents
- Fonctions : 10 définies, 7 importées

## Protections

| Protection | État |
|------------|------|
| NX | non |
| Stack canary | non |
| PIE | non |
| RELRO | none |
| FORTIFY | non |

## Synthèse

- 1 vulnérabilité(s) détectée(s).
- Répartition : 1 critical.

## Vulnérabilités

### [CRITICAL 90.0] stack_buffer_overflow — `vuln` @ 0x401178

- Confiance : confirmed
- Exploitabilité : EXPLOITABLE
- Offset statique : 0x401178 | offset exploit : -
- Sources : dynamic:casr-san+static:dangerous_funcs+static:taint
- Description : Crash reproductible (stack-buffer-overflow(write)) à /home/jinshi/dev/ecole/rattrapage-pa/corpus/src/01_stack_bof.c:40.
- Remédiation : corriger la vulnérabilité mémoire à l'origine du crash
- Preuves : sink = strcpy, call_site = 0x401178, source = fgets, bug = stack-buffer-overflow(write), exploitability = EXPLOITABLE, crash_location = /home/jinshi/dev/ecole/rattrapage-pa/corpus/src/01_stack_bof.c:40, tool = casr-san

