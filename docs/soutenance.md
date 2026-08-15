# Soutenance : plan de slides, script de démo, préparation Q&A

Format : 20 min de présentation (slides + démo) + 10 min de questions.

## 1. Plan de présentation (20 min)

| # | Slide | Durée | Contenu clé |
|---|-------|-------|-------------|
| 1 | Titre | 0:30 | argus, rattrapage cybersécurité, sécurité défensive / audit |
| 2 | Problème et objectif | 1:00 | « mini-Mayhem » : binaire en entrée, rapport en sortie (classe, fonction, offset, sévérité) |
| 3 | Périmètre | 1:00 | 6 classes de vulns, corpus écrit par moi, 3 profils de compilation |
| 4 | Architecture | 2:00 | 5 étapes (ingestion, statique, dynamique, corrélation+scoring, reporting), pipeline Python modulaire, CLI `argus` |
| 5 | Piège n°1 : binaire vs sources | 1:30 | statique = vrai black-box ; dynamique recompile (légitime car j'ai les sources) ; bonus QEMU |
| 6 | Ingestion | 1:30 | détection maison des protections (où chaque protection se lit dans l'ELF) recoupée avec checksec ; `_vuln` vs `_prot` |
| 7 | Moteur statique | 3:00 | 3 analyses ; résolution d'appels PLT/GOT robuste (CET) ; 2 pièges -O0 (format via rax, global en immédiat no-PIE) ; 0 faux positif |
| 8 | Moteur dynamique | 3:00 | builder/fuzzer/triage ; AFL++ en mode GCC plugin (contournement LLVM 22) ; CASR = type + exploitabilité |
| 9 | Corrélation + scoring | 2:00 | fusion des 3 sources ; formule impact x confiance x exploitabilité x mitigations ; CRITICAL vs LOW selon protections |
| 10 | Démo | 3:30 | voir le script §2 |
| 11 | Résultats | 1:30 | 6/6 détectées, 0 FP ; tableau protections ; PoC (offset 72, contrôle de RIP) |
| 12 | Bonus + limites + conclusion | 1:30 | PoC, FP/FN, CI ; limites assumées ; complémentarité statique/dynamique |

## 2. Script de démo (à répéter et à pré-charger)

Préparation (avant la soutenance) : `make -C corpus all`, venv activé, CASR et
AFL++ prêts, rapports déjà générés dans `reports/` comme filet de sécurité.

1. **Ingestion et protections** (contraste visuel)
   ```
   argus corpus/build/01_stack_bof_vuln --no-checksec
   argus corpus/build/01_stack_bof_prot --no-checksec
   ```
   Montrer : `_vuln` tout à « non », adresse fixe ; `_prot` tout à « oui », PIE.

2. **Analyse statique** (précision, offset, fonction)
   ```
   argus corpus/build/02_heap_bof_vuln --static --no-checksec
   ```
   Montrer : heap overflow trouvé statiquement (`read` 4096 dans un tas de 64).

3. **Pipeline complet** (statique + dynamique corrélés)
   ```
   argus corpus/build/02_heap_bof_vuln --static --dynamic \
         --sources corpus/src/02_heap_bof.c --fuzz-timeout 30 --no-checksec
   ```
   Montrer : le fuzzing découvre le crash, CASR confirme, fusion en CONFIRMED.

4. **Tableau des protections**
   ```
   python scripts/comparatif_protections.py
   ```
   Montrer : même vuln, CRITICAL en `_vuln` vs LOW/INFO en `_prot`.

5. **PoC : contrôle de RIP**
   ```
   python poc/poc_stack_bof.py
   ```
   Montrer : offset 72 trouvé par cyclic, `RIP = 0xdeadbeef`.

6. **Rapport HTML** : ouvrir `reports/01_stack_bof_vuln.html` dans le navigateur.

## 3. Préparation Q&A (questions probables du jury)

- **« Le sujet dit sur binaire, pourquoi recompiler ? »**
  Le moteur statique ne prend que le binaire (vrai black-box). Seul le moteur
  dynamique recompile, pour instrumenter (ASan, couverture AFL). C'est légitime
  car j'écris le corpus. Sans sources, on ferait du fuzzing en mode QEMU (bonus).

- **« Qu'est-ce que l'offset dans votre rapport ? »**
  Deux sens, tous deux exposés : l'offset **statique** est l'adresse de
  l'instruction/fonction vulnérable ; l'offset d'**exploitation** est la distance
  buffer -> adresse de retour (72 octets sur le stack overflow, trouvée au cyclic).

- **« Pourquoi ASan + CASR pour le triage ? »**
  ASan donne le **type mémoire exact** (heap/stack overflow, UAF, double free).
  CASR l'exécute, ajoute le **verdict d'exploitabilité** (style CERT) et une trace
  structurée, et sait dédupliquer. C'est la voie la plus fiable.

- **« Comment est calculé le score ? Pourquoi pas CVSS ? »**
  `impact(classe) x confiance x exploitabilité x mitigations`, avec une table de
  décision documentée, mappée sur un niveau. C'est un choix assumé : plus simple
  à défendre et directement lié aux protections détectées, sans prétendre
  reproduire un CVSS exact.

- **« Vos faux positifs / négatifs ? »**
  0 faux positif sur le corpus. Le statique manque 04/05/06 (integer overflow,
  UAF, double free) : ce sont des bugs temporels/sémantiques, non détectables sur
  la forme du code. Le dynamique les couvre. C'est la complémentarité, assumée.

- **« Pourquoi AFL++ en mode GCC plugin ? »**
  Le paquet AUR échoue : l'auto-test d'instrumentation LLVM-PCGUARD ne passe pas
  avec LLVM 22 (trop récent). Le mode GCC plugin, lui, fonctionne ; je l'ai
  compilé depuis les sources. Ça montre que je connais les deux backends d'AFL++.

- **« Comment résolvez-vous les appels dans le désassemblage ? »**
  Je lis réellement le saut du stub PLT (`jmp [rip+GOT]`) puis je mappe l'entrée
  GOT vers son nom via les relocations. Robuste à `.plt.sec` (CET) et aux appels
  directs par la GOT (-fno-plt).

- **« Comment évitez-vous de flaguer tous les printf ? »**
  Je ne signale un format string que si l'argument de format n'est pas constant,
  via une propagation de constantes sur les registres (indispensable à -O0 où le
  format passe par rax).

- **« Comment détectez-vous un heap overflow en statique ? »**
  Je suis le pointeur de `malloc(K)` à travers la variable locale (store/reload)
  jusqu'à la copie (`read(a, 4096)`) et je compare 4096 à 64.

- **« Comment étendre l'outil ? »**
  Analyse inter-procédurale, taint multi-sauts, DDG via angr (bonus), fuzzing
  QEMU black-box, reproduction de CVE réelles, et un corpus plus large pour des
  taux FP/FN significatifs.

- **« Projet individuel ? »**
  Oui : architecture, choix (taint intra-procédural, ASan+CASR, scoring par
  règles), code et documentation sont propres à ce projet.
