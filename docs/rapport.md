# argus : détection automatisée de vulnérabilités bas niveau sur binaire

Rapport de projet (rattrapage). Sécurité défensive et audit : l'outil analyse un
binaire et produit un rapport, il ne cible aucun système tiers. Le corpus de test
est écrit pour l'exercice.

Ce document est la synthèse. Le détail par module (méthode + pseudocode +
résultats) est dans les fichiers `docs/*.md` référencés à chaque section.

---

## 1. Contexte et périmètre

- **Entrée** : un binaire ELF x86-64. **Sortie** : un rapport (JSON + HTML +
  Markdown) donnant, pour chaque vulnérabilité, sa **classe**, la **fonction**
  concernée, l'**offset** et la **sévérité** estimée.
- **Six classes** couvertes (une par binaire du corpus) : stack buffer overflow,
  heap buffer overflow, format string, integer overflow, use-after-free, double
  free.
- **Principe** : ne pas réinventer désassembleur ni fuzzer. La valeur est dans
  l'orchestration, la classification, le scoring et le reporting.
- **Environnement** : Arch Linux x86-64, Python 3.14, gcc 16, AFL++ (mode GCC
  plugin), CASR, AddressSanitizer, Capstone, pyelftools.

## 2. Architecture

Pipeline modulaire en cinq étapes, orchestrées par la CLI `argus` :

```
[binaire] -> (1) INGESTION -> ELFInfo {arch, protections, imports, symboles}
                  |
                  |-> (2) MOTEUR STATIQUE (binaire seul = black-box)
                  |       fonctions dangereuses, buffer sizing, taint
                  |
                  |-> (3) MOTEUR DYNAMIQUE (recompile ASan+AFL, car sources dispo)
                  |       build instrumenté, fuzzing AFL++, triage ASan/CASR
                  |
                  v
             (4) CORRELATION + SCORING (fusion, sévérité vs protections)
                  |
                  v
             (5) REPORTING -> JSON + HTML + Markdown
```

Contrat de données commun : `pipeline/models.py` (Finding, Report, enums de
classe/sévérité/confiance).

## 3. Méthodologie et algorithmes

### 3.1 Ingestion (vrai black-box) - `docs/ingestion.md`

Lecture de l'ELF avec pyelftools : architecture, type (PIE), point d'entrée,
inventaire des fonctions (imports de la `.dynsym`, fonctions définies de la
`.symtab`). Détection **maison** des protections, recoupée avec `checksec` :

| Protection | Signal ELF |
|------------|-----------|
| NX | segment `PT_GNU_STACK` non exécutable |
| PIE | `e_type == ET_DYN` |
| Canary | import `__stack_chk_fail` |
| RELRO | `PT_GNU_RELRO` (+ BIND_NOW pour full) |
| FORTIFY | imports `__*_chk` |

### 3.2 Moteur statique (black-box) - `docs/static.md`

Trois analyses sur désassemblage Capstone (résolution d'appels PLT/GOT robuste,
CET compris) :

- **Fonctions dangereuses** : appels résolus à `gets`, `strcpy`, `sprintf`,
  `scanf`, `system`... ; pour `printf`, on ne signale que si le format n'est pas
  constant (propagation de constantes sur les registres).
- **Buffer sizing** : on retrouve l'allocation (pile via `sub rsp` / `lea [rbp-D]`,
  tas via `malloc`, suivie à travers les variables locales) et on la compare à la
  taille de la copie (`read`, `memcpy`, `fgets`...).
- **Taint tracking** intra-procédural : une source (fgets, read...) contamine un
  buffer ; un sink (strcpy, printf...) qui le lit fait monter la confiance à
  PROBABLE.

### 3.3 Moteur dynamique - `docs/dynamic.md`

- **builder** : recompile la source en cible AFL+ASan (fuzzing) et en cible ASan
  (triage).
- **fuzzer** : AFL++ (`afl-fuzz`, entrée stdin, arrêt au premier crash pour la
  démo) découvre des entrées qui font crasher.
- **triage** : `casr-san` donne le type exact, l'exploitabilité et la trace ;
  repli sur la lecture ASan brute. Crash reproductible = confiance CONFIRMED.

Note d'installation : le paquet AUR d'AFL++ échoue (auto-test LLVM-PCGUARD
incompatible avec LLVM 22) ; AFL++ a été compilé en **mode GCC plugin** depuis
les sources.

### 3.4 Corrélation + scoring - `docs/scoring.md`

Fusion des findings d'une même fonction (réconciliation `UNKNOWN` pour le format
string), en gardant la confiance la plus haute, l'offset statique et
l'exploitabilité. Scoring par règles :

    score = impact(classe) x confiance x exploitabilité(CASR) x mitigations(protections)

mappé sur CRITICAL / HIGH / MEDIUM / LOW / INFO.

### 3.5 Reporting

Un `Report` (cible + ELFInfo + findings + stats) sérialisé en JSON (machine),
HTML (jinja2, coloré, imprimable en PDF) et Markdown.

## 4. Points stratégiques (pièges du sujet)

- **« Sur binaire » vs sources** : le moteur statique est un vrai black-box (il
  ne lit que le binaire). Le moteur dynamique recompile le corpus (ASan + AFL),
  ce qui est légitime puisque nous en écrivons les sources. Bonus possible : AFL
  en mode QEMU (black-box, sans sources).
- **Double sens d'« offset »** : le rapport expose l'offset **statique** (adresse
  de l'instruction) et l'offset d'**exploitation** (distance buffer -> RIP,
  trouvée par le PoC). Les deux champs coexistent dans `Finding`.

## 5. Résultats

### 5.1 Détection (profils `_vuln`) - `docs/evaluation.md`

| Binaire | Sévérité | Classe | Confiance | Sources |
|---------|----------|--------|-----------|---------|
| 01_stack_bof | CRITICAL 90 | stack_buffer_overflow | confirmed | dangerous_funcs + taint + casr |
| 02_heap_bof | HIGH 80 | heap_buffer_overflow | confirmed | buffer_sizing + casr |
| 03_format_string | MEDIUM 51 | format_string | confirmed | dangerous_funcs + taint + casr |
| 04_integer_overflow | HIGH 80 | heap_buffer_overflow | confirmed | casr |
| 05_use_after_free | MEDIUM 48 | use_after_free | confirmed | casr |
| 06_double_free | MEDIUM 42 | double_free | confirmed | casr |

Couverture : statique 3/6, dynamique 6/6, combinée **6/6**, **0 faux positif**.

### 5.2 Impact des protections - `docs/protections.md`

Même vulnérabilité, deux profils :

| Binaire | Sévérité `_vuln` | Sévérité `_prot` |
|---------|------------------|------------------|
| 01_stack_bof | CRITICAL 90 | LOW 27 |
| 02_heap_bof | HIGH 80 | MEDIUM 64 |
| 03_format_string | MEDIUM 51 | INFO 18 |
| 04_integer_overflow | HIGH 80 | MEDIUM 64 |
| 05_use_after_free | MEDIUM 48 | LOW 38 |
| 06_double_free | MEDIUM 42 | LOW 40 |

Les mitigations de pile (canary, PIE) sont très efficaces sur le stack overflow,
FORTIFY est décisif sur le format string, et les bugs de tas sont peu affectés.

### 5.3 PoC (bonus) - `poc/`

Sur `01_stack_bof_vuln` : offset buffer -> RIP = **72 octets** (via cyclic
pattern), contrôle de RIP démontré (`RIP = 0xdeadbeef`).

## 6. Bonus réalisés

- **Génération de PoC** (contrôle de RIP) : fait (`poc/poc_stack_bof.py`).
- **Couverture + FP/FN** : fait (`scripts/evaluation.py`, `docs/evaluation.md`).
- **Intégration CI** : fait (`ci/github-actions.yml`, analyse statique à chaque
  commit).
- **Reproduction de CVE réelle** : piste non réalisée dans ce rendu (voir §7).

## 7. Limites

- Analyse statique **intra-procédurale** ; taint à un seul saut ; pas de modèle
  d'alias mémoire complet ; le tas n'est pas suivi par le taint.
- CASR **sous-évalue le format string** (il n'observe qu'un SEGV), d'où un score
  prudent ; la classe reste correcte (fournie par le statique).
- Le **corpus est petit et écrit par nous** : les taux valident la conception, pas
  une performance généralisable.
- Le **fuzzing est borné en temps** : les crashes difficiles (format, integer
  précis) demandent seeds/dictionnaire et budget.
- **CVE réelle** non reproduite : piste concrète = choisir une CVE simple et
  locale (ex. débordement dans un petit utilitaire), compiler la version
  vulnérable, lancer `argus` dessus. À réaliser sur un runner dédié.

## 8. Installation et usage

```
# Environnement Python
python -m venv .venv && source .venv/bin/activate.fish
python -m pip install -e ".[dev]"

# Outils : checksec (paru -S checksec), CASR (cargo install casr),
# AFL++ (compilé en mode GCC plugin dans ~/.local/opt/AFLplusplus)

# Corpus
make -C corpus all

# Pipeline complet sur une cible
argus corpus/build/01_stack_bof_vuln \
      --static --dynamic --sources corpus/src/01_stack_bof.c \
      --report reports/

# Tests
pytest -q
```

## 9. Conclusion

argus réalise un « mini-Mayhem » : analyse statique black-box, fuzzing
coverage-guided et triage, orchestrés de bout en bout, avec corrélation et
scoring tenant compte des protections. Sur le corpus, il détecte les six classes
sans faux positif, estime une sévérité défendable qui reflète l'effet des
mitigations, et va jusqu'au contrôle de RIP en PoC. Les limites (portée
intra-procédurale, corpus réduit) sont assumées et documentées.
