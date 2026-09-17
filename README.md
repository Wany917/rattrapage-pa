# Rattrapage PA : détection automatisée de vulnérabilités bas niveau

Pipeline d'audit qui prend un binaire ELF x86-64 en entrée et produit un rapport
structuré (JSON + HTML/Markdown) listant, pour chaque vulnérabilité : classe,
fonction concernée, offset et sévérité estimée.

Sécurité défensive et audit : l'outil analyse des binaires et génère un rapport,
il ne cible aucun système tiers. Le corpus de test est constitué de binaires C
volontairement vulnérables, écrits pour l'exercice.

## Architecture

Le pipeline enchaîne cinq étapes (un sous-ensemble de `pipeline/` par étape) :

1. **Ingestion** (`ingestion.py`) : parse l'ELF, détecte les protections
   (NX, canary, PIE, RELRO, FORTIFY) et inventorie les fonctions.
2. **Moteur statique** (`static/`) : fonctions dangereuses, comparaison taille
   de buffer vs taille de copie, taint tracking source vers sink.
3. **Moteur dynamique** (`dynamic/`) : recompilation instrumentée, fuzzing
   AFL++, triage des crashes via AddressSanitizer et CASR.
4. **Corrélation et scoring** (`correlation.py`, `scoring.py`) : fusion des
   findings statiques et dynamiques, déduplication, estimation de sévérité.
5. **Reporting** (`report/`) : génération JSON et HTML/Markdown.

Voir `docs/` pour la méthodologie, les algorithmes, les résultats et les limites.

## Organisation du dépôt

```
corpus/    binaires C vulnérables + Makefile (profils vuln / prot / asan)
pipeline/  modules Python du pipeline
reports/   rapports générés (JSON + HTML/MD)
docker/    image de démo reproductible (Dockerfile + compose)
.github/   intégration continue (GitHub Actions : tests + analyse statique)
docs/      rapport et notes de méthodologie
tests/     tests unitaires (pytest)
```

## Démo reproductible (Docker, notamment macOS)

Le pipeline vise des ELF x86-64 et l'outillage Linux (gcc GNU, AFL++, ASan,
CASR). Sur une machine sans cet environnement (macOS, autre distro), l'image
`docker/Dockerfile` reproduit tout : outillage, corpus compilé et `argus`
installé. Elle se construit en `linux/amd64` pour que disasm, offsets et PoC
(RIP à l'offset 72) correspondent au rapport.

```
docker compose -f docker/compose.yaml build      # ~10-20 min (AFL++ + CASR)
docker compose -f docker/compose.yaml run --rm argus
# puis, dans le conteneur :
scripts/demo.sh                                  # rejoue les 4 étapes de la démo
```

Le compose passe déjà `--security-opt seccomp=unconfined`, requis par CASR
(syscall `personality`). En `docker run` direct, l'ajouter explicitement :

```
docker run --rm -it --platform linux/amd64 --security-opt seccomp=unconfined \
       -v "$PWD/reports:/app/reports" argus:demo
```

AFL++ tourne en mode plugin GCC (`AFL_CC_COMPILER=GCC_PLUGIN`). Sur Apple
Silicon le fuzzing tourne sous émulation (plus lent) : le `--fuzz-timeout` de la
démo est à 60 s pour laisser AFL découvrir le crash.

## Installation (Arch Linux)

Environnement Python (venv, shell fish) :

```
python -m venv .venv
source .venv/bin/activate.fish
python -m pip install -e ".[dev]"     # ajouter [poc] pour pwntools
```

Outils du moteur dynamique :

```
paru -S checksec          # recoupement des protections (optionnel)
cargo install casr        # triage des crashes (type + exploitabilité)
```

AFL++ : le paquet AUR `aflplusplus-git` échoue avec LLVM 22 (auto-test
LLVM-PCGUARD). On le compile en mode GCC plugin depuis les sources :

```
git clone --depth 1 https://github.com/AFLplusplus/AFLplusplus ~/.local/opt/AFLplusplus
make -C ~/.local/opt/AFLplusplus LLVM_CONFIG=llvm-config-absent NO_NYX=1
```

## Usage

```
# Ingestion + protections
argus corpus/build/01_stack_bof_vuln

# Analyse statique
argus corpus/build/02_heap_bof_vuln --static

# Pipeline complet (statique + dynamique + rapports JSON/HTML/MD)
argus corpus/build/02_heap_bof_vuln --static --dynamic \
      --sources corpus/src/02_heap_bof.c --report reports/

# Utilitaires
python scripts/comparatif_protections.py   # tableau _vuln vs _prot
python scripts/evaluation.py               # couverture + FP/FN
python scripts/scan_reel.py /usr/bin/awk   # scan statique de binaires réels
python poc/poc_stack_bof.py                # PoC : contrôle de RIP
```

Validation sur binaires réels et note CVE : `docs/validation_reelle.md`.

## État d'avancement

- [x] Phase 0 : setup (arbo, venv, contrat de données, test fumigène)
- [x] Phase 1 : corpus C (6 classes, profils vuln / prot / asan)
- [x] Phase 2 : ingestion (ELF + protections + inventaire)
- [x] Phase 3 : moteur statique
- [x] Phase 4 : moteur dynamique
- [x] Phase 5 : corrélation + scoring
- [x] Phase 6 : reporting
- [x] Phase 7 : étude des protections
- [x] Phase 8 : documentation (`docs/rapport.md` + notes par module)
- [x] Phase 9 : bonus (PoC contrôle de RIP, couverture + FP/FN, CI ; CVE = piste)
- [x] Phase 10 : soutenance (`docs/soutenance.md` : slides + démo + Q&A)
