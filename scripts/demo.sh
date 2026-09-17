#!/usr/bin/env bash
# Rejoue le script de démo de la soutenance (docs/soutenance.md §2).
# À lancer dans le conteneur argus:demo. Pause entre chaque étape.
set -euo pipefail
cd "$(dirname "$0")/.."

pause() { echo; read -rp "── Entrée pour l'étape suivante ──" _; echo; }

echo "### 1. Ingestion et protections : contraste _vuln vs _prot"
argus corpus/build/01_stack_bof_vuln --no-checksec
argus corpus/build/01_stack_bof_prot --no-checksec
pause

echo "### 2. Analyse statique : heap overflow (read 4096 dans un tas de 64)"
argus corpus/build/02_heap_bof_vuln --static --no-checksec
pause

echo "### 3. Pipeline complet : statique + dynamique corrélés"
argus corpus/build/02_heap_bof_vuln --static --dynamic \
      --sources corpus/src/02_heap_bof.c --fuzz-timeout 60 --no-checksec \
      --report reports/
pause

echo "### 4. Tableau des protections : CRITICAL (_vuln) vs LOW/INFO (_prot)"
python scripts/comparatif_protections.py
