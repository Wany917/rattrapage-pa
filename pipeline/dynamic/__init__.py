"""Moteur d'analyse dynamique : build instrumenté, fuzzing AFL++, triage.

  - `builder` : recompile la cible en profils instrumentés (ASan, AFL++) ;
  - `fuzzer`  : pilote AFL++ (seeds, mutation guidée par la couverture) ;
  - `triage`  : rejoue les crashes et les classe via AddressSanitizer et CASR.
"""
