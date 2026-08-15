# PoC : génération automatique et contrôle de RIP (bonus §4)

`poc_stack_bof.py` démontre, sur `01_stack_bof_vuln` (profil sans protections :
no-PIE, sans canary, NX off), les deux étapes classiques d'une exploitation de
débordement de pile :

1. **Découverte de l'offset** buffer -> adresse de retour via un motif cyclique
   (pwntools `cyclic` / `cyclic_find`), en lisant l'adresse de retour écrasée
   sous gdb.
2. **Preuve de contrôle de RIP** : envoi de `offset x 'A' + p64(0xdeadbeef)`, puis
   vérification que `RIP == 0xdeadbeef` au crash.

## Exécution

```
python poc/poc_stack_bof.py
```

Sortie attendue :

```
[+] Offset buffer -> saved RIP : 72 octets
[+] RIP au moment du crash : 0xdeadbeef
[OK] Contrôle de RIP démontré : RIP = 0xdeadbeef.
```

## Lien avec le double sens d'« offset »

L'offset trouvé ici (72) est la **distance buffer -> RIP**, celle de
l'exploitation. C'est un sens différent de l'offset **statique** du rapport
(l'adresse de l'instruction vulnérable). argus expose les deux (`static_offset`
et `exploit_offset`).
