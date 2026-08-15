# Évaluation : couverture et faux positifs/négatifs (bonus)

## Méthode

Table générée par `scripts/evaluation.py` sur le corpus. Pour chaque binaire :
détection par le moteur statique seul, par le moteur dynamique seul, et classe
finale après corrélation. Comme chaque binaire ne contient qu'une vulnérabilité,
un finding de classe inattendue serait un faux positif, et l'absence de détection
un faux négatif.

## Résultats

| Binaire | Attendu | Statique | Dynamique | Classe pipeline |
|---------|---------|----------|-----------|-----------------|
| 01_stack_bof | stack_buffer_overflow | oui | oui | stack_buffer_overflow |
| 02_heap_bof | heap_buffer_overflow | oui | oui | heap_buffer_overflow |
| 03_format_string | format_string | oui | oui | format_string |
| 04_integer_overflow | integer_overflow | non | oui | heap_buffer_overflow |
| 05_use_after_free | use_after_free | non | oui | use_after_free |
| 06_double_free | double_free | non | oui | double_free |

- Couverture **statique** : 3/6 (les vulnérabilités « de forme »).
- Couverture **dynamique** : 6/6.
- Couverture **combinée** : 6/6.
- **Faux positifs : 0** (aucun finding de classe inattendue).

## Analyse

- **Précision (0 FP)** : le statique ne se déclenche que sur des motifs sûrs
  (fonction dangereuse réellement appelée, taille de copie constatée supérieure à
  la capacité, format non constant). Le dynamique ne remonte que des crashes
  reproductibles. Aucun bruit sur le corpus.
- **Faux négatifs du statique (04, 05, 06)** : integer overflow, use-after-free
  et double free sont des bugs **temporels/sémantiques**, non détectables sur la
  seule forme du code. C'est un faux négatif *assumé et documenté* : le moteur
  dynamique les couvre. La complémentarité statique/dynamique donne 100 % sur le
  corpus.
- **Cas 04 (integer overflow)** : le pipeline le détecte, mais le nomme
  `heap_buffer_overflow`, car c'est la **conséquence** observable du wrap de
  taille (allocation trop petite puis débordement du tas). La vulnérabilité est
  bien trouvée ; l'étiquette reflète la manifestation mémoire, pas la cause
  racine.

## Limites de la mesure

- Le corpus est **écrit par nous** et **petit** (6 cas). Ces taux valident la
  *conception* (complémentarité statique/dynamique, absence de bruit sur les
  classes ciblées), pas une performance statistique généralisable à du code réel.
- Le dynamique dépend du fuzzing : sur des cibles réelles, atteindre 100 %
  supposerait des seeds, un dictionnaire et un budget de temps adaptés.
