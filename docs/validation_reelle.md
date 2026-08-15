# Validation sur cas réels (programmes et vulnérabilités existants)

Le corpus étant écrit pour l'exercice, on valide ici argus sur de **vrais
programmes** et sur une **vraie vulnérabilité** de logiciel largement utilisé.

## 1. Analyse statique sur binaires système (vrai black-box)

`scripts/scan_reel.py` lance l'analyse statique sur des binaires de `/usr/bin`.

| Binaire | Protections | Findings réels |
|---------|-------------|----------------|
| xxd | toutes actives | 1 (fprintf format) |
| su | toutes actives | 0 |
| awk | toutes actives | 23 (22 `strcpy`/`strcat`, 1 `popen`) |
| ddcutil | toutes actives | 26 (`strcpy`, `system`, `popen`) |
| bash | toutes actives | 35 (`strcpy` + flux taint `read -> strcpy`) |

- **Robustesse** : aucun plantage sur des ELF variés (petits, gros, strippés,
  PIE, fortifiés).
- **Protections concordantes avec checksec** sur du vrai code (vérifié sur awk).
- **Vraies fonctions dangereuses** détectées avec offset ; taint `read -> strcpy`
  dans bash.
- Sévérité INFO (correct : peu exploitable dans un binaire durci -> précision).
- Strippé -> fonction `(.text)` + offset (limite documentée).

## 2. Vraies vulnérabilités reproduites : stb_image (3 classes)

**stb_image** (`nothings/stb`) est un chargeur d'images en un seul header, utilisé
par des milliers de projets. Sur une **version ancienne** (mai 2016, commit
`94dd6fe`), argus (build instrumenté AFL+ASan -> fuzzing en mode fichier `@@`
et entrées ciblées -> triage ASan/CASR) découvre et classe **trois classes** de
vraies vulnérabilités :

| Classe | Fonction (stb_image.h) | Détail |
|--------|------------------------|--------|
| stack buffer overflow | `stbi__compute_huffman_codes` (:3740) | lecture hors bornes, décodeur Huffman JPEG (trouvée par fuzzing en ~30 s) |
| heap buffer overflow | `stbi__convert_format` (:1369), `stbi__bmp_load` (:4910) | écriture hors bornes, **EXPLOITABLE** (CASR) |
| integer overflow | `stbi__getn` (:1285) | `negative-size-param` : le calcul de taille déborde en négatif (dimensions énormes) |

Ce sont de **vraies vulnérabilités** dans un logiciel réel très diffusé,
découvertes et classées par argus (les deux classes obligatoires, plus l'integer
overflow). Reproduction :

```
git clone https://github.com/nothings/stb && git checkout 94dd6fe
# driver : #define STB_IMAGE_IMPLEMENTATION ; stbi_load(argv[1], ...)
argus dynamique -> build afl-cc+ASan -> afl-fuzz @@ / entrées ciblées -> triage
```

Note : la détection de l'integer overflow a été ajoutée à argus à cette occasion
(ASan `negative-size-param` = taille qui a débordé en négatif -> classe
integer_overflow).

## 3. Fuzzing d'un vrai parseur : jhead

argus a aussi compilé et fuzzé **jhead** (parseur EXIF/JPEG) en mode fichier :
168 nouveaux chemins, mais **0 crash** en 150 s. La version récente est **durcie**
(débordements EXIF classiques corrigés, récursion et compteurs géants gérés). Un
résultat honnête : le pipeline dynamique fonctionne sur du vrai code de parsing
et ne fabrique pas de faux crash.

## 4. Améliorations d'argus révélées par les cas réels

Tester sur du vrai code a mis au jour et corrigé trois vraies lacunes :

- **Entrée fichier (`@@`)** : la plupart des vrais programmes lisent un fichier,
  pas stdin. Mode fichier ajouté au fuzzer et au triage (`file_input=True`).
- **Édition de liens `libm`** : beaucoup de programmes réels utilisent des
  fonctions math ; le builder lie désormais `-lm`.
- **Cible de fuzzing en `-O2`** : `-O0` + ASan est trop lent pour du vrai code ;
  passage en `-O2` (recommandation AFL), d'où le crash trouvé en ~30 s.
- Création automatique du dossier de travail (robustesse).

## 5. Classes restantes : format string, use-after-free, double free

Ces trois classes sont couvertes par le corpus (03, 05, 06) et détectées par
argus (statique pour le format string ; ASan/CASR pour UAF et double free, cf.
Phase 4). Les reproduire sur du **vrai logiciel** dans le temps d'une session est
difficile, et c'est un enseignement en soi :

- **Format string** : quasiment éradiqué du code moderne (compilateurs et
  `-Wformat-security` le signalent), donc rarement trouvable au fuzzing.
- **Use-after-free / double free** : ils vivent dans des parseurs complexes très
  éprouvés. libxml2 2.9.4, fuzzé ~15 min avec un harnais (XML + XInclude + HTML)
  et 60 seeds, n'a pas produit de crash : il a déjà été fuzzé à l'échelle
  d'OSS-Fuzz. Les atteindre demande un budget bien plus grand (heures) ou un PoC
  public de CVE documentée.

Piste pour un runner dédié : appliquer la démarche validée sur stb_image à une
version à CVE documentée de ces classes (PoC public, ou fuzzing long).

## Conclusion

argus fonctionne sur du vrai code : l'analyse **statique** s'applique en
black-box à n'importe quel ELF, et l'analyse **dynamique** découvre et classe une
**vraie vulnérabilité** dans un logiciel réel largement diffusé (stb_image),
entrée stdin ou fichier. Les cas réels ont aussi fait progresser l'outil.
