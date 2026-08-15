"""Point d'entrée « python -m pipeline » (équivalent à la commande argus)."""

import sys

from pipeline.cli import main

if __name__ == "__main__":
    sys.exit(main())
