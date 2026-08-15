# Makefile du corpus : compile chaque source C en trois profils de protection.
#
#   _vuln : toutes les protections DÉSACTIVÉES (cible d'exploitation / PoC)
#   _prot : toutes les protections ACTIVÉES (étude de l'impact des mitigations)
#   _asan : instrumenté AddressSanitizer (triage précis des crashes en Phase 4)
#
# Chaque binaire lit son entrée sur stdin (compatible fuzzing).
# Usage : make            (compile les 3 profils)
#         make vuln|prot|asan
#         make clean

CC      ?= gcc
SRCDIR  := src
OUTDIR  := build
SOURCES := $(wildcard $(SRCDIR)/*.c)
NAMES   := $(basename $(notdir $(SOURCES)))

VULN := $(addprefix $(OUTDIR)/,$(addsuffix _vuln,$(NAMES)))
PROT := $(addprefix $(OUTDIR)/,$(addsuffix _prot,$(NAMES)))
ASAN := $(addprefix $(OUTDIR)/,$(addsuffix _asan,$(NAMES)))

# -Wno-format-security : les bugs sont volontaires, on veut compiler quand même.

# Profil VULN : NX off (execstack), pas de canary, pas de PIE, pas de RELRO,
# FORTIFY désactivé. -O0 pour garder le code proche de la source.
CFLAGS_VULN  := -O0 -g -fno-stack-protector -fno-pie \
                -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=0 -Wno-format-security
LDFLAGS_VULN := -no-pie -z norelro -z execstack

# Profil PROT : canary partout, PIE, RELRO complet (relro + now), FORTIFY.
# FORTIFY_SOURCE n'agit qu'à partir de -O1, donc on compile en -O2.
CFLAGS_PROT  := -O2 -g -fstack-protector-all -fPIE \
                -D_FORTIFY_SOURCE=2 -Wno-format-security
LDFLAGS_PROT := -pie -Wl,-z,relro -Wl,-z,now

# Profil ASAN : instrumentation mémoire pour un triage exact (type + trace).
CFLAGS_ASAN  := -O1 -g -fsanitize=address -fno-omit-frame-pointer -Wno-format-security
LDFLAGS_ASAN := -fsanitize=address

.PHONY: all vuln prot asan clean list
.DELETE_ON_ERROR:

all: $(VULN) $(PROT) $(ASAN)
vuln: $(VULN)
prot: $(PROT)
asan: $(ASAN)

$(OUTDIR)/%_vuln: $(SRCDIR)/%.c | $(OUTDIR)
	$(CC) $(CFLAGS_VULN) $< -o $@ $(LDFLAGS_VULN)

$(OUTDIR)/%_prot: $(SRCDIR)/%.c | $(OUTDIR)
	$(CC) $(CFLAGS_PROT) $< -o $@ $(LDFLAGS_PROT)

$(OUTDIR)/%_asan: $(SRCDIR)/%.c | $(OUTDIR)
	$(CC) $(CFLAGS_ASAN) $< -o $@ $(LDFLAGS_ASAN)

$(OUTDIR):
	mkdir -p $(OUTDIR)

list:
	@echo "Sources : $(NAMES)"

clean:
	rm -rf $(OUTDIR)
