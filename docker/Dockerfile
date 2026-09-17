# Environnement de démo reproductible pour argus (pipeline de détection de
# vulnérabilités bas niveau). L'image est construite en linux/amd64 : le corpus
# doit être du vrai ELF x86-64 pour que la disasm capstone, les offsets et le
# PoC (contrôle de RIP à l'offset 72) correspondent au rapport.
#
#   docker build --platform linux/amd64 -t argus:demo -f docker/Dockerfile .
#   docker run --rm -it --platform linux/amd64 argus:demo
#
FROM --platform=linux/amd64 ubuntu:24.04

# AFL_CC_COMPILER=GCC_PLUGIN : force le mode plugin GCC (afl-cc part sinon en
# LLVM/clang, qui exige compiler-rt asan absent ici). C'est aussi le mode décrit
# dans la soutenance. AFL++ est résolu via le PATH par pipeline/dynamic/afl_env.
ENV DEBIAN_FRONTEND=noninteractive \
    AFL_CC_COMPILER=GCC_PLUGIN \
    PATH=/opt/venv/bin:/root/.cargo/bin:/opt/AFLplusplus:/usr/local/bin:/usr/bin:/bin

# --- Outillage système : build C, ELF, checksec, LLVM + plugin GCC pour AFL++ ---
RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential \
        clang \
        llvm-dev \
        libclang-dev \
        gcc-13-plugin-dev \
        make \
        cmake \
        git \
        curl \
        ca-certificates \
        pkg-config \
        libssl-dev \
        zlib1g-dev \
        python3 \
        python3-venv \
        python3-dev \
        checksec \
        binutils \
        gdb \
    && rm -rf /var/lib/apt/lists/*

# --- AFL++ compilé depuis les sources dans un dossier unique ($AFL_DIR) ---
# afl-fuzz, afl-cc et afl-compiler-rt.o coexistent dans ce dossier, ce que la
# résolution afl_env.afl_dir() du pipeline attend (AFL_PATH = ce dossier).
RUN git clone --depth 1 --branch stable \
        https://github.com/AFLplusplus/AFLplusplus /opt/AFLplusplus \
    && make -C /opt/AFLplusplus NO_NYX=1 source-only \
    && rm -rf /opt/AFLplusplus/.git

# --- CASR : triage des crashes (type + exploitabilité) ---
RUN curl -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal \
    && /root/.cargo/bin/cargo install casr --locked \
    && rm -rf /root/.cargo/registry /root/.cargo/git

# Ubuntu active _FORTIFY_SOURCE par défaut dès -O1 : read(buf, 4096) dans un tas
# de 64 déclenche alors le garde-fou glibc (SIGABRT) AVANT qu'ASan ne voie le
# débordement, et CASR ne classe plus qu'un « AbortSignal ». Arch (cible de réf)
# n'auto-active pas FORTIFY. On neutralise ce défaut via un wrapper cc/gcc pour
# que le rapport ASan (donc CASR) porte la vraie classe. Le profil _prot du
# corpus redéfinit -D_FORTIFY_SOURCE=2 après ces flags : sa protection est
# préservée (dernière définition gagnante).
RUN for w in cc gcc c++ g++; do \
        printf '#!/bin/sh\nexec /usr/bin/%s -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=0 "$@"\n' "$w" \
            > "/usr/local/bin/$w" && chmod +x "/usr/local/bin/$w"; \
    done

# --- Environnement Python + paquet argus ---
WORKDIR /app
COPY pyproject.toml README.md ./
COPY pipeline ./pipeline
RUN python3 -m venv /opt/venv \
    && pip install --no-cache-dir -U pip \
    && pip install --no-cache-dir -e ".[dev,poc]"

# --- Reste du projet + compilation du corpus ELF x86-64 (3 profils) ---
COPY . .
RUN make -C corpus all

# Le fuzzer règle lui-même AFL_SKIP_CPUFREQ / AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES
# et ASAN_OPTIONS à l'exécution (pipeline/dynamic/fuzzer.py). CASR a besoin du
# syscall personality : lancer le conteneur avec --security-opt seccomp=unconfined.
CMD ["/bin/bash"]
