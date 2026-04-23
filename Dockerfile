FROM ubuntu:22.04
ENV DEBIAN_FRONTEND=noninteractive

# =============================================================================
# 1. System packages (kernel build deps + LLVM-14 + Python)
# =============================================================================
RUN apt-get update && apt-get install -y --no-install-recommends \
    sudo git time bear build-essential cmake ninja-build \
    llvm-14 llvm-14-tools clang-14 lldb-14 lld-14 clangd-14 libclang-14-dev \
    python3 python3-pip python3-venv python3-dev \
    flex bison bc rsync kmod cpio \
    libssl-dev libelf-dev libncurses-dev dwarves \
    libsqlite3-dev zlib1g-dev liblzma-dev libicu-dev libbz2-dev \
    libglib2.0-dev libgcrypt20-dev libpcap-dev libc-ares-dev \
    libgtest-dev libgoogle-perftools-dev \
    wget unzip curl jq file ripgrep parallel pkg-config \
    autoconf automake libtool git-lfs \
    universal-ctags \
    && rm -rf /var/lib/apt/lists/*

# =============================================================================
# 2. Normalize LLVM-14 tool names (idempotent alternatives)
# =============================================================================
RUN update-alternatives --install /usr/bin/clang clang /usr/bin/clang-14 200 \
      --slave /usr/bin/clang++ clang++ /usr/bin/clang++-14 && \
    for tool in llvm-config llvm-link llvm-dis llvm-ar llvm-nm opt; do \
        if [ -f "/usr/bin/${tool}-14" ]; then \
            update-alternatives --install "/usr/bin/${tool}" "${tool}" "/usr/bin/${tool}-14" 200; \
        fi; \
    done && \
    ln -sf /usr/bin/ld.lld-14 /usr/bin/ld.lld

# =============================================================================
# 3. Build Z3 (pinned tag for reproducibility)
# =============================================================================
ARG Z3_VERSION=4.12.4

RUN git clone --depth 1 --branch z3-${Z3_VERSION} https://github.com/Z3Prover/z3.git /tmp/z3 && \
    cd /tmp/z3 && \
    python3 scripts/mk_make.py --prefix=/opt/z3 && \
    cd build && make -j$(nproc) && make install && \
    rm -rf /tmp/z3

ENV PATH="/opt/z3/bin:${PATH}"
ENV LD_LIBRARY_PATH="/opt/z3/lib:${LD_LIBRARY_PATH:-}"

# =============================================================================
# 4. Build KLEE with Z3 + uclibc POSIX runtime (pinned v3.1)
# =============================================================================
RUN mkdir -p /opt/tools && cd /opt/tools && \
    git clone --depth 1 https://github.com/klee/klee-uclibc.git && \
    cd klee-uclibc && \
    ./configure --make-llvm-lib \
        --with-cc /usr/lib/llvm-14/bin/clang \
        --with-llvm-config /usr/lib/llvm-14/bin/llvm-config && \
    make -j$(nproc) && \
    cd /opt/tools && \
    git clone --depth 1 --branch v3.1 https://github.com/klee/klee.git && \
    cd klee && mkdir build && cd build && \
    cmake .. \
      -DCMAKE_C_COMPILER=/usr/lib/llvm-14/bin/clang \
      -DCMAKE_CXX_COMPILER=/usr/lib/llvm-14/bin/clang++ \
      -DCMAKE_INSTALL_PREFIX=/opt/klee \
      -DLLVM_CONFIG_BINARY=/usr/lib/llvm-14/bin/llvm-config \
      -DLLVMCC=/usr/lib/llvm-14/bin/clang \
      -DLLVMCXX=/usr/lib/llvm-14/bin/clang++ \
      -DENABLE_SOLVER_Z3=ON \
      -DZ3_INCLUDE_DIRS=/opt/z3/include \
      -DZ3_LIBRARIES=/opt/z3/lib/libz3.so \
      -DENABLE_POSIX_RUNTIME=ON \
      -DKLEE_UCLIBC_PATH=/opt/tools/klee-uclibc \
      -DENABLE_UNIT_TESTS=OFF \
      -DENABLE_SYSTEM_TESTS=OFF \
      -DENABLE_TCMALLOC=OFF \
      -G Ninja && \
    ninja -j$(nproc) && ninja install && \
    cd /opt/tools && rm -rf klee/build klee-uclibc/build

ENV PATH="/opt/klee/bin:${PATH}"
ENV C_INCLUDE_PATH="/opt/klee/include:${C_INCLUDE_PATH:-}"

RUN klee --version && z3 --version

# =============================================================================
# 5. CodeQL CLI (pinned version -- latest may be incompatible with older packs)
# =============================================================================
ARG CODEQL_VERSION=2.17.6

RUN mkdir -p /opt/codeql-cli && \
    wget -q "https://github.com/github/codeql-cli-binaries/releases/download/v${CODEQL_VERSION}/codeql-linux64.zip" \
      -O /tmp/codeql.zip && \
    unzip -q /tmp/codeql.zip -d /opt/codeql-cli && \
    rm /tmp/codeql.zip && \
    ln -sf /opt/codeql-cli/codeql/codeql /usr/bin/codeql && \
    codeql version

RUN rm -rf /root/.codeql/packages 2>/dev/null || true && \
    codeql pack download codeql/cpp-queries@1.0.0 codeql/cpp-all@1.0.0 && \
    echo "=== Installed CodeQL packs ===" && \
    find /root/.codeql/packages/codeql/ -mindepth 1 -maxdepth 2 -type d | sort

# =============================================================================
# 6. Python venv + SAILOR deps (install deps BEFORE copy for layer caching)
# =============================================================================
WORKDIR /app

COPY requirements.txt /app/requirements.txt
RUN python3 -m venv /app/venv && \
    /app/venv/bin/pip install --upgrade pip && \
    /app/venv/bin/pip install -r /app/requirements.txt

# =============================================================================
# 7. Copy project + finalize
# =============================================================================
COPY . .

RUN chmod +x *.sh *.py 2>/dev/null || true && \
    find sailor_engine/ -name "*.sh" -exec chmod +x {} \; 2>/dev/null || true && \
    mkdir -p dataset sa_outputs specs se_runs artifacts

# Install local CodeQL query pack dependencies
RUN if [ -f rules/sailor-queries/qlpack.yml ]; then \
      codeql pack install rules/sailor-queries || true; \
    fi

# --- Environment ---
ENV LLVM_COMPILER=clang \
    LLVM_COMPILER_PATH=/usr/lib/llvm-14/bin \
    CC=/usr/lib/llvm-14/bin/clang \
    CXX=/usr/lib/llvm-14/bin/clang++ \
    CLANG=/usr/lib/llvm-14/bin/clang \
    LLVM_LINK=/usr/lib/llvm-14/bin/llvm-link \
    LLVM_NM=/usr/lib/llvm-14/bin/llvm-nm \
    KLEE=/opt/klee/bin/klee \
    WLLVM_LLVM_LINK=llvm-link \
    SE_RUNS_ROOT=/app/se_runs \
    SA_OUT_DIR=/app/sa_outputs \
    DATASET_ROOT=/app/dataset \
    SAILOR_ROOT=/app \
    PATH="/app/venv/bin:/opt/klee/bin:/opt/codeql-cli/codeql:${PATH}" \
    VIRTUAL_ENV=/app/venv

# --- Verify ---
RUN echo "=== SAILOR Build Verification ===" && \
    clang-14 --version | head -1 && \
    klee --version | head -1 && \
    z3 --version && \
    codeql version --format=terse && \
    python3 --version && \
    python3 -c "import openai; print('openai OK')" && \
    echo "=== All tools verified ==="

CMD ["/bin/bash"]
