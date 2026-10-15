# Same Ubuntu 24.04 everyone uses, with the C tools and liboqs already installed.
FROM mcr.microsoft.com/devcontainers/base:ubuntu-24.04

# C compiler, build tools, OpenSSL headers, and two debugging helpers (gdb, valgrind)
RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential cmake ninja-build libssl-dev git curl gdb valgrind \
    && rm -rf /var/lib/apt/lists/*

# liboqs, pinned to one release so all three of us build identical code.
# Only ML-KEM-768 and ML-DSA-65 are built, which keeps the build fast.
ARG LIBOQS_VERSION=0.16.0
RUN curl -sSL https://github.com/open-quantum-safe/liboqs/archive/refs/tags/${LIBOQS_VERSION}.tar.gz | tar xz -C /tmp \
    && cmake -S /tmp/liboqs-${LIBOQS_VERSION} -B /tmp/liboqs-build -GNinja \
        -DCMAKE_BUILD_TYPE=Release -DBUILD_SHARED_LIBS=OFF -DOQS_BUILD_ONLY_LIB=ON \
        -DOQS_MINIMAL_BUILD="KEM_ml_kem_768;SIG_ml_dsa_65" -DCMAKE_INSTALL_PREFIX=/usr/local \
    && cmake --build /tmp/liboqs-build \
    && cmake --install /tmp/liboqs-build \
    && rm -rf /tmp/liboqs-*
