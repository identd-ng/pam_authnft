# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2025 Avinash H. Duduskar
#
# Container image for running `make test-integration` without touching the
# host's /etc/passwd, /etc/pam.d, nftables state, or systemd units.
#
# Arch base matches the maintainer's development environment. pamtester
# is built from AUR at image-creation time (not present in stock repos).
#
# Build:
#   podman build -t pam_authnft-test -f Containerfile .
#
# Run (see `make test-integration-container` for the canonical invocation):
#   podman run --rm \
#       --systemd=always \
#       --cap-add=NET_ADMIN \
#       --cap-add=SYS_ADMIN \
#       --security-opt label=disable \
#       -v "$PWD:/src:ro,Z" \
#       pam_authnft-test

FROM archlinux:base

# Build and runtime dependencies. libnftables ships inside the nftables
# package on Arch (no separate -devel split).
RUN pacman -Sy --noconfirm --needed \
        base-devel \
        pkgconf \
        nftables \
        libseccomp \
        systemd \
        systemd-sysvcompat \
        libcap \
        pam \
        valgrind \
        keyutils \
        strace \
        sudo \
        git \
    && pacman -Scc --noconfirm

# pamtester is AUR-only. makepkg refuses to run as root, so create a
# throwaway builder user with passwordless sudo, build pamtester as that
# user, install the resulting package as root, then remove the builder.
RUN useradd -m -s /bin/bash builder \
 && echo 'builder ALL=(ALL) NOPASSWD: ALL' > /etc/sudoers.d/builder \
 && su - builder -c 'git clone --depth 1 https://aur.archlinux.org/pamtester.git \
                     && cd pamtester \
                     && makepkg --noconfirm --noprogressbar' \
 && pacman -U --noconfirm /home/builder/pamtester/pamtester-*.pkg.tar.zst \
 && userdel -r builder \
 && rm /etc/sudoers.d/builder

WORKDIR /build

RUN cat > /usr/local/bin/run-integration <<'EOF' \
 && chmod +x /usr/local/bin/run-integration
#!/bin/bash
set -euo pipefail
cp -a /src/. /build/
cd /build
make clean
make
make test
make test-integration
EOF

ENTRYPOINT ["/usr/local/bin/run-integration"]
