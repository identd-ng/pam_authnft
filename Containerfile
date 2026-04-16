# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2025 Avinash H. Duduskar
#
# Container image for running the unit test suite with CAP_NET_ADMIN,
# on any host that has podman or docker (Fedora, Arch, Debian, Ubuntu,
# RHEL, macOS with podman-machine, etc.). Fedora is the base because
# it ships every dependency in stock repos, but that is an image-level
# detail and does not constrain what the host must run.
#
# Scope: the ten unit stages in tests/test_suite.c, including stages 4
# and 7 which otherwise SKIP without CAP_NET_ADMIN. Stages that talk
# to systemd over sd-bus (`nft_handler_setup`'s fragment-load stage 7
# is the main one) run against the container's libnftables and kernel
# nftables context, not against a booted systemd. The full end-to-end
# pamtester flow (integration 10.1–10.7) requires systemd as PID 1 to
# service `StartTransientUnit` and is therefore run on a real host via
# `make test-integration`, not inside this image.
#
# Build:
#   podman build -t pam_authnft-test -f Containerfile .
#
# Run (see `make test-container` for the canonical invocation):
#   podman run --rm \
#       --cap-add=NET_ADMIN \
#       --security-opt label=disable \
#       -v "$PWD:/src:ro,Z" \
#       pam_authnft-test

FROM registry.fedoraproject.org/fedora:latest

RUN dnf -y install \
        gcc \
        make \
        pkgconf-pkg-config \
        nftables \
        nftables-devel \
        libseccomp-devel \
        systemd-devel \
        libcap-devel \
        pam-devel \
        pamtester \
        valgrind \
        keyutils \
        strace \
        checksec \
        openssl \
        procps-ng \
        util-linux \
        sudo \
        git \
        diffutils \
        which \
    && dnf clean all

WORKDIR /build

RUN cat > /usr/local/bin/run-unit-tests <<'EOF' \
 && chmod +x /usr/local/bin/run-unit-tests
#!/bin/bash
set -euo pipefail
cp -a /src/. /build/
cd /build
make clean
make
make test
EOF

ENTRYPOINT ["/usr/local/bin/run-unit-tests"]
