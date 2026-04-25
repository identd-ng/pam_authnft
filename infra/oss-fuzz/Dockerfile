# OSS-Fuzz builder image for pam_authnft.
# The base-builder image provides clang, compiler-rt/libFuzzer, and the
# OSS-Fuzz build infrastructure. We only need to add the library
# dependencies that pam_authnft links against.
FROM gcr.io/oss-fuzz-base/base-builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    pkg-config \
    libnftables-dev \
    libseccomp-dev \
    libsystemd-dev \
    libpam0g-dev \
    libcap-dev \
    libaudit-dev \
    && rm -rf /var/lib/apt/lists/*

COPY build.sh $SRC/
WORKDIR $SRC
RUN git clone --depth 1 https://github.com/identd-ng/pam_authnft
