# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2025 Avinash H. Duduskar

.POSIX:

CC         = gcc
PKG_CONFIG = pkg-config
PAM_DIR    = /usr/lib/security
MAN_DIR    = /usr/share/man/man8
PANDOC     = pandoc
TEST_USER  ?= authnft-test
CFLAGS     =

LIBS      = libnftables libseccomp libsystemd pam libcap

HARDENING = -fstack-clash-protection \
            -fcf-protection \
            -ftrivial-auto-var-init=zero \
            -fstack-protector-strong \
            -Wformat -Wformat-security \
            -Werror=implicit-fallthrough \
            -fno-strict-overflow \
            -Wtrampolines

CFLAGS_BASE  = -fPIC -Wall -Wextra -O2 -Iinclude -D_GNU_SOURCE $(HARDENING)
LDFLAGS_BASE = -Wl,-z,relro,-z,now
SO_LDFLAGS   = $(LDFLAGS_BASE) -shared -Wl,--version-script=pam_authnft.map

TARGET   = pam_authnft.so
TEST_BIN = authnft_test
OBJ_DIR  = obj

OBJS = $(OBJ_DIR)/bus_handler.o \
       $(OBJ_DIR)/event.o       \
       $(OBJ_DIR)/keyring.o     \
       $(OBJ_DIR)/nft_handler.o \
       $(OBJ_DIR)/pam_entry.o   \
       $(OBJ_DIR)/peer_lookup.o \
       $(OBJ_DIR)/sandbox.o

all: $(TARGET)

debug:
	@$(MAKE) clean --no-print-directory
	@$(MAKE) CFLAGS_BASE="$(CFLAGS_BASE) -DDEBUG -g" all --no-print-directory

$(OBJ_DIR)/%.o: src/%.c
	@mkdir -p $(OBJ_DIR)
	$(CC) $(CFLAGS_BASE) `$(PKG_CONFIG) --cflags $(LIBS)` $(CFLAGS) -c $< -o $@

$(TARGET): $(OBJS)
	$(CC) $(SO_LDFLAGS) $(LDFLAGS) -o $@ $(OBJS) `$(PKG_CONFIG) --libs $(LIBS)`

# Unit tests — no root required. Stages that need CAP_NET_ADMIN skip gracefully.
test: test-symbols $(TEST_BIN)
	./$(TEST_BIN)

# Invariant guard #7: exported symbols must be exactly the two PAM entry points.
# Catches missing `static`, accidental re-exports, and broken version scripts.
test-symbols: $(TARGET)
	@echo "[STAGE 0] Exported symbol whitelist..."
	@exported=$$(nm -D --defined-only $(TARGET) | awk '$$2=="T"{print $$3}' | sort | xargs); \
	expected="pam_sm_close_session pam_sm_open_session"; \
	if [ "$$exported" = "$$expected" ]; then \
	    echo "[PASS] exactly two symbols exported"; \
	else \
	    echo "[FAIL] expected \"$$expected\", got \"$$exported\""; \
	    exit 1; \
	fi

# Audit aid for invariant guard #5 (seccomp allowlist provenance).
# Runs one pamtester open+close cycle under `strace -f -c` with the sandbox
# bypassed, producing a syscall summary in trace.log. This is NOT a gate —
# review the summary and diff against SCMP_SYS(...) in src/sandbox.c before
# adding any syscall to the allowlist.
trace: $(TARGET)
	@command -v strace >/dev/null || { echo "strace not installed"; exit 1; }
	@command -v pamtester >/dev/null || { echo "pamtester not installed"; exit 1; }
	sudo ./tests/trace.sh $(CURDIR)/$(TARGET)

# Feature-path companion to `make trace`. Runs the unit suite under
# `strace -f -c` to catalogue syscalls issued by code paths that the
# pamtester-driven trace cannot easily exercise (rhost_policy=kernel
# sock_diag, claims_env keyctl read). Output: trace-features.log plus a
# diff-friendly report on stderr identifying test-harness-only syscalls.
# No root required; no system state modified.
trace-features: $(TEST_BIN)
	@command -v strace >/dev/null || { echo "strace not installed"; exit 1; }
	./tests/trace_features.sh

$(TEST_BIN): $(TARGET)
	$(CC) $(CFLAGS_BASE) $(LDFLAGS_BASE) -g -O1 \
	    tests/test_suite.c $(OBJS) -o $(TEST_BIN) \
	    `$(PKG_CONFIG) --libs $(LIBS)`

# Integration tests — requires root (pamtester, nftables, systemd, valgrind).
# Runs the full session open/close cycle against the live system.
test-integration: $(TEST_BIN)
	sudo ./tests/integration_test.sh $(CURDIR)/$(TARGET)
	sudo -E AUTHNFT_AUDIT_MODE=1 valgrind \
	    --leak-check=full --show-leak-kinds=all --error-exitcode=1 \
	    ./$(TEST_BIN)
	@sudo chown -R $$(id -u):$$(id -g) . 2>/dev/null; true

# Containerised workflows. Every test surface the project ships runs
# inside a booted-systemd container on any host with podman or docker
# — no sudo required, no host state mutation.
#
# The container's PID 1 is systemd; a oneshot unit (authnft-workflow)
# reads /shared/workflow, executes the corresponding make goals,
# writes the exit code to /shared/exit, and halts the container.
# The host-side Makefile recipe reads the exit code back.

CONTAINER_IMG = pam_authnft-test
CONTAINER_BUILD = @command -v podman >/dev/null || { echo "podman not installed"; exit 1; } \
                  ; podman build -t $(CONTAINER_IMG) -f Containerfile . >/dev/null

# Common podman invocation. Callers set RESULT_DIR to a host path
# that will be bind-mounted to /shared, and populate
# $(RESULT_DIR)/workflow with the workflow name before calling.
define RUN_CONTAINER
	podman run --rm \
	    --systemd=always \
	    --cap-add=NET_ADMIN \
	    --cap-add=SYS_ADMIN \
	    --security-opt label=disable \
	    --security-opt seccomp=unconfined \
	    -v $(CURDIR):/src:ro,Z \
	    -v $(RESULT_DIR):/shared:Z \
	    $(CONTAINER_IMG) >/dev/null
	@echo "=== workflow output ==="
	@cat $(RESULT_DIR)/log 2>/dev/null || echo "(no log captured)"
	@EC=$$(cat $(RESULT_DIR)/exit 2>/dev/null || echo 1); \
	 echo "=== container exit: $$EC ==="; \
	 exit $$EC
endef

# Unit tests inside the container (`make test` — 10 stages, all with
# CAP_NET_ADMIN so no stages SKIP on that account).
test-container: RESULT_DIR = $(CURDIR)/.container-result
test-container:
	$(CONTAINER_BUILD)
	@mkdir -p $(RESULT_DIR) && echo unit > $(RESULT_DIR)/workflow
	$(RUN_CONTAINER)

# Full pamtester integration flow inside the container. systemd
# is running as PID 1, so StartTransientUnit over sd-bus works.
# This replaces `sudo make test-integration` as the default
# integration-test path.
test-integration-container: RESULT_DIR = $(CURDIR)/.container-result
test-integration-container:
	$(CONTAINER_BUILD)
	@mkdir -p $(RESULT_DIR) && echo integration > $(RESULT_DIR)/workflow
	$(RUN_CONTAINER)

# Seccomp allowlist trace inside the container. Produces
# trace.log and trace-claims.log, which are copied out to
# $(RESULT_DIR). Replaces `sudo make trace` as the default path.
trace-container: RESULT_DIR = $(CURDIR)/.container-result
trace-container:
	$(CONTAINER_BUILD)
	@mkdir -p $(RESULT_DIR) && echo trace > $(RESULT_DIR)/workflow
	$(RUN_CONTAINER)

install: $(TARGET)
	sudo mkdir -p /etc/authnft/users
	sudo install -m 755 $(TARGET) $(PAM_DIR)/$(TARGET)
	sudo install -m 644 data/authnft.slice /etc/systemd/system/authnft.slice
	sudo systemctl daemon-reload

uninstall:
	sudo rm -f $(PAM_DIR)/$(TARGET)
	sudo rm -f $(MAN_DIR)/pam_authnft.8.gz

# Manpage — requires pandoc. Builds pam_authnft.8 from man/pam_authnft.8.md.
man: man/pam_authnft.8

man/pam_authnft.8: man/pam_authnft.8.md
	$(PANDOC) -s -t man $< -o $@

install-man: man/pam_authnft.8
	sudo install -d $(MAN_DIR)
	sudo install -m 644 man/pam_authnft.8 $(MAN_DIR)/pam_authnft.8
	sudo gzip -f $(MAN_DIR)/pam_authnft.8

clean:
	rm -rf $(OBJ_DIR) $(TARGET) $(TEST_BIN) *.d rules.tmp trace.log trace-claims.log trace-features.log man/pam_authnft.8 .container-result

distclean: clean
	@if sudo nft list tables 2>/dev/null | grep -q "inet authnft"; then \
	    sudo nft delete table inet authnft; \
	fi
	@sudo rm -f /etc/pam.d/authnft_test /etc/authnft/users/$(TEST_USER)

.PHONY: all debug clean test test-symbols test-integration test-container \
        test-integration-container trace trace-container trace-features \
        distclean install uninstall man install-man
