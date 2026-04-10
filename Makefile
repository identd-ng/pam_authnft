.POSIX:

CC        = gcc
PKG_CONFIG = pkg-config
PAM_DIR   = /usr/lib/security

LIBS      = libnftables libseccomp libsystemd pam libcap

HARDENING = -fstack-clash-protection \
            -fcf-protection \
            -ftrivial-auto-var-init=zero \
            -fstack-protector-strong \
            -Wformat -Wformat-security \
            -Werror=implicit-fallthrough \
            -fno-strict-overflow \
            -Wtrampolines

CFLAGS_BASE  = -fPIC -Wall -Wextra -Iinclude -D_GNU_SOURCE $(HARDENING)
LDFLAGS_BASE = -Wl,-z,relro,-z,now
SO_LDFLAGS   = $(LDFLAGS_BASE) -shared -Wl,--version-script=pam_authnft.map

TARGET   = pam_authnft.so
TEST_BIN = authnft_test
OBJ_DIR  = obj

OBJS = $(OBJ_DIR)/bus_handler.o \
       $(OBJ_DIR)/nft_handler.o \
       $(OBJ_DIR)/pam_entry.o   \
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
test: $(TEST_BIN)
	./$(TEST_BIN)

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

install: $(TARGET)
	sudo mkdir -p /etc/authnft/users
	sudo install -m 755 $(TARGET) $(PAM_DIR)/$(TARGET)

uninstall:
	sudo rm -f $(PAM_DIR)/$(TARGET)

clean:
	rm -rf $(OBJ_DIR) $(TARGET) $(TEST_BIN)

distclean: clean
	@if sudo nft list tables 2>/dev/null | grep -q "inet authnft"; then \
	    sudo nft delete table inet authnft; \
	fi
	@sudo rm -f /etc/pam.d/authnft_test /etc/authnft/users/strykar-test

.PHONY: all debug clean test test-integration distclean install uninstall
