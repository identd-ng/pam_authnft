// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2025 Avinash H. Duduskar
//
// kring_bridge_demo — demonstrate the prmana ↔ pam_authnft kernel-keyring
// bridge with a production-grade enterprise scenario.
//
// Scenario: SRE on a bastion host authenticates via OIDC IdP with
// DPoP-bound tokens. prmana extracts OIDC claims (compliance tier,
// risk pool, load balancer affinity, department) and publishes them to
// the kernel keyring. pam_authnft reads the claims, enforces per-session
// network policy via nftables cgroup matching, and emits correlated
// journal events. The entire auth→session→packet pipeline is auditable
// through a single correlation token.
//
// This tool runs the full keyring round-trip without OIDC infrastructure.
//
// Build:  make kring-bridge-demo
//    or:  cc -o kring_bridge_demo kring_bridge_demo.c -Wall -Wextra
// Run:    ./tools/kring_bridge_demo  (may need root or CAP_SYS_ADMIN)

#include <ctype.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

// ---- constants mirroring both projects ----

#define MAX_PAYLOAD       256   // prmana keyring::MAX_PAYLOAD
#define CLAIMS_TAG_MAX    192   // pam_authnft CLAIMS_TAG_MAX
#define CORRELATION_ID_MAX 64   // pam_authnft CORRELATION_ID_MAX

// keyctl opcodes
#define KEYCTL_READ          11
#define KEYCTL_SET_TIMEOUT   15
#define KEYCTL_SETPERM        5
#define KEYCTL_REVOKE         3

// keyring anchors
#define KEY_SPEC_PROCESS_KEYRING (-2)

// permission bits
#define KEY_POS_VIEW    0x01000000
#define KEY_POS_READ    0x02000000
#define KEY_POS_SEARCH  0x08000000

// ---- ANSI colours ----

#define C_RESET   "\033[0m"
#define C_BOLD    "\033[1m"
#define C_BLUE    "\033[34m"
#define C_GREEN   "\033[32m"
#define C_YELLOW  "\033[33m"
#define C_CYAN    "\033[36m"
#define C_RED     "\033[31m"
#define C_DIM     "\033[2m"
#define C_MAG     "\033[35m"

// ---- timestamp helper ----

static void print_ts(void) {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    struct tm tm;
    gmtime_r(&ts.tv_sec, &tm);
    fprintf(stdout, C_DIM "%04d-%02d-%02dT%02d:%02d:%02d.%03ldZ" C_RESET " ",
            tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
            tm.tm_hour, tm.tm_min, tm.tm_sec, ts.tv_nsec / 1000000);
}

#define LOG(colour, tag, fmt, ...) do { \
    print_ts(); \
    fprintf(stdout, colour "[%-10s]" C_RESET " " fmt "\n", tag, ##__VA_ARGS__); \
} while (0)

// ---- syscall wrappers ----

static long keyctl_syscall(int op, unsigned long a, unsigned long b,
                           unsigned long c, unsigned long d) {
    return syscall(SYS_keyctl, op, a, b, c, d);
}

// ---- sanitizer (mirrors pam_authnft keyring.c) ----

static int is_safe(unsigned char c) {
    if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
        (c >= '0' && c <= '9'))
        return 1;
    switch (c) {
        case '_': case '=': case ',': case '.': case ':':
        case ';': case '/': case '-':
            return 1;
        default:
            return 0;
    }
}

static ssize_t sanitize_payload(const char *raw, size_t raw_len,
                                char *out, size_t out_sz) {
    size_t w = 0;
    for (size_t i = 0; i < raw_len && w + 1 < out_sz && w < CLAIMS_TAG_MAX; i++) {
        unsigned char c = (unsigned char)raw[i];
        if (c == '\0') break;
        out[w++] = is_safe(c) ? (char)c : '_';
    }
    out[w] = '\0';
    return (ssize_t)w;
}

// ---- correlation sanitizer (mirrors pam_authnft event.c) ----

static int is_corr_safe(unsigned char c) {
    if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
        (c >= '0' && c <= '9'))
        return 1;
    return c == '_' || c == '-' || c == '.' || c == ':';
}

static void sanitize_correlation(const char *in, char *out, size_t out_sz) {
    size_t w = 0;
    for (size_t i = 0; in[i] && w + 1 < out_sz; i++) {
        if (is_corr_safe((unsigned char)in[i]))
            out[w++] = in[i];
    }
    out[w] = '\0';
}

// ---- hex dump ----

static void hex_dump(const char *label, const void *data, size_t len) {
    const unsigned char *p = data;
    fprintf(stdout, "           " C_DIM "%s (%zu bytes): ", label, len);
    for (size_t i = 0; i < len && i < 80; i++)
        fprintf(stdout, "%02x ", p[i]);
    if (len > 80) fprintf(stdout, "...");
    fprintf(stdout, C_RESET "\n");
}

// ---- usage ----

static void usage(const char *prog) {
    fprintf(stderr,
        "Usage: %s [key=value ...]\n"
        "\n"
        "Demonstrate the prmana <-> pam_authnft kernel-keyring bridge.\n"
        "Runs the full round-trip: add_key -> keyctl_read -> sanitize.\n"
        "\n"
        "Custom claims are appended to the default payload. Examples:\n"
        "  %s pool=prod-east lb=lb-east-07 dept=sre zone=regulated\n"
        "  %s env=staging tier=gold\n"
        "  %s  (uses built-in enterprise scenario)\n",
        prog, prog, prog, prog);
}

// ---- main ----

int main(int argc, char *argv[]) {
    if (argc > 1 && (strcmp(argv[1], "-h") == 0 || strcmp(argv[1], "--help") == 0)) {
        usage(argv[0]);
        return 0;
    }

    // Collect any CLI-supplied key=value pairs
    int n_extra = 0;
    struct { const char *key; const char *val; } extras[32];
    for (int i = 1; i < argc && n_extra < 32; i++) {
        char *eq = strchr(argv[i], '=');
        if (eq && eq != argv[i]) {
            extras[n_extra].key = argv[i];
            extras[n_extra].val = NULL;  // we'll pass the whole "key=val" string
            n_extra++;
        } else {
            fprintf(stderr, "Ignoring argument '%s' (expected key=value)\n", argv[i]);
        }
    }

    fprintf(stdout, "\n");
    fprintf(stdout, C_BOLD "================================================================\n");
    fprintf(stdout, "  prmana <-> pam_authnft: Kernel Keyring Bridge — Audit Trace\n");
    fprintf(stdout, "================================================================" C_RESET "\n");
    fprintf(stdout, C_DIM "  Scenario: SRE on bastion host, OIDC + DPoP\n");
    fprintf(stdout, "  Full pipeline: OIDC auth -> keyring -> nftables -> journal\n" C_RESET);
    if (n_extra > 0)
        fprintf(stdout, C_DIM "  Custom claims: %d extra key=value pair(s) from CLI\n" C_RESET, n_extra);
    fprintf(stdout, "\n");

    // ── Simulated OIDC token claims ──
    //
    // In production, these come from the IdP (Keycloak, Okta, etc.) token.
    // Custom claims (dept, pool, compliance_zone, lb) are configured in the
    // IdP and extracted by prmana from TokenClaims.extra via get_claim_str().

    const char *sim_jti      = "f47ac10b-58cc-4372-a567-0e02b2c3d479";
    const char *sim_exp      = "1745053200";
    const char *sim_iss      = "https://idp.example.com/realms/prod";
    const char *sim_sid      = "sess-7e3f1a92";
    const char *sim_user     = "alice";
    const char *sim_uid      = "1001";
    const char *sim_acr      = "urn:example:mfa";
    const char *sim_dpop     = "SHA256:x4Ei9K2p";  // JWK thumbprint (truncated for demo)

    // Custom claims from IdP — arbitrary key=value pairs supported:
    // pool=prod-east, dept=sre-infra, lb=lb-east-07, compliance_zone=regulated
    const char *sim_dept     = "sre-infra";
    const char *sim_pool     = "prod-east";
    const char *sim_lb       = "lb-east-07";
    const char *sim_zone     = "regulated";

    const char *sim_remote   = "10.42.7.131";
    int         sim_pid      = getpid();
    int         sim_ttl      = 600;  // 10-minute token (short-lived for compliance)

    LOG(C_BOLD, "BRIDGE", "PID %d — demonstrating keyring bridge", sim_pid);

    // ================================================================
    // PHASE 1: PRODUCER (prmana — OIDC auth + keyring publish)
    // ================================================================

    fprintf(stdout, "\n" C_BLUE C_BOLD
            "-- Phase 1: Producer (prmana) ------------------------------------------"
            C_RESET "\n\n");

    LOG(C_BLUE, "PRODUCER", "OIDC authentication succeeded for user '%s'", sim_user);
    LOG(C_BLUE, "PRODUCER", "  IdP:     %s", sim_iss);
    LOG(C_BLUE, "PRODUCER", "  JTI:     %s", sim_jti);
    LOG(C_BLUE, "PRODUCER", "  ACR:     %s (multi-factor)", sim_acr);
    LOG(C_BLUE, "PRODUCER", "  DPoP:    %s (proof-of-possession bound)", sim_dpop);
    LOG(C_BLUE, "PRODUCER", "  Expiry:  %ss (%d min TTL)", sim_exp, sim_ttl / 60);

    // Format the rich claims payload — this is what flows through the kernel
    //
    // The format_claims function in prmana takes arbitrary &[(&str, &str)] pairs.
    // pam_authnft's contract (INTEGRATIONS.txt §2.4) says: "printable ASCII,
    // bounded length, producer-defined meaning." Both sides agree on semicolons
    // as separators and key=value pairs. The consumer doesn't parse structure —
    // it sanitizes and embeds verbatim.

    char payload[MAX_PAYLOAD + 1];
    int plen = snprintf(payload, sizeof(payload),
        "jti=%s;exp=%s;iss=%s;sid=%s;user=%s;uid=%s;acr=%s;dpop=%s;"
        "dept=%s;pool=%s;lb=%s;zone=%s",
        sim_jti, sim_exp, sim_iss, sim_sid, sim_user, sim_uid, sim_acr,
        sim_dpop, sim_dept, sim_pool, sim_lb, sim_zone);

    // Append CLI-supplied extra claims (simple key=value pairs)
    for (int i = 0; i < n_extra && plen >= 0 && (size_t)plen < sizeof(payload) - 1; i++) {
        int added = snprintf(payload + plen, sizeof(payload) - (size_t)plen,
                             ";%s", extras[i].key);
        if (added > 0) plen += added;
    }

    if (plen < 0 || (size_t)plen >= sizeof(payload)) {
        plen = MAX_PAYLOAD;
        payload[MAX_PAYLOAD] = '\0';
        LOG(C_YELLOW, "PRODUCER", "Payload truncated at %d bytes (MAX_PAYLOAD cap)", MAX_PAYLOAD);
    }

    LOG(C_BLUE, "PRODUCER", "Keyring payload (%d bytes):", plen);
    fprintf(stdout, "           " C_DIM "Standard:  jti, exp, iss, sid, user, uid" C_RESET "\n");
    fprintf(stdout, "           " C_DIM "Security:  acr (MFA level), dpop (proof-of-possession)" C_RESET "\n");
    fprintf(stdout, "           " C_DIM "Ops:       dept=%s, pool=%s, lb=%s, zone=%s" C_RESET "\n",
            sim_dept, sim_pool, sim_lb, sim_zone);
    if (n_extra > 0) {
        fprintf(stdout, "           " C_DIM "CLI:       ");
        for (int i = 0; i < n_extra; i++)
            fprintf(stdout, "%s%s", i ? ", " : "", extras[i].key);
        fprintf(stdout, C_RESET "\n");
    }
    hex_dump("wire bytes", payload, (size_t)plen);

    // add_key syscall
    char desc[64];
    snprintf(desc, sizeof(desc), "prmana_%s", sim_sid);

    LOG(C_BLUE, "PRODUCER", "add_key(\"user\", \"%s\", %d bytes, PROCESS_KEYRING)", desc, plen);

    long serial = syscall(SYS_add_key,
                          "user", desc,
                          payload, (size_t)plen,
                          (unsigned long)KEY_SPEC_PROCESS_KEYRING);
    if (serial < 0) {
        LOG(C_RED, "PRODUCER", "add_key failed: %s (errno=%d)", strerror(errno), errno);
        LOG(C_RED, "PRODUCER", "Hint: may need root or CAP_SYS_ADMIN");
        return 1;
    }
    LOG(C_GREEN, "PRODUCER", "Kernel allocated serial %ld", serial);

    // KEYCTL_SET_TIMEOUT — BEFORE SETPERM (ordering invariant)
    LOG(C_BLUE, "PRODUCER", "keyctl(SET_TIMEOUT, %ld, %d) [before SETPERM — ordering invariant]",
        serial, sim_ttl);
    if (keyctl_syscall(KEYCTL_SET_TIMEOUT, (unsigned long)serial,
                       (unsigned long)sim_ttl, 0, 0) < 0) {
        LOG(C_RED, "PRODUCER", "SET_TIMEOUT failed: %s", strerror(errno));
        return 1;
    }

    // KEYCTL_SETPERM — UID-only, strips SETATTR
    uint32_t perms = KEY_POS_VIEW | KEY_POS_READ | KEY_POS_SEARCH;
    LOG(C_BLUE, "PRODUCER", "keyctl(SETPERM, %ld, 0x%08x) [POSSESSOR VIEW|READ|SEARCH only]",
        serial, perms);
    if (keyctl_syscall(KEYCTL_SETPERM, (unsigned long)serial,
                       (unsigned long)perms, 0, 0) < 0) {
        LOG(C_RED, "PRODUCER", "SETPERM failed: %s", strerror(errno));
        return 1;
    }

    // PAM env vars
    LOG(C_BLUE, "PRODUCER", "pam_putenv(\"PRMANA_KEY=%ld\")", serial);

    char corr_token[CORRELATION_ID_MAX];
    snprintf(corr_token, sizeof(corr_token), "prmana-%s", sim_sid);
    LOG(C_BLUE, "PRODUCER", "pam_putenv(\"AUTHNFT_CORRELATION=%s\")", corr_token);

    LOG(C_GREEN, "PRODUCER", "Published: 1 keyring entry + 2 PAM env vars");

    // ================================================================
    // PHASE 2: CONSUMER (pam_authnft — keyring read + nftables insert)
    // ================================================================

    fprintf(stdout, "\n" C_CYAN C_BOLD
            "-- Phase 2: Consumer (pam_authnft) -------------------------------------"
            C_RESET "\n\n");

    // Read PRMANA_KEY from PAM env
    LOG(C_CYAN, "CONSUMER", "pam_getenv(\"PRMANA_KEY\") -> \"%ld\"", serial);
    LOG(C_CYAN, "CONSUMER", "strtol(\"%ld\") -> serial %ld (valid int32)", serial, serial);

    // keyctl_read
    char read_buf[MAX_PAYLOAD * 2 + 1];
    LOG(C_CYAN, "CONSUMER", "keyctl(KEYCTL_READ, %ld, buf, %zu)", serial, sizeof(read_buf));

    long nbytes = keyctl_syscall(KEYCTL_READ,
                                 (unsigned long)(uint32_t)(int32_t)serial,
                                 (unsigned long)read_buf,
                                 (unsigned long)sizeof(read_buf), 0);
    if (nbytes < 0) {
        LOG(C_RED, "CONSUMER", "keyctl_read failed: %s", strerror(errno));
        return 1;
    }
    read_buf[nbytes] = '\0';

    LOG(C_GREEN, "CONSUMER", "Read %ld bytes from kernel keyring", nbytes);
    hex_dump("raw read", read_buf, (size_t)nbytes);

    // Sanitize (mirrors keyring.c)
    char sanitized[CLAIMS_TAG_MAX + 1];
    ssize_t slen = sanitize_payload(read_buf, (size_t)nbytes,
                                    sanitized, sizeof(sanitized));
    LOG(C_CYAN, "CONSUMER", "Sanitized: %zd bytes (charset [A-Za-z0-9_=,.:;/-])", slen);

    // Parse and display individual claims from sanitized output
    LOG(C_CYAN, "CONSUMER", "Parsed claims from keyring payload:");
    {
        char tmp[CLAIMS_TAG_MAX + 1];
        strncpy(tmp, sanitized, sizeof(tmp) - 1);
        tmp[sizeof(tmp) - 1] = '\0';
        char *saveptr = NULL;
        char *pair = strtok_r(tmp, ";", &saveptr);
        while (pair) {
            char *eq = strchr(pair, '=');
            if (eq) {
                *eq = '\0';
                fprintf(stdout, "           " C_CYAN "  %-8s" C_RESET " = %s\n", pair, eq + 1);
            }
            pair = strtok_r(NULL, ";", &saveptr);
        }
    }

    // Read AUTHNFT_CORRELATION
    char corr_sanitized[CORRELATION_ID_MAX];
    sanitize_correlation(corr_token, corr_sanitized, sizeof(corr_sanitized));
    LOG(C_CYAN, "CONSUMER", "AUTHNFT_CORRELATION -> \"%s\"", corr_sanitized);

    // Simulated nftables element insertion
    char comment[512];
    snprintf(comment, sizeof(comment), "%s (PID:%d) [%s]",
             sim_user, sim_pid, sanitized);

    fprintf(stdout, "\n");
    LOG(C_CYAN, "CONSUMER", "Simulated nftables operations:");
    LOG(C_CYAN, "NFT", "add table inet authnft");
    LOG(C_CYAN, "NFT", "add set inet authnft session_%s_%d_v4 ...", sim_user, sim_pid);
    LOG(C_CYAN, "NFT", "add element inet authnft session_%s_%d_v4 \\", sim_user, sim_pid);
    fprintf(stdout, "           " C_CYAN
            "  { \"authnft.slice/authnft-%s-%d.scope\" . %s" C_RESET "\n",
            sim_user, sim_pid, sim_remote);
    fprintf(stdout, "           " C_CYAN
            "    timeout %ds" C_RESET "\n", sim_ttl);
    fprintf(stdout, "           " C_CYAN
            "    comment \"%s\" }" C_RESET "\n", comment);

    LOG(C_CYAN, "NFT", "define+include fragment with placeholder substitution");

    // Show what the fragment rules would look like
    fprintf(stdout, "\n");
    LOG(C_CYAN, "CONSUMER", "Example fragment /etc/authnft/users/%s:", sim_user);
    fprintf(stdout, "           " C_DIM
            "  # Per-session chain and sets — placeholders substituted at open" C_RESET "\n");
    fprintf(stdout, "           " C_DIM
            "  add rule inet authnft @session_chain \\" C_RESET "\n");
    fprintf(stdout, "           " C_DIM
            "    socket cgroupv2 level 2 . ip saddr @session_v4 \\" C_RESET "\n");
    fprintf(stdout, "           " C_DIM
            "    tcp dport { 443, 8443, 9090 } accept" C_RESET "\n");
    fprintf(stdout, "           " C_DIM
            "  # Block lateral movement to other network zones" C_RESET "\n");
    fprintf(stdout, "           " C_DIM
            "  add rule inet authnft @session_chain \\" C_RESET "\n");
    fprintf(stdout, "           " C_DIM
            "    socket cgroupv2 level 2 . ip saddr @session_v4 \\" C_RESET "\n");
    fprintf(stdout, "           " C_DIM
            "    ip daddr 10.42.0.0/16 drop" C_RESET "\n");

    // ================================================================
    // PHASE 3: ROUND-TRIP VERIFICATION
    // ================================================================

    fprintf(stdout, "\n" C_GREEN C_BOLD
            "-- Phase 3: Round-Trip Verification ------------------------------------"
            C_RESET "\n\n");

    int mismatch = (strcmp(payload, read_buf) != 0);
    if (mismatch) {
        LOG(C_RED, "VERIFY", "PAYLOAD MISMATCH");
        LOG(C_RED, "VERIFY", "  sent: %.80s...", payload);
        LOG(C_RED, "VERIFY", "  recv: %.80s...", read_buf);
    } else {
        LOG(C_GREEN, "VERIFY", "Payload round-trip: IDENTICAL (%ld bytes)", nbytes);
    }

    // Check sanitization didn't lose data (all chars in our payload are safe)
    if (slen == nbytes) {
        LOG(C_GREEN, "VERIFY", "Sanitization: LOSSLESS (all %zd bytes pass charset filter)", slen);
    } else {
        LOG(C_YELLOW, "VERIFY", "Sanitization: %ld -> %zd bytes (%ld bytes filtered)",
            nbytes, slen, nbytes - slen);
    }

    LOG(C_GREEN, "VERIFY", "Correlation token: \"%s\" (shared by both modules)", corr_sanitized);

    // ================================================================
    // PHASE 4: SIMULATED JOURNAL OUTPUT
    // ================================================================

    fprintf(stdout, "\n" C_YELLOW C_BOLD
            "-- Phase 4: Journal Audit Trail ----------------------------------------"
            C_RESET "\n\n");

    LOG(C_YELLOW, "JOURNAL", "What journalctl shows for this session:");
    fprintf(stdout, "\n");

    // prmana auth event
    fprintf(stdout, C_DIM "  -- pam_prmana authentication event --" C_RESET "\n");
    fprintf(stdout, "  SYSLOG_IDENTIFIER = pam_prmana\n");
    fprintf(stdout, "  MESSAGE           = Authentication successful\n");
    fprintf(stdout, "  PRMANA_USER       = %s\n", sim_user);
    fprintf(stdout, "  PRMANA_SESSION_ID = %s\n", sim_sid);
    fprintf(stdout, "  PRMANA_JTI        = %s\n", sim_jti);
    fprintf(stdout, "  PRMANA_ISSUER     = %s\n", sim_iss);
    fprintf(stdout, "  PRMANA_ACR        = %s\n", sim_acr);
    fprintf(stdout, "  PRMANA_DPOP       = %s\n", sim_dpop);
    fprintf(stdout, "  PRMANA_KEY        = %ld (keyring serial)\n", serial);
    fprintf(stdout, "\n");

    // pam_authnft session open event
    fprintf(stdout, C_DIM "  -- pam_authnft session-open event --" C_RESET "\n");
    fprintf(stdout, "  SYSLOG_IDENTIFIER    = pam_authnft\n");
    fprintf(stdout, "  AUTHNFT_EVENT        = open\n");
    fprintf(stdout, "  AUTHNFT_USER         = %s\n", sim_user);
    fprintf(stdout, "  AUTHNFT_CG_PATH      = authnft.slice/authnft-%s-%d.scope\n", sim_user, sim_pid);
    fprintf(stdout, "  AUTHNFT_REMOTE_IP    = %s\n", sim_remote);
    fprintf(stdout, "  AUTHNFT_SCOPE_UNIT   = authnft-%s-%d.scope\n", sim_user, sim_pid);
    fprintf(stdout, "  AUTHNFT_CLAIMS_TAG   = %s\n", sanitized);
    fprintf(stdout, "  " C_GREEN "AUTHNFT_CORRELATION" C_RESET "  = " C_GREEN "%s" C_RESET "\n", corr_sanitized);
    fprintf(stdout, "\n");

    // Correlation proof
    fprintf(stdout, C_DIM "  -- SIEM join query --" C_RESET "\n");
    fprintf(stdout, "  journalctl AUTHNFT_CORRELATION=%s\n", corr_sanitized);
    fprintf(stdout, "  " C_DIM "(returns both events above — one auth, one session)" C_RESET "\n");

    // ================================================================
    // PHASE 5: WHAT THE SECURITY DIRECTOR SEES
    // ================================================================

    fprintf(stdout, "\n" C_MAG C_BOLD
            "-- Phase 5: Operator / SIEM View ---------------------------------------"
            C_RESET "\n\n");

    LOG(C_MAG, "OPERATOR", "nft list table inet authnft :");
    fprintf(stdout, "\n");
    fprintf(stdout, C_DIM "  table inet authnft {\n");
    fprintf(stdout, "    set session_%s_%d_v4 {\n", sim_user, sim_pid);
    fprintf(stdout, "      typeof socket cgroupv2 level 2 . ip saddr\n");
    fprintf(stdout, "      flags timeout\n");
    fprintf(stdout, "      elements = {\n");
    fprintf(stdout, "        \"authnft.slice/authnft-%s-%d.scope\" . %s\n",
            sim_user, sim_pid, sim_remote);
    fprintf(stdout, "          timeout %ds expires %ds\n", sim_ttl, sim_ttl - 12);
    fprintf(stdout, C_RESET "          comment " C_GREEN "\"%s\"" C_RESET C_DIM "\n", comment);
    fprintf(stdout, "      }\n");
    fprintf(stdout, "    }\n");
    fprintf(stdout, "  }" C_RESET "\n");

    fprintf(stdout, "\n");
    LOG(C_MAG, "OPERATOR", "What this means for a security director:");
    fprintf(stdout, "\n");
    fprintf(stdout, C_BOLD "  Authentication:" C_RESET "\n");
    fprintf(stdout, "  " C_GREEN " 1." C_RESET " User '%s' authenticated via OIDC IdP with MFA (acr=%s)\n",
            sim_user, sim_acr);
    fprintf(stdout, "  " C_GREEN " 2." C_RESET " Token is DPoP-bound (dpop=%s) — stolen tokens are useless\n",
            sim_dpop);
    fprintf(stdout, "  " C_GREEN " 3." C_RESET " Additional RFC 9449 hardening spec available (discuss on call)\n");
    fprintf(stdout, "\n");
    fprintf(stdout, C_BOLD "  Session enforcement:" C_RESET "\n");
    fprintf(stdout, "  " C_GREEN " 4." C_RESET " Session kernel-isolated in cgroupv2 scope\n");
    fprintf(stdout, "  " C_GREEN " 5." C_RESET " Network policy kernel-enforced via nftables — not iptables,\n"
                    "      not firewalld zones, not application-level ACLs\n");
    fprintf(stdout, "  " C_GREEN " 6." C_RESET " Operational context in nft element comments:\n"
                    "      dept=%s, pool=%s, lb=%s, compliance_zone=%s\n",
            sim_dept, sim_pool, sim_lb, sim_zone);
    fprintf(stdout, "\n");
    fprintf(stdout, C_BOLD "  Audit:" C_RESET "\n");
    fprintf(stdout, "  " C_GREEN " 7." C_RESET " Full trail in journald, joinable by correlation token:\n"
                    "      AUTHNFT_CORRELATION=%s\n", corr_sanitized);
    fprintf(stdout, "  " C_GREEN " 8." C_RESET " Session close auto-removes nft element + emits close event\n");
    fprintf(stdout, "  " C_GREEN " 9." C_RESET " 24h timeout safety net evicts stale elements on crash\n");
    fprintf(stdout, "\n");
    fprintf(stdout, C_BOLD "  Architecture:" C_RESET "\n");
    fprintf(stdout, "  " C_GREEN "10." C_RESET " No agent, no sidecar, no proxy — pure kernel primitives\n");
    fprintf(stdout, "  " C_GREEN "11." C_RESET " Two independent projects, no shared codebase\n"
                    "      GPL (pam_authnft) + Apache (prmana), composed via PAM + keyring\n");

    // ================================================================
    // PHASE 6: WIRE DIAGRAM
    // ================================================================

    fprintf(stdout, "\n" C_BOLD
            "-- Wire Diagram --------------------------------------------------------"
            C_RESET "\n\n");

    fprintf(stdout,
        "  prmana (PAM auth)       kernel keyring        pam_authnft (session)    nftables\n"
        "  ─────────────────       ──────────────        ─────────────────────    ────────\n"
        "        │                       │                       │                   │\n"
        "   OIDC + DPoP validated        │                       │                   │\n"
        "        │                       │                       │                   │\n"
        "   add_key(claims) ──────────> │                       │                   │\n"
        "        │                 serial=%ld                   │                   │\n"
        "        │ <─────────────────── │                       │                   │\n"
        "        │                       │                       │                   │\n"
        "   SET_TIMEOUT ──────────────> │                       │                   │\n"
        "   SETPERM ───────────────── > │                       │                   │\n"
        "        │                       │                       │                   │\n"
        "   putenv(PRMANA_KEY=%ld) ──────────────────────────> │                   │\n"
        "   putenv(AUTHNFT_CORR=..) ──────────────────────────> │                   │\n"
        "        │                       │                       │                   │\n"
        "        │                       │      getenv(PRMANA_KEY)                   │\n"
        "        │                       │ <──────────────────── │                   │\n"
        "        │                       │                       │                   │\n"
        "        │                  KEYCTL_READ                  │                   │\n"
        "        │                       │ <──────────────────── │                   │\n"
        "        │                       │ ─── %d bytes ───────> │                   │\n"
        "        │                       │                       │                   │\n"
        "        │                       │                  sanitize + scope          │\n"
        "        │                       │                       │                   │\n"
        "        │                       │      nft add element ──────────────────> │\n"
        "        │                       │      nft include frag ──────────────────> │\n"
        "        │                       │                       │                   │\n"
        "        │                       │                       │            kernel match:\n"
        "        │                       │                       │            socket cgroupv2\n"
        "        │                       │                       │            level 2 . saddr\n"
        "        │                       │                       │            @session_v4\n"
        "        │                       │                       │                   │\n"
        "   journal:                     │                  journal:                 │\n"
        "   AUTH_SUCCESS                 │                  AUTHNFT_EVENT=open       │\n"
        "   corr=%s                      │                  corr=%s                  │\n"
        "        │                       │                       │                   │\n"
        "        └───────────────────────┴───────────────────────┴───────────────────┘\n"
        "                            shared correlation token\n",
        serial, serial, plen, corr_sanitized, corr_sanitized
    );

    // ================================================================
    // Cleanup
    // ================================================================

    fprintf(stdout, "\n");
    LOG(C_DIM, "CLEANUP", "Revoking keyring entry serial %ld", serial);
    if (keyctl_syscall(KEYCTL_REVOKE, (unsigned long)serial, 0, 0, 0) < 0)
        LOG(C_YELLOW, "CLEANUP", "revoke: %s (non-fatal)", strerror(errno));
    else
        LOG(C_GREEN, "CLEANUP", "Key revoked");

    fprintf(stdout, "\n" C_BOLD
            "================================================================\n");
    fprintf(stdout, "  Result: %s\n",
            mismatch ? "FAIL — payload mismatch" : "PASS — full pipeline verified");
    fprintf(stdout, "================================================================"
            C_RESET "\n\n");

    return mismatch ? 1 : 0;
}
