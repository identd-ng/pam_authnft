#include "authnft.h"
#include <arpa/inet.h>
#include <errno.h>
#include <nftables/libnftables.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/personality.h>
#include <sys/wait.h>
#include <unistd.h>
#include <sys/capability.h>
#include <sys/stat.h>

static int is_audit_mode(void) {
    const char *mode = getenv("AUTHNFT_AUDIT_MODE");
    return (mode && strcmp(mode, "1") == 0);
}

/* Stage 1: username validation rejects path traversal and shell metacharacters */
static void run_input_validation_test(void) {
    printf("[STAGE 1] Input sanitization...\n");
    const char *bad[] = {"../etc/passwd", "root;rm -rf /", "user\n", NULL};
    for (int i = 0; bad[i] != NULL; i++) {
        if (util_is_valid_username(bad[i])) {
            fprintf(stderr, "[FAIL] Accepted illegal username: %s\n", bad[i]);
            exit(1);
        }
    }
    printf("[PASS]\n");
}

/* Stage 2: a syscall absent from the allowlist must trigger SIGSYS */
static void run_violation_test(void) {
    if (is_audit_mode()) {
        printf("[SKIP] Stage 2: Seccomp vs Valgrind conflict.\n");
        return;
    }
    printf("[STAGE 2] Seccomp kill on blocked syscall...\n");
    pid_t pid = fork();
    if (pid == 0) {
        sandbox_apply(NULL);
        /* personality() is not on the allowlist — must trigger SIGSYS */
        (void)personality(0xffffffff);
        _exit(0);
    }
    int status;
    waitpid(pid, &status, 0);
    if (WIFSIGNALED(status) && WTERMSIG(status) == SIGSYS)
        printf("[PASS]\n");
    else {
        fprintf(stderr, "[FAIL] Not killed by Seccomp (status: %d)\n", status);
        exit(1);
    }
}

/* Stage 3: an allowlisted syscall must succeed through the sandbox */
static void run_allowlist_test(void) {
    printf("[STAGE 3] Allowlisted syscall survives sandbox...\n");
    pid_t pid = fork();
    if (pid == 0) {
        if (!is_audit_mode()) sandbox_apply(NULL);
        /* close() on an invalid fd returns EBADF, not SIGSYS */
        if (close(999) == -1 && errno == EBADF) _exit(42);
        _exit(1);
    }
    int status;
    waitpid(pid, &status, 0);
    if (WIFEXITED(status) && WEXITSTATUS(status) == 42)
        printf("[PASS]\n");
    else
        exit(1);
}

/* Stage 4: libnftables dry-run rejects malformed commands */
static void run_nft_syntax_test(void) {
    printf("[STAGE 4] Nftables dry-run syntax check...\n");
    cap_t caps = cap_get_proc();
    cap_flag_value_t val;
    cap_get_flag(caps, CAP_NET_ADMIN, CAP_EFFECTIVE, &val);
    cap_free(caps);
    if (val != CAP_SET) {
        printf("[SKIP] Requires CAP_NET_ADMIN.\n");
        return;
    }
    struct nft_ctx *ctx = nft_ctx_new(NFT_CTX_DEFAULT);
    nft_ctx_set_dry_run(ctx, 1);
    char cmd[CMD_BUF_SIZE];
    snprintf(cmd, sizeof(cmd), "add table inet %s_syntax_test", TABLE_NAME);
    if (nft_run_cmd_from_buffer(ctx, cmd) == 0)
        printf("[PASS]\n");
    else {
        fprintf(stderr, "[FAIL] Nftables rejected valid syntax.\n");
        exit(1);
    }
    nft_ctx_free(ctx);
}

/* Stage 5: util_get_cgroup_id resolves the cgroupv2 inode for a live PID */
static void run_cgroup_logic_test(void) {
    printf("[STAGE 5] cgroupv2 inode resolution...\n");
    uint64_t cg_id = 0;
    if (util_get_cgroup_id(getpid(), &cg_id) == 0 && cg_id > 0)
        printf("[PASS] inode=%lu\n", (unsigned long)cg_id);
    else {
        fprintf(stderr, "[FAIL] Could not resolve cgroup ID.\n");
        exit(1);
    }
}

/* Stage 6: binary hardening flags are present in the compiled .so */
static void run_checksec_test(void) {
    printf("[STAGE 6] Binary hardening (checksec)...\n");
    if (system("command -v checksec > /dev/null 2>&1") != 0) {
        printf("[SKIP] checksec not found.\n");
        return;
    }
    if (system("checksec file pam_authnft.so | grep -qi 'Full RELRO'") == 0)
        printf("[PASS]\n");
    else
        exit(1);
}

/* Stage 7: nft_handler_setup loads a valid root-owned fragment without error */
static void run_path_resolution_test(void) {
    printf("[STAGE 7] Fragment path resolution and load...\n");
    cap_t caps = cap_get_proc();
    cap_flag_value_t val;
    cap_get_flag(caps, CAP_NET_ADMIN, CAP_EFFECTIVE, &val);
    cap_free(caps);
    if (val != CAP_SET) {
        printf("[SKIP] Requires CAP_NET_ADMIN.\n");
        return;
    }

    const char *test_user = "strykar-test";
    char mock_path[256];
    snprintf(mock_path, sizeof(mock_path), "%s/%s", RULES_DIR, test_user);

    (void)system("sudo mkdir -p " RULES_DIR);
    char cmd[768];
    snprintf(cmd, sizeof(cmd),
             "echo 'add rule inet %s filter accept' | sudo tee %s > /dev/null",
             TABLE_NAME, mock_path);
    (void)system(cmd);
    snprintf(cmd, sizeof(cmd), "sudo chown root:root %s && sudo chmod 644 %s",
             mock_path, mock_path);
    (void)system(cmd);

    int res = nft_handler_setup(NULL, test_user, 12345, "127.0.0.1");

    snprintf(cmd, sizeof(cmd), "sudo rm -f %s", mock_path);
    (void)system(cmd);

    if (res == PAM_SUCCESS)
        printf("[PASS]\n");
    else
        exit(1);
}

int main(void) {
    printf("--- pam_authnft unit tests ---\n\n");
    run_input_validation_test();
    run_violation_test();
    run_allowlist_test();
    run_nft_syntax_test();
    run_cgroup_logic_test();
    run_checksec_test();
    run_path_resolution_test();
    printf("\n[DONE]\n");
    return 0;
}
