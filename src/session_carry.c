// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2025 Avinash H. Duduskar

/*
 * PAM-env session-state carry: serialize authnft_session_t into a PAM
 * env value at open_session, deserialize at close_session.
 *
 * Background: under modern OpenSSH (>= 9.8) privsep, pam_open_session
 * runs in the privsep child but pam_close_session runs in the monitor.
 * pam_set_data writes to the calling process's PAM data list, which is
 * unreachable from the other process. PAM environment variables are
 * different — sshd explicitly proxies its env across the privsep boundary
 * via import_environments(), so a value set with pam_putenv at open
 * remains visible to pam_getenv at close. See issue #35 for the full
 * source-level walk and the fallback semantics.
 *
 * Schema: a flat JSON object with a versioned "v" field. Field set is
 * the cleanup-relevant subset of authnft_session_t (cg_path, scope_unit,
 * remote_ip, claims_tag, correlation_id, chain_name, set_v4, set_v6,
 * set_cg, jump_handle). All string fields are producer-validated upstream
 * to safe ASCII subsets (charsets defined in their respective validators)
 * so no JSON escaping is required at encode time; decode does a strict
 * "value is a quoted simple string" parse and re-validates each field
 * through util_is_valid_username, util_normalize_ip, etc. before the
 * decoded struct is used.
 *
 * This carry is INTERNAL to pam_authnft. Unlike the JSON file under
 * /run/authnft/sessions/<scope>.json (INTEGRATIONS.txt §5.6, schema v=2),
 * the env-carry schema is not a public contract. The "v" field exists so
 * a future change to either side of the open/close boundary can detect
 * incompatible peers and bail safely. Bump v on any field rename or
 * removal; additive fields can land without a bump.
 */

#include "authnft.h"

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CARRY_SCHEMA_VERSION 1

/*
 * Serialize sd into the buffer as a single JSON object. Returns the
 * number of bytes written (excluding the terminating NUL), or -1 on
 * overflow or error. The buffer is sized by the caller; a 1024-byte
 * buffer is sufficient for any populated authnft_session_t given the
 * field caps in include/authnft.h.
 */
int session_carry_encode(const authnft_session_t *sd, char *out, size_t out_sz) {
    if (!sd || !out || out_sz == 0) return -1;
    int n = snprintf(out, out_sz,
        "{\"v\":%d,"
        "\"cg_path\":\"%s\","
        "\"scope_unit\":\"%s\","
        "\"remote_ip\":\"%s\","
        "\"claims_tag\":\"%s\","
        "\"correlation_id\":\"%s\","
        "\"chain_name\":\"%s\","
        "\"set_v4\":\"%s\","
        "\"set_v6\":\"%s\","
        "\"set_cg\":\"%s\","
        "\"jump_handle\":%" PRIu64 "}",
        CARRY_SCHEMA_VERSION,
        sd->cg_path, sd->scope_unit, sd->remote_ip, sd->claims_tag,
        sd->correlation_id, sd->chain_name,
        sd->set_v4, sd->set_v6, sd->set_cg, sd->jump_handle);
    if (n < 0 || (size_t)n >= out_sz) return -1;
    return n;
}

/*
 * Pull a quoted JSON string field by key into out[out_sz]. Returns 0 on
 * success, -1 on missing key, malformed quoting, or buffer overflow.
 *
 * Limitations: assumes the value contains no embedded quotes or
 * backslashes. This is enforced at the encoder side (all fields come
 * from validators with bounded ASCII charsets) and re-checked by the
 * caller's per-field re-validation after extraction. A malformed peer
 * (different version of pam_authnft, or a hostile injection) would be
 * caught at re-validate, not here.
 */
static int json_get_str(const char *json, const char *key,
                        char *out, size_t out_sz) {
    char needle[64];
    int n = snprintf(needle, sizeof(needle), "\"%s\":\"", key);
    if (n < 0 || (size_t)n >= sizeof(needle)) return -1;
    const char *p = strstr(json, needle);
    if (!p) return -1;
    p += (size_t)n;
    const char *q = strchr(p, '"');
    if (!q) return -1;
    size_t len = (size_t)(q - p);
    if (len >= out_sz) return -1;
    memcpy(out, p, len);
    out[len] = '\0';
    return 0;
}

/* Pull an integer JSON field. Returns 0 on success, -1 otherwise. */
static int json_get_u64(const char *json, const char *key, uint64_t *out) {
    char needle[64];
    int n = snprintf(needle, sizeof(needle), "\"%s\":", key);
    if (n < 0 || (size_t)n >= sizeof(needle)) return -1;
    const char *p = strstr(json, needle);
    if (!p) return -1;
    p += (size_t)n;
    char *end = NULL;
    unsigned long long v = strtoull(p, &end, 10);
    if (end == p) return -1;
    *out = (uint64_t)v;
    return 0;
}

/*
 * Deserialize a JSON-encoded session carry into sd. Returns 0 on
 * success, -1 on schema mismatch or malformed input. Does NOT
 * re-validate field semantics — the caller is responsible for running
 * each field through its existing validator (charset, length bounds,
 * cgroup path depth invariant) before acting on the decoded struct.
 */
int session_carry_decode(const char *json, authnft_session_t *sd) {
    if (!json || !sd) return -1;
    memset(sd, 0, sizeof(*sd));

    uint64_t v = 0;
    if (json_get_u64(json, "v", &v) != 0) return -1;
    if (v != CARRY_SCHEMA_VERSION) return -1;

    if (json_get_str(json, "cg_path",        sd->cg_path,        sizeof(sd->cg_path))        != 0) return -1;
    if (json_get_str(json, "scope_unit",     sd->scope_unit,     sizeof(sd->scope_unit))     != 0) return -1;
    /* remote_ip and claims_tag may legitimately be empty strings. */
    (void)json_get_str(json, "remote_ip",    sd->remote_ip,      sizeof(sd->remote_ip));
    (void)json_get_str(json, "claims_tag",   sd->claims_tag,     sizeof(sd->claims_tag));
    if (json_get_str(json, "correlation_id", sd->correlation_id, sizeof(sd->correlation_id)) != 0) return -1;
    if (json_get_str(json, "chain_name",     sd->chain_name,     sizeof(sd->chain_name))     != 0) return -1;
    if (json_get_str(json, "set_v4",         sd->set_v4,         sizeof(sd->set_v4))         != 0) return -1;
    if (json_get_str(json, "set_v6",         sd->set_v6,         sizeof(sd->set_v6))         != 0) return -1;
    if (json_get_str(json, "set_cg",         sd->set_cg,         sizeof(sd->set_cg))         != 0) return -1;
    if (json_get_u64(json, "jump_handle",    &sd->jump_handle)                                != 0) return -1;

    return 0;
}
