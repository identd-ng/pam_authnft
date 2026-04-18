#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2025 Avinash H. Duduskar
#
# audit_correlate.sh — Full-stack audit trail for the prmana ↔ pam_authnft
# kernel-keyring bridge.
#
# Captures and correlates:
#   1. Kernel keyring state (session keys published by prmana)
#   2. nftables table/set/element state (session elements managed by pam_authnft)
#   3. Packet-level trace via nft monitor (optional, live mode)
#   4. Journal events from both pam_authnft and pam_prmana
#   5. Session identity files (/run/authnft/sessions/*.json)
#   6. Systemd scope state (authnft.slice)
#
# Usage:
#   ./audit_correlate.sh              # one-shot snapshot
#   ./audit_correlate.sh --live       # continuous monitoring with packet trace
#   ./audit_correlate.sh --user alice # filter to a specific user
#   ./audit_correlate.sh --corr TOKEN # filter to a specific correlation token
#   ./audit_correlate.sh --since 10m  # journal window (default: 1h)
#
# Requirements: keyctl (keyutils), nft (nftables), journalctl, jq (optional)

set -euo pipefail

# ── Defaults ──

MODE="snapshot"
FILTER_USER=""
FILTER_CORR=""
JOURNAL_SINCE="1h"
OUTPUT_FILE=""
NFT_MONITOR_PID=""

# ── Colours ──

if [[ -t 1 ]]; then
    BOLD='\033[1m'
    DIM='\033[2m'
    BLUE='\033[34m'
    GREEN='\033[32m'
    YELLOW='\033[33m'
    CYAN='\033[36m'
    RED='\033[31m'
    RESET='\033[0m'
else
    BOLD='' DIM='' BLUE='' GREEN='' YELLOW='' CYAN='' RED='' RESET=''
fi

# ── Helpers ──

header() {
    printf "\n${BOLD}══ %s ══${RESET}\n\n" "$1"
}

subheader() {
    printf "${BOLD}── %s${RESET}\n" "$1"
}

info()  { printf "${GREEN}[INFO]${RESET}  %s\n" "$*"; }
warn()  { printf "${YELLOW}[WARN]${RESET}  %s\n" "$*"; }
err()   { printf "${RED}[ERR]${RESET}   %s\n" "$*" >&2; }

ts() {
    date -u '+%Y-%m-%dT%H:%M:%SZ'
}

check_tool() {
    if ! command -v "$1" &>/dev/null; then
        warn "$1 not found — $2 section will be skipped"
        return 1
    fi
    return 0
}

cleanup() {
    if [[ -n "${NFT_MONITOR_PID}" ]] && kill -0 "${NFT_MONITOR_PID}" 2>/dev/null; then
        kill "${NFT_MONITOR_PID}" 2>/dev/null || true
        wait "${NFT_MONITOR_PID}" 2>/dev/null || true
    fi
}
trap cleanup EXIT

# ── Argument parsing ──

while [[ $# -gt 0 ]]; do
    case "$1" in
        --live)       MODE="live"; shift ;;
        --user)       FILTER_USER="$2"; shift 2 ;;
        --corr)       FILTER_CORR="$2"; shift 2 ;;
        --since)      JOURNAL_SINCE="$2"; shift 2 ;;
        --output|-o)  OUTPUT_FILE="$2"; shift 2 ;;
        --help|-h)
            printf "Usage: %s [--live] [--user USER] [--corr TOKEN] [--since TIME] [--output FILE]\n" "$0"
            exit 0 ;;
        *) err "Unknown option: $1"; exit 1 ;;
    esac
done

# Redirect to file if requested
if [[ -n "${OUTPUT_FILE}" ]]; then
    exec > >(tee "${OUTPUT_FILE}") 2>&1
    BOLD='' DIM='' BLUE='' GREEN='' YELLOW='' CYAN='' RED='' RESET=''
fi

printf "${BOLD}╔═══════════════════════════════════════════════════════════╗${RESET}\n"
printf "${BOLD}║  prmana ↔ pam_authnft: Full-Stack Audit Trail           ║${RESET}\n"
printf "${BOLD}║  Generated: $(ts)                       ║${RESET}\n"
printf "${BOLD}║  Mode: %-49s║${RESET}\n" "${MODE}"
[[ -n "${FILTER_USER}" ]] && printf "${BOLD}║  Filter user: %-43s║${RESET}\n" "${FILTER_USER}"
[[ -n "${FILTER_CORR}" ]] && printf "${BOLD}║  Filter corr: %-43s║${RESET}\n" "${FILTER_CORR}"
printf "${BOLD}╚═══════════════════════════════════════════════════════════╝${RESET}\n"


# ══════════════════════════════════════════════════════════════
# Section 1: Kernel Keyring State
# ══════════════════════════════════════════════════════════════

header "1. Kernel Keyring State (prmana-published session keys)"

if check_tool keyctl "keyring"; then
    subheader "Session keyring contents"
    # List keys in the session keyring; filter for prmana_ entries
    if keyctl show @s 2>/dev/null; then
        printf "\n"
        subheader "Searching for prmana_* keys"
        found_keys=0
        while IFS= read -r line; do
            serial=$(echo "$line" | awk '{print $1}')
            desc=$(echo "$line" | sed 's/.*: //')
            if [[ "${desc}" == prmana_* ]]; then
                found_keys=1
                printf "  ${CYAN}serial=${serial}${RESET}  desc=\"${desc}\"\n"
                # Try to read the payload
                payload=$(keyctl pipe "${serial}" 2>/dev/null || echo "[unreadable]")
                printf "  ${DIM}payload: %s${RESET}\n" "${payload}"
                # Parse key=value pairs from payload
                if [[ "${payload}" != "[unreadable]" ]]; then
                    IFS=';' read -ra pairs <<< "${payload}"
                    for pair in "${pairs[@]}"; do
                        printf "    ${GREEN}%s${RESET}\n" "${pair}"
                    done
                fi
                # Show key metadata
                keyctl timeout "${serial}" 2>/dev/null && \
                    printf "  ${DIM}timeout: $(keyctl timeout "${serial}" 2>/dev/null)${RESET}\n" || true
                printf "\n"
            fi
        done < <(keyctl list @s 2>/dev/null || true)
        if [[ ${found_keys} -eq 0 ]]; then
            info "No prmana_* keys found in session keyring (no active OIDC sessions)"
        fi
    else
        warn "Cannot access session keyring (may need root or active PAM session)"
    fi
    printf "\n"

    subheader "User keyring (fallback anchor)"
    keyctl show @u 2>/dev/null | head -20 || warn "Cannot access user keyring"
fi


# ══════════════════════════════════════════════════════════════
# Section 2: nftables State
# ══════════════════════════════════════════════════════════════

header "2. nftables State (pam_authnft session elements)"

if check_tool nft "nftables"; then
    subheader "Table: inet authnft"
    if nft list table inet authnft 2>/dev/null; then
        printf "\n"
    else
        info "Table 'inet authnft' does not exist (no active authnft sessions)"
        printf "\n"
    fi

    # Dump individual sets with element details
    # Plan B: per-session sets — discover dynamically from nft state
    for set_name in $(nft list table inet authnft 2>/dev/null | grep -oP 'set \Ksession_\S+' || true); do
        subheader "Set: ${set_name}"
        set_output=$(nft list set inet authnft "${set_name}" 2>/dev/null || true)
        if [[ -n "${set_output}" ]]; then
            echo "${set_output}"
            # Count elements
            elem_count=$(echo "${set_output}" | grep -c 'comment' || echo 0)
            info "${elem_count} active element(s) in ${set_name}"

            # Filter by user if requested
            if [[ -n "${FILTER_USER}" ]]; then
                printf "  ${YELLOW}Filtered to user '${FILTER_USER}':${RESET}\n"
                echo "${set_output}" | grep -i "${FILTER_USER}" || info "  (no matches)"
            fi
        else
            printf "  ${DIM}(not present)${RESET}\n"
        fi
        printf "\n"
    done

    subheader "Chain: filter (rules loaded from fragments)"
    nft list chain inet authnft filter 2>/dev/null || \
        printf "  ${DIM}(chain not present)${RESET}\n"
    printf "\n"
fi


# ══════════════════════════════════════════════════════════════
# Section 3: Session Identity Files
# ══════════════════════════════════════════════════════════════

header "3. Session Identity Files (/run/authnft/sessions/)"

session_dir="/run/authnft/sessions"
if [[ -d "${session_dir}" ]]; then
    session_files=("${session_dir}"/*.json 2>/dev/null) || session_files=()
    if [[ ${#session_files[@]} -gt 0 && -e "${session_files[0]}" ]]; then
        for f in "${session_files[@]}"; do
            subheader "$(basename "$f")"
            if check_tool jq "JSON pretty-print" 2>/dev/null; then
                jq '.' "$f" 2>/dev/null || cat "$f"
            else
                cat "$f"
            fi

            # Extract and display correlation-relevant fields
            if command -v jq &>/dev/null; then
                local_user=$(jq -r '.user // empty' "$f" 2>/dev/null)
                local_corr=$(jq -r '.claims_tag // empty' "$f" 2>/dev/null)
                local_cg=$(jq -r '.cg_path // empty' "$f" 2>/dev/null)
                local_ip=$(jq -r '.remote_ip // empty' "$f" 2>/dev/null)

                # Apply filters
                if [[ -n "${FILTER_USER}" && "${local_user}" != "${FILTER_USER}" ]]; then
                    printf "  ${DIM}(skipped — user filter)${RESET}\n"
                    continue
                fi

                printf "  ${GREEN}user=${local_user}  cg=${local_cg}  ip=${local_ip}${RESET}\n"
                [[ -n "${local_corr}" ]] && \
                    printf "  ${GREEN}claims_tag=${local_corr}${RESET}\n"
            fi
            printf "\n"
        done
    else
        info "No session files present (no active authnft sessions)"
    fi
else
    info "${session_dir} does not exist (pam_authnft not installed or no sessions opened)"
fi


# ══════════════════════════════════════════════════════════════
# Section 4: Systemd Scope State
# ══════════════════════════════════════════════════════════════

header "4. Systemd Scopes (authnft.slice)"

if check_tool systemctl "systemd scope"; then
    subheader "Active authnft scopes"
    scopes=$(systemctl --type=scope --no-pager list-units 'authnft-*.scope' 2>/dev/null || true)
    if [[ -n "${scopes}" ]] && echo "${scopes}" | grep -q 'authnft-'; then
        echo "${scopes}"
        printf "\n"

        subheader "Cgroup tree"
        systemd-cgls /authnft.slice 2>/dev/null || \
            printf "  ${DIM}(cgls unavailable)${RESET}\n"
    else
        info "No active authnft scopes (no sessions running)"
    fi
    printf "\n"
fi


# ══════════════════════════════════════════════════════════════
# Section 5: Journal Events (correlated)
# ══════════════════════════════════════════════════════════════

header "5. Journal Events (last ${JOURNAL_SINCE})"

if check_tool journalctl "journal"; then
    # 5a. prmana auth events
    subheader "pam_prmana events (authentication)"
    journal_args=(--since "-${JOURNAL_SINCE}" --no-pager -o short-iso)
    [[ -n "${FILTER_USER}" ]] && journal_args+=(--grep="${FILTER_USER}")

    prmana_events=$(journalctl "${journal_args[@]}" -t pam_prmana 2>/dev/null || \
                    journalctl "${journal_args[@]}" SYSLOG_IDENTIFIER=pam_prmana 2>/dev/null || true)
    if [[ -n "${prmana_events}" ]]; then
        echo "${prmana_events}" | head -50
        prmana_count=$(echo "${prmana_events}" | wc -l)
        [[ ${prmana_count} -gt 50 ]] && info "(showing 50/${prmana_count} entries)"
    else
        info "No pam_prmana journal events in the last ${JOURNAL_SINCE}"
    fi
    printf "\n"

    # 5b. pam_authnft session events
    subheader "pam_authnft events (session lifecycle)"
    authnft_events=$(journalctl "${journal_args[@]}" -t pam_authnft 2>/dev/null || \
                     journalctl "${journal_args[@]}" SYSLOG_IDENTIFIER=pam_authnft 2>/dev/null || true)
    if [[ -n "${authnft_events}" ]]; then
        echo "${authnft_events}" | head -50
        authnft_count=$(echo "${authnft_events}" | wc -l)
        [[ ${authnft_count} -gt 50 ]] && info "(showing 50/${authnft_count} entries)"
    else
        info "No pam_authnft journal events in the last ${JOURNAL_SINCE}"
    fi
    printf "\n"

    # 5c. Structured event correlation
    subheader "Correlation token join (AUTHNFT_CORRELATION)"
    corr_args=(--since "-${JOURNAL_SINCE}" --no-pager -o json)

    if [[ -n "${FILTER_CORR}" ]]; then
        # Filter to a specific correlation token
        corr_events=$(journalctl "${corr_args[@]}" \
            AUTHNFT_CORRELATION="${FILTER_CORR}" 2>/dev/null || true)
    else
        corr_events=$(journalctl "${corr_args[@]}" -t pam_authnft \
            2>/dev/null || true)
    fi

    if [[ -n "${corr_events}" ]] && command -v jq &>/dev/null; then
        # Extract unique correlation tokens and their events
        echo "${corr_events}" | jq -r '
            select(.AUTHNFT_CORRELATION != null) |
            "\(.AUTHNFT_CORRELATION)\t\(.AUTHNFT_EVENT // "?")\t\(.AUTHNFT_USER // "?")\t\(.__REALTIME_TIMESTAMP // "?")"
        ' 2>/dev/null | sort -t$'\t' -k1,1 -k4,4 | \
        awk -F'\t' '
            BEGIN { printf "  %-30s %-8s %-16s %s\n", "CORRELATION", "EVENT", "USER", "TIMESTAMP" }
            {
                ts = $4
                if (ts ~ /^[0-9]+$/) {
                    # Convert microseconds to readable
                    cmd = "date -d @" int(ts/1000000) " -u +%Y-%m-%dT%H:%M:%SZ 2>/dev/null"
                    cmd | getline ts
                    close(cmd)
                }
                printf "  %-30s %-8s %-16s %s\n", $1, $2, $3, ts
            }
        ' || info "No structured correlation events found"
    elif [[ -n "${FILTER_CORR}" ]]; then
        journalctl --since "-${JOURNAL_SINCE}" --no-pager \
            AUTHNFT_CORRELATION="${FILTER_CORR}" 2>/dev/null || \
            info "No events matching correlation token '${FILTER_CORR}'"
    else
        info "Install jq for structured correlation analysis"
    fi
    printf "\n"

    # 5d. Syslog fallback events (error paths)
    subheader "Syslog fallback events (authnft: prefix)"
    syslog_events=$(journalctl --since "-${JOURNAL_SINCE}" --no-pager \
        -o short-iso --grep='authnft:' 2>/dev/null || true)
    if [[ -n "${syslog_events}" ]]; then
        echo "${syslog_events}" | head -20
    else
        info "No syslog-fallback events (journal delivery healthy)"
    fi
fi


# ══════════════════════════════════════════════════════════════
# Section 6: Packet-Level Trace (live mode only)
# ══════════════════════════════════════════════════════════════

if [[ "${MODE}" == "live" ]]; then
    header "6. Live Packet Trace (nft monitor trace)"

    if check_tool nft "nftables trace"; then
        info "Starting nft monitor trace — packets matching authnft rules will appear below."
        info "Press Ctrl+C to stop."
        printf "\n"

        # Enable tracing on the authnft chain if not already set
        # (requires a meta nftrace set 1 rule in the chain)
        has_trace=$(nft list chain inet authnft filter 2>/dev/null | grep -c 'nftrace' || echo 0)
        if [[ "${has_trace}" -eq 0 ]]; then
            warn "No 'meta nftrace set 1' rule in chain — trace events may not appear"
            warn "Add: nft add rule inet authnft filter meta nftrace set 1"
        fi

        # Run nft monitor in foreground — user Ctrl+C to stop
        nft monitor trace 2>/dev/null || \
            warn "nft monitor trace failed (may need root)"
    fi
else
    header "6. Packet Trace"
    info "Packet-level tracing available in --live mode"
    info "Run: $0 --live"
    printf "\n"
    info "To enable nftables tracing manually:"
    printf "  ${DIM}nft add rule inet authnft filter meta nftrace set 1${RESET}\n"
    printf "  ${DIM}nft monitor trace${RESET}\n"
fi


# ══════════════════════════════════════════════════════════════
# Summary
# ══════════════════════════════════════════════════════════════

header "Summary"

printf "${BOLD}Data flow: packet → kernel → log${RESET}\n\n"
printf "  ┌─────────────────┐\n"
printf "  │   SSH client     │  OIDC token + DPoP proof\n"
printf "  └────────┬────────┘\n"
printf "           │\n"
printf "           ▼\n"
printf "  ┌─────────────────┐\n"
printf "  │   pam_prmana     │  1. Validate OIDC token\n"
printf "  │   (PAM auth)     │  2. add_key(claims) → kernel keyring\n"
printf "  │                  │  3. putenv(PRMANA_KEY=serial)\n"
printf "  │                  │  4. putenv(AUTHNFT_CORRELATION=token)\n"
printf "  └────────┬────────┘\n"
printf "           │ PAM env vars\n"
printf "           ▼\n"
printf "  ┌─────────────────┐\n"
printf "  │  pam_authnft     │  5. keyctl_read(serial) → claims\n"
printf "  │  (PAM session)   │  6. Create systemd scope\n"
printf "  │                  │  7. Insert nft element (cgroup+IP)\n"
printf "  │                  │  8. Load user fragment rules\n"
printf "  │                  │  9. Write session JSON\n"
printf "  │                  │ 10. Emit journal event (correlated)\n"
printf "  └────────┬────────┘\n"
printf "           │\n"
printf "           ▼\n"
printf "  ┌─────────────────┐\n"
printf "  │  kernel nftables │  11. Packet arrives\n"
printf "  │  (socket cgroupv2│  12. Match cgroup + src IP → set element\n"
printf "  │   level 2)       │  13. Apply fragment rules (accept/drop)\n"
printf "  └────────┬────────┘\n"
printf "           │\n"
printf "           ▼\n"
printf "  ┌─────────────────┐\n"
printf "  │  journald        │  14. Auth event (pam_prmana)\n"
printf "  │  audit trail      │  15. Session event (pam_authnft)\n"
printf "  │                  │  16. Joined via AUTHNFT_CORRELATION\n"
printf "  └─────────────────┘\n"
printf "\n"

info "Audit queries:"
printf "  ${DIM}# All authnft session events${RESET}\n"
printf "  ${DIM}journalctl -t pam_authnft --since '1 hour ago'${RESET}\n\n"
printf "  ${DIM}# Correlate auth + session for a specific login${RESET}\n"
printf "  ${DIM}journalctl AUTHNFT_CORRELATION=<token>${RESET}\n\n"
printf "  ${DIM}# Active session elements with claims tags${RESET}\n"
printf "  ${DIM}nft list table inet authnft${RESET}\n\n"
printf "  ${DIM}# Session metadata JSON${RESET}\n"
printf "  ${DIM}cat /run/authnft/sessions/*.json | jq .${RESET}\n\n"
printf "  ${DIM}# Live packet trace${RESET}\n"
printf "  ${DIM}nft monitor trace${RESET}\n\n"

if [[ -n "${OUTPUT_FILE}" ]]; then
    info "Audit trail saved to: ${OUTPUT_FILE}"
fi
