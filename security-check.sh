#!/usr/bin/env bash
# OBP-OIDC Security Checker
#
# Runs two passes:
#   1. Config audit   - inspects environment / .env for risky settings
#   2. Runtime probe  - black-box HTTP checks against a running server
#
# Usage:
#   ./security-check.sh                   # probe $OIDC_EXTERNAL_URL or localhost:9000
#   ./security-check.sh -u https://oidc.example.com
#   ./security-check.sh -e .env.prod      # load a specific env file
#
# Exit code: 0 if no FAILs, 1 if any FAIL.

set -u

RED=$'\e[31m'; YELLOW=$'\e[33m'; GREEN=$'\e[32m'; BLUE=$'\e[34m'; NC=$'\e[0m'
PASS=0; WARN=0; FAIL=0

usage() {
  sed -n '2,14p' "$0" | sed 's/^# \{0,1\}//'
}

TARGET_URL=""
ENV_FILE=".env"

while getopts "u:e:h" opt; do
  case "$opt" in
    u) TARGET_URL="$OPTARG" ;;
    e) ENV_FILE="$OPTARG" ;;
    h) usage; exit 0 ;;
    *) usage; exit 1 ;;
  esac
done

if [[ -f "$ENV_FILE" ]]; then
  # shellcheck disable=SC1090
  set -a; . "$ENV_FILE"; set +a
  ENV_LOADED="$ENV_FILE"
else
  ENV_LOADED="(none — using current environment only)"
fi

if [[ -z "$TARGET_URL" ]]; then
  TARGET_URL="${OIDC_EXTERNAL_URL:-http://localhost:9000}"
fi

printf "OBP-OIDC Security Checker\n"
printf "  Target:   %s\n" "$TARGET_URL"
printf "  Env file: %s\n" "$ENV_LOADED"

pass() { printf "%s[PASS]%s %s\n" "$GREEN" "$NC" "$1"; PASS=$((PASS+1)); }
warn() { printf "%s[WARN]%s %s\n" "$YELLOW" "$NC" "$1"; WARN=$((WARN+1)); }
fail() { printf "%s[FAIL]%s %s\n" "$RED" "$NC" "$1"; FAIL=$((FAIL+1)); }
info() { printf "%s[INFO]%s %s\n" "$BLUE" "$NC" "$1"; }
section() { printf "\n== %s ==\n" "$1"; }

check_password() {
  local name="$1" val="${2-}"
  if [[ -z "$val" ]]; then
    warn "$name not set in current env — cannot audit"
    return
  fi
  local len=${#val}
  local lower; lower=$(printf '%s' "$val" | tr '[:upper:]' '[:lower:]')
  case "$lower" in
    password|changeme|changeit|admin|secret|test|todo|"please_change_me"|"replaceme")
      fail "$name is a known placeholder value"
      return
      ;;
  esac
  if (( len < 12 )); then
    fail "$name is only $len chars (min 12 recommended)"
  else
    pass "$name length OK ($len chars)"
  fi
}

############################
# 1) Config audit
############################
section "Config audit"

check_password "OBP_API_PASSWORD"     "${OBP_API_PASSWORD-}"
check_password "OIDC_USER_PASSWORD"   "${OIDC_USER_PASSWORD-}"
check_password "OIDC_ADMIN_PASSWORD"  "${OIDC_ADMIN_PASSWORD-}"

if [[ "${LOCAL_DEVELOPMENT_MODE:-false}" == "true" ]]; then
  warn "LOCAL_DEVELOPMENT_MODE=true — /info, /clients, /stats are exposed"
else
  pass "LOCAL_DEVELOPMENT_MODE disabled (or unset)"
fi

if [[ "$TARGET_URL" =~ ^https:// ]]; then
  pass "Target URL uses HTTPS"
elif [[ "$TARGET_URL" =~ ^http://localhost ]] || [[ "$TARGET_URL" =~ ^http://127\. ]]; then
  info "Target URL is HTTP on loopback (OK for local dev)"
else
  fail "Target URL uses HTTP on non-loopback — tokens and auth codes will flow in cleartext"
fi

if [[ "${ENABLE_DYNAMIC_CLIENT_REGISTRATION:-true}" == "true" ]]; then
  warn "Dynamic Client Registration enabled — confirm rate limits and allowlists are tuned"
else
  info "Dynamic Client Registration disabled"
fi

if [[ "${USE_VERIFY_ENDPOINTS:-false}" == "true" ]]; then
  info "USE_VERIFY_ENDPOINTS=true (OBP API as source of truth)"
else
  info "USE_VERIFY_ENDPOINTS=false (DB views as source of truth)"
fi

token_exp="${OIDC_TOKEN_EXPIRATION:-3600}"
if ! [[ "$token_exp" =~ ^[0-9]+$ ]]; then
  warn "OIDC_TOKEN_EXPIRATION is not numeric: '$token_exp'"
elif (( token_exp > 86400 )); then
  warn "OIDC_TOKEN_EXPIRATION=${token_exp}s (>24h) — short-lived access tokens are preferred"
elif (( token_exp < 60 )); then
  warn "OIDC_TOKEN_EXPIRATION=${token_exp}s is very short"
else
  pass "OIDC_TOKEN_EXPIRATION=${token_exp}s is reasonable"
fi

############################
# 2) Runtime probe
############################
section "Runtime probe"

if ! command -v curl >/dev/null 2>&1; then
  fail "curl not found — runtime probes require curl"
  printf "\nSummary: PASS=%d WARN=%d FAIL=%d\n" "$PASS" "$WARN" "$FAIL"
  exit 2
fi

http_status() { curl -sk -o /dev/null -w "%{http_code}" --max-time 10 "$1" 2>/dev/null; }
http_body()   { curl -sk --max-time 10 "$1" 2>/dev/null; }
http_headers(){ curl -sk -I --max-time 10 "$1" 2>/dev/null; }

health=$(http_status "$TARGET_URL/health")
if [[ "$health" == "200" ]]; then
  pass "/health reachable (200)"
else
  fail "/health not reachable (got '$health') — skipping remaining runtime probes"
  printf "\n== Summary ==\n"
  printf "%sPASS=%d%s  %sWARN=%d%s  %sFAIL=%d%s\n" \
    "$GREEN" "$PASS" "$NC" "$YELLOW" "$WARN" "$NC" "$RED" "$FAIL" "$NC"
  (( FAIL > 0 )) && exit 1 || exit 0
fi

# TLS inspection (if HTTPS)
if [[ "$TARGET_URL" =~ ^https:// ]]; then
  host=$(printf '%s' "$TARGET_URL" | sed -E 's|^https://([^/:]+).*|\1|')
  port=$(printf '%s' "$TARGET_URL" | sed -E 's|^https://[^/:]+:?([0-9]*).*|\1|')
  port="${port:-443}"
  if command -v openssl >/dev/null 2>&1; then
    exp=$(echo | openssl s_client -servername "$host" -connect "$host:$port" 2>/dev/null \
           | openssl x509 -noout -enddate 2>/dev/null | cut -d= -f2)
    if [[ -n "$exp" ]]; then
      pass "TLS handshake succeeded"
      info "TLS certificate not-after: $exp"
    else
      fail "TLS handshake failed against $host:$port"
    fi
  else
    info "openssl not found — skipping TLS inspection"
  fi
fi

# Security headers on "/"
headers=$(http_headers "$TARGET_URL/")

check_header() {
  local hdr="$1" severity="$2" expected="${3-}"
  local line; line=$(printf '%s' "$headers" | grep -i "^$hdr:" | head -n1 | tr -d '\r')
  if [[ -z "$line" ]]; then
    case "$severity" in
      fail) fail "Missing header: $hdr" ;;
      warn) warn "Missing header: $hdr" ;;
    esac
  elif [[ -n "$expected" ]] && ! printf '%s' "$line" | grep -qi "$expected"; then
    warn "Header $hdr present but missing '$expected': $line"
  else
    pass "Header present: $hdr"
  fi
}

if [[ "$TARGET_URL" =~ ^https:// ]]; then
  check_header "Strict-Transport-Security" fail
else
  info "HSTS not applicable on HTTP target"
fi
check_header "X-Content-Type-Options" fail "nosniff"
check_header "X-Frame-Options"        warn
check_header "Referrer-Policy"        warn
check_header "Content-Security-Policy" warn

# Dev-only endpoints
for ep in /info /clients /stats; do
  code=$(http_status "$TARGET_URL$ep")
  if [[ "$code" == "200" ]]; then
    if [[ "${LOCAL_DEVELOPMENT_MODE:-false}" == "true" ]]; then
      info "$ep exposed (200) — expected in dev mode"
    else
      warn "$ep returns 200 with LOCAL_DEVELOPMENT_MODE not true — confirm this is intentional"
    fi
  elif [[ "$code" == "403" || "$code" == "404" ]]; then
    pass "$ep gated ($code)"
  else
    info "$ep returned $code"
  fi
done

# Discovery
disc_url="$TARGET_URL/obp-oidc/.well-known/openid-configuration"
disc=$(http_body "$disc_url")
if [[ -n "$disc" ]] && printf '%s' "$disc" | grep -q '"issuer"'; then
  pass "Discovery document reachable"
  if printf '%s' "$disc" | grep -q '"code_challenge_methods_supported"'; then
    if printf '%s' "$disc" | grep -q '"S256"'; then
      pass "Discovery advertises PKCE S256"
    else
      warn "Discovery advertises PKCE but not S256"
    fi
  else
    warn "Discovery does not advertise PKCE (code_challenge_methods_supported)"
  fi
  issuer=$(printf '%s' "$disc" \
            | grep -oE '"issuer"[[:space:]]*:[[:space:]]*"[^"]+"' \
            | head -1 | sed -E 's/.*"([^"]+)"$/\1/')
  info "issuer = $issuer"
else
  fail "Discovery document unreachable or malformed at $disc_url"
fi

# JWKS
jwks_url="$TARGET_URL/obp-oidc/jwks"
jwks=$(http_body "$jwks_url")
if [[ -n "$jwks" ]] && printf '%s' "$jwks" | grep -q '"keys"'; then
  pass "JWKS reachable"
  n_val=$(printf '%s' "$jwks" \
           | grep -oE '"n"[[:space:]]*:[[:space:]]*"[^"]+"' \
           | head -1 | sed -E 's/.*"([^"]+)"$/\1/')
  n_len=${#n_val}
  # 2048-bit RSA modulus => 256 bytes => ~342 base64url chars (no padding).
  if (( n_len >= 340 )); then
    pass "JWKS RSA modulus looks >= 2048 bits ($n_len b64url chars)"
  elif (( n_len > 0 )); then
    fail "JWKS RSA modulus only $n_len b64url chars — < 2048 bits"
  else
    warn "JWKS did not contain an 'n' field — non-RSA key?"
  fi
else
  fail "JWKS unreachable or malformed at $jwks_url"
fi

# Token endpoint without creds — POST empty form; expect 4xx with an error body
tok_code=$(curl -sk -o /dev/null -w "%{http_code}" --max-time 10 \
  -X POST -H "Content-Type: application/x-www-form-urlencoded" \
  --data "" "$TARGET_URL/obp-oidc/token" 2>/dev/null)
if [[ "$tok_code" == "200" ]]; then
  fail "Token endpoint returned 200 to empty POST"
elif [[ "$tok_code" == "400" || "$tok_code" == "401" ]]; then
  pass "Token endpoint rejects empty POST ($tok_code)"
else
  info "Token endpoint returned $tok_code for empty POST"
fi

# Authorize endpoint — send a full OIDC param set with a bogus client_id.
# Healthy responses: 302/303 (redirect to login or to redirect_uri with error),
# 400 (client_id validation), 200 (error page rendered inline).
auth_q="response_type=code&scope=openid&client_id=__security_check__&redirect_uri=http://localhost/x&state=sc"
auth_code=$(http_status "$TARGET_URL/obp-oidc/auth?$auth_q")
case "$auth_code" in
  302|303|400) pass "Authorize endpoint handled invalid request ($auth_code)" ;;
  200)         warn "Authorize endpoint returned 200 to invalid request — check param validation" ;;
  404)         fail "Authorize endpoint returned 404 — route may not be mounted" ;;
  *)           info "Authorize endpoint returned $auth_code" ;;
esac

# /status parity
status_code=$(http_status "$TARGET_URL/status.json")
if [[ "$status_code" == "200" ]]; then
  body=$(http_body "$TARGET_URL/status.json")
  if printf '%s' "$body" | grep -q '"status":"ok"'; then
    pass "/status.json overall = ok"
  else
    warn "/status.json reachable but overall not ok — open /status for details"
  fi
else
  info "/status.json returned $status_code"
fi

############################
# Summary
############################
printf "\n== Summary ==\n"
printf "%sPASS=%d%s  %sWARN=%d%s  %sFAIL=%d%s\n" \
  "$GREEN" "$PASS" "$NC" "$YELLOW" "$WARN" "$NC" "$RED" "$FAIL" "$NC"

(( FAIL > 0 )) && exit 1 || exit 0
