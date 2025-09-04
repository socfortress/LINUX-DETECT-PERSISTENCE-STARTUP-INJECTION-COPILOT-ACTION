#!/bin/sh
set -eu

ScriptName="Detect-Persistence-Startup-Injection"
LogPath="/tmp/${ScriptName}-script.log"
ARLog="/var/ossec/logs/active-responses.log"
LogMaxKB=100
LogKeep=5
HostName="$(hostname)"
runStart=$(date +%s)

RECENT_DAYS="${RECENT_DAYS:-90}"
HASH_ALL="${HASH_ALL:-0}"
DO_FIX="0"
[ "${1:-}" = "--fix" ] && DO_FIX="1"
[ "${FIX:-0}" = "1" ] && DO_FIX="1"

WriteLog() {
  Message="$1"; Level="${2:-INFO}"
  ts="$(date '+%Y-%m-%d %H:%M:%S')"
  line="[$ts][$Level] $Message"
  case "$Level" in
    ERROR) printf '\033[31m%s\033[0m\n' "$line" >&2 ;;
    WARN)  printf '\033[33m%s\033[0m\n' "$line" >&2 ;;
    DEBUG) [ "${VERBOSE:-0}" -eq 1 ] && printf '%s\n' "$line" >&2 ;;
    *)     printf '%s\n' "$line" >&2 ;;
  esac
  printf '%s\n' "$line" >> "$LogPath"
}

RotateLog() {
  [ -f "$LogPath" ] || return 0
  size_kb=$(du -k "$LogPath" | awk '{print $1}')
  [ "$size_kb" -le "$LogMaxKB" ] && return 0
  i=$((LogKeep-1))
  while [ $i -ge 0 ]; do
    [ -f "$LogPath.$i" ] && mv -f "$LogPath.$i" "$LogPath.$((i+1))"
    i=$((i-1))
  done
  mv -f "$LogPath" "$LogPath.1"
}

iso_now() { date -u +"%Y-%m-%dT%H:%M:%SZ"; }
escape_json() { printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g'; }
is_valid_shell() { case "$1" in */nologin|*/false|"") return 1 ;; *) return 0 ;; esac; }
is_comment_or_blank() {
  line="$1"
  printf '%s' "$line" | grep -Eq '^[[:space:]]*$' && return 0 || true
  printf '%s' "$line" | grep -Eq '^[[:space:]]*#' && return 0 || true
  return 1
}
is_benign_line() {
  echo "$1" | grep -Eiq '(PS1=|PROMPT_COMMAND=__vte_|bash_completion|XDG_DATA_DIRS|XDG_CONFIG_DIRS|debian_chroot|lesspipe|dircolors|checkwinsize|sudo hint|flatpak\.sh|vte-2\.91\.sh|cloud-init warnings|locale test|apps-bin-path|gnome-session_gnomerc|cedilla-portuguese|^return 0$)'
}
hit_category() {
  line="$1"
  echo "$line" | grep -Eiq '(curl|wget|fetch)[^|;\n]*https?://[^|;\n]*\|\s*(sh|bash|zsh|ksh)' && { echo "pipe_download"; return; }
  echo "$line" | grep -Eiq 'base64\s+-d\s*\|\s*(sh|bash)|python[^#\n]*base64[^#\n]*decode|perl[^#\n]*MIME::Base64|eval\s+["'\''`].{0,200}(base64|\\x[0-9a-f]{2}|[A-Za-z0-9+/]{200,}={0,2})' && { echo "encoded_exec"; return; }
  echo "$line" | grep -Eiq '(nc|ncat|netcat)\s+[^#\n]*( -e |/bin/sh|/bin/bash)|bash\s+-i[^#\n]*>/dev/tcp/|/dev/tcp/[0-9\.]+/[0-9]+|python\s+-c\s*["'\''`][^"'\''`]*socket[^"'\''`]*connect|openssl\s+s_client[^|]*\|\s*(sh|bash)' && { echo "revshell"; return; }
  echo "$line" | grep -Eiq 'stratum\+tcp|xmrig|minerd|cpuminer|hellminer|nbminer|t-rex|trex|lolminer|bminer|phoenixminer|teamredminer|gminer|ethminer' && { echo "miner"; return; }
  echo "$line" | grep -Eiq '(^|;|\s)export\s+PATH=.*(^|:)(\.|/tmp|/var/tmp|/dev/shm)(:|$)|(^|;|\s)(LD_PRELOAD=|export\s+LD_PRELOAD)\s*/(tmp|var/tmp|dev/shm)/' && { echo "env_hijack"; return; }
  echo "$line" | grep -Eiq 'PROMPT_COMMAND=.*(curl|wget|nc|/dev/tcp|bash\s+-i)|(^|;|\s)trap\s+['"'"'"].*['"'"'"]' && { echo "prompt_trap"; return; }
  echo ""
}
file_score_for_cat() { case "$1" in revshell) echo 50 ;; pipe_download|encoded_exec) echo 40 ;; miner) echo 35 ;; env_hijack|prompt_trap) echo 25 ;; *) echo 0 ;; esac; }

collect_targets() {
  printf '%s\n' "/etc/profile" "/etc/bash.bashrc"
  if [ "${SKIP_ETC_PROFILED:-0}" != "1" ] && [ -d /etc/profile.d ]; then
    find /etc/profile.d -maxdepth 1 -type f -name '*.sh' 2>/dev/null
  fi
  getent passwd | awk -F: '($3>=1000 || $1=="root"){print $6":"$7}' | \
  while IFS=: read -r home shell; do
    is_valid_shell "$shell" || continue
    [ -d "$home" ] || continue
    printf '%s\n' \
      "$home/.bashrc" "$home/.profile" "$home/.bash_profile" "$home/.bash_login" \
      "$home/.zshrc" "$home/.zprofile" "$home/.zlogin" \
      "$home/.xprofile" "$home/.xsessionrc"
  done
}

BeginNDJSON(){ TMP_AR="$(mktemp)"; }
AddHit(){
  ts="$(iso_now)"
  file="$1"; line_no="$2"; category="$3"; text="$4"
  mtime="$5"; size="$6"; sha="$7"; owner="$8"; perm="$9"; ww="${10}"; recent="${11}"
  printf '{"timestamp":"%s","host":"%s","action":"%s","copilot_action":true,"file":"%s","line":%s,"category":"%s","text":"%s","mtime":"%s","size":%s,"sha256":"%s","owner":"%s","perm":"%s","world_writable":%s,"recent_mod":%s}\n' \
    "$ts" "$HostName" "$ScriptName" \
    "$(escape_json "$file")" "$line_no" "$(escape_json "$category")" "$(escape_json "$text")" \
    "$(escape_json "$mtime")" "${size:-0}" "$(escape_json "$sha")" "$(escape_json "$owner")" "$(escape_json "$perm")" \
    "$ww" "$recent" >> "$TMP_AR"
}
AddFileStatus(){
  ts="$(iso_now)"; file="$1"; exists="$2"; readable="$3"
  printf '{"timestamp":"%s","host":"%s","action":"%s","copilot_action":true,"file":"%s","exists":"%s","readable":"%s"}\n' \
    "$ts" "$HostName" "$ScriptName" "$(escape_json "$file")" "$(escape_json "$exists")" "$(escape_json "$readable")" >> "$TMP_AR"
}
AddRemediation(){
  ts="$(iso_now)"; file="$1"; backup="$2"; lines="$3"
  printf '{"timestamp":"%s","host":"%s","action":"%s","copilot_action":true,"remediation":true,"file":"%s","backup":"%s","commented_lines":%s}\n' \
    "$ts" "$HostName" "$ScriptName" "$(escape_json "$file")" "$(escape_json "$backup")" "$lines" >> "$TMP_AR"
}
AddSummary(){
  ts="$(iso_now)"; sev="$1"; recent_days="$2"; hash_all="$3"; fix_applied="$4"
  printf '{"timestamp":"%s","host":"%s","action":"%s","copilot_action":true,"summary":true,"severity":"%s","recent_days":%s,"hash_all":%s,"fix_applied":%s}\n' \
    "$ts" "$HostName" "$ScriptName" "$(escape_json "$sev")" "$recent_days" "$hash_all" "$fix_applied" >> "$TMP_AR"
}
AddInfo(){
  ts="$(iso_now)"; msg="$(escape_json "$1")"
  printf '{"timestamp":"%s","host":"%s","action":"%s","copilot_action":true,"status":"info","message":"%s"}\n' \
    "$ts" "$HostName" "$ScriptName" "$msg" >> "$TMP_AR"
}

CommitNDJSON(){
  [ -s "$TMP_AR" ] || AddInfo "no_results"
  AR_DIR="$(dirname "$ARLog")"
  [ -d "$AR_DIR" ] || WriteLog "Directory missing: $AR_DIR (will attempt write anyway)" WARN
  if mv -f "$TMP_AR" "$ARLog"; then
    WriteLog "Wrote NDJSON to $ARLog" INFO
  else
    WriteLog "Primary write FAILED to $ARLog" WARN
    if mv -f "$TMP_AR" "$ARLog.new"; then
      WriteLog "Wrote NDJSON to $ARLog.new (fallback)" WARN
    else
      keep="/tmp/active-responses.$$.ndjson"
      cp -f "$TMP_AR" "$keep" 2>/dev/null || true
      WriteLog "Failed to write both $ARLog and $ARLog.new; saved $keep" ERROR
      rm -f "$TMP_AR" 2>/dev/null || true
      exit 1
    fi
  fi
  for p in "$ARLog" "$ARLog.new"; do
    if [ -f "$p" ]; then
      sz=$(wc -c < "$p" 2>/dev/null || echo 0)
      ino=$(ls -li "$p" 2>/dev/null | awk '{print $1}')
      head1=$(head -n1 "$p" 2>/dev/null || true)
      WriteLog "VERIFY: path=$p inode=$ino size=${sz}B first_line=${head1:-<empty>}" INFO
    fi
  done
}

RotateLog
WriteLog "=== SCRIPT START : $ScriptName (host=$HostName) ==="
BeginNDJSON

targets="$(collect_targets | awk 'NF' | sort -u)"
tmpdir="$(mktemp -d)"
overall_sev="low"
any_hits=0
fix_applied="false"

for tgt in $targets; do
  if [ ! -f "$tgt" ]; then
    AddFileStatus "$tgt" "false" "false"
    continue
  fi
  if [ ! -r "$tgt" ]; then
    AddFileStatus "$tgt" "true" "false"
    continue
  fi

  mtime_epoch="$(stat -c %Y "$tgt" 2>/dev/null || date -r "$tgt" +%s 2>/dev/null || echo 0)"
  mtime_iso="$(date -u -d "@$mtime_epoch" '+%Y-%m-%dT%H:%M:%SZ' 2>/dev/null || date -r "$tgt" '+%Y-%m-%dT%H:%M:%SZ' 2>/dev/null || echo "")"
  size="$(stat -c%s "$tgt" 2>/dev/null || wc -c <"$tgt" 2>/dev/null || echo 0)"
  owner="$(stat -c '%U' "$tgt" 2>/dev/null || echo "")"
  perm="$(stat -c '%a' "$tgt" 2>/dev/null || echo "")"
  ww="false"; echo "$perm" | grep -Eq '.[2367][2367]$' && ww="true"
  recent="$( [ $(( $(date +%s) - mtime_epoch )) -le $(( RECENT_DAYS*86400 )) ] && echo true || echo false )"
  sha=""
  if [ "$HASH_ALL" = "1" ]; then
    command -v sha256sum >/dev/null 2>&1 && sha="$(sha256sum "$tgt" 2>/dev/null | awk '{print $1}')"
  fi

  ln=0
  hit_lines_file="$tmpdir/$(echo "$tgt" | sed 's/[\/\.]/_/g').lines"
  : > "$hit_lines_file"
  file_score=0

  while IFS= read -r line || [ -n "$line" ]; do
    ln=$((ln+1))
    is_comment_or_blank "$line" && continue
    is_benign_line "$line" && continue
    catg="$(hit_category "$line")"; [ -z "$catg" ] && continue

    any_hits=1
    s="$(file_score_for_cat "$catg")"; file_score=$((file_score+s))
    if [ -z "$sha" ]; then
      if [ "$HASH_ALL" = "1" ] || [ -n "$catg" ]; then
        command -v sha256sum >/dev/null 2>&1 && sha="$(sha256sum "$tgt" 2>/dev/null | awk '{print $1}')"
      fi
    fi
    esc_text="$(printf '%s' "$line" | tr -d '\r')"
    AddHit "$tgt" "$ln" "$catg" "$esc_text" "$mtime_iso" "$size" "$sha" "$owner" "$perm" "$ww" "$recent"

    printf '%s\n' "$ln" >> "$hit_lines_file"
  done < "$tgt"
  grep -q '"category":"revshell"' "$TMP_AR" 2>/dev/null && overall_sev="critical"
  if [ "$overall_sev" = "low" ]; then
    grep -q '"category":"pipe_download"' "$TMP_AR" 2>/dev/null && overall_sev="high"
  fi
  if [ "$overall_sev" = "low" ]; then
    grep -q '"category":"encoded_exec"' "$TMP_AR" 2>/dev/null && overall_sev="high"
  fi
  if [ "$overall_sev" = "low" ]; then
    grep -q '"category":"miner"' "$TMP_AR" 2>/dev/null && overall_sev="medium"
    grep -q '"category":"env_hijack"' "$TMP_AR" 2>/dev/null && overall_sev="medium"
    grep -q '"category":"prompt_trap"' "$TMP_AR" 2>/dev/null && overall_sev="medium"
  fi
  if grep -q '"recent_mod":true' "$TMP_AR" 2>/dev/null; then
    [ "$overall_sev" != "low" ] && overall_sev="critical"
  fi
done
if [ "$DO_FIX" = "1" ] && { [ "$overall_sev" = "high" ] || [ "$overall_sev" = "critical" ]; }; then
  WriteLog "Auto-remediation enabled (--fix). Applying comments to flagged lines." WARN
  for tgt in $targets; do
    hf="$tmpdir/$(echo "$tgt" | sed 's/[\/\.]/_/g').lines"
    [ -f "$tgt" ] || continue
    [ -s "$hf" ] || continue
    tsfix="$(date -u '+%Y%m%d%H%M%S')"
    bak="${tgt}.bak.${tsfix}"
    cp -p "$tgt" "$bak" 2>/dev/null || cp "$tgt" "$bak" 2>/dev/null || true
    lines="$(awk 'NF' "$hf" | paste -sd, -)"
    tmpf="$tmpdir/patch.$$"
    awk -v LINES="$lines" -v TS="$tsfix" '
      BEGIN{ split(LINES, a, ","); for(i in a) mark[a[i]]=1 }
      { ln++; if (ln in mark) { print "# [SOAR-" TS "] " $0 } else { print $0 } }
    ' ln=0 "$tgt" > "$tmpf"
    mv -f "$tmpf" "$tgt"
    fix_applied="true"
    clist="["; first=1
    for l in $(awk 'NF' "$hf"); do
      if [ $first -eq 1 ]; then clist="$clist$l"; first=0; else clist="$clist,$l"; fi
    done
    clist="$clist]"
    AddRemediation "$tgt" "$bak" "$clist"
  done
fi
AddSummary "$overall_sev" "$RECENT_DAYS" "$([ "$HASH_ALL" = "1" ] && echo true || echo false)" "$fix_applied"
[ "$any_hits" -eq 1 ] || AddInfo "no suspicious startup injection lines detected"
CommitNDJSON
dur=$(( $(date +%s) - runStart ))
WriteLog "=== SCRIPT END : ${dur}s ==="
