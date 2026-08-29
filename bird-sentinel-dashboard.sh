#!/usr/bin/env bash
# Sentinel TUI - lightweight Linux dashboard with read-only built-in collectors.

set -u

VERSION="1.3.0"
REFRESH_SECONDS="${SENTINEL_REFRESH:-20}"
MAX_ROWS="${SENTINEL_ROWS:-0}"
CONNECTION_FILTER=""
NETWORK_INTERFACES="wlan0,eth0"
PING_TARGET="${SENTINEL_PING_TARGET:-1.1.1.1}"
CUSTOM_COMMAND="${SENTINEL_COMMAND:-htop}"
TMP_DIR=""
TMUX_SOCKET=""
STOPPED=0
STARTED=0
declare -A PANEL_V PANEL_H
PANEL_ORDER=(resources persistence connections command)
ACTIVE_PANEL=0
MISSING_TOOLS=()
NEED_CORE=0; NEED_AWK=0; NEED_SED=0; NEED_GREP=0; NEED_FIND=0
NEED_PROCPS=0; NEED_TPUT=0; NEED_NETWORK=0; NEED_PING=0; NEED_HTTP=0
NEED_TMUX=0; NEED_HTOP=0

# Palette (disabled automatically when stdout is not a terminal or NO_COLOR is set).
if [[ -t 1 && -z "${NO_COLOR:-}" ]]; then
  RESET=$'\e[0m'; BOLD=$'\e[1m'; DIM=$'\e[2m'
  GREEN=$'\e[38;5;46m'; LIME=$'\e[38;5;118m'; CYAN=$'\e[38;5;51m'
  BLUE=$'\e[38;5;39m'; YELLOW=$'\e[38;5;226m'; RED=$'\e[38;5;196m'
  MAGENTA=$'\e[38;5;201m'; GRAY=$'\e[38;5;244m'; DARK=$'\e[38;5;238m'
else
  RESET=""; BOLD=""; DIM=""; GREEN=""; LIME=""; CYAN=""; BLUE=""
  YELLOW=""; RED=""; MAGENTA=""; GRAY=""; DARK=""
fi

cleanup() {
  STOPPED=1
  trap - INT TERM EXIT
  if [[ -n "$TMUX_SOCKET" ]] && command -v tmux >/dev/null 2>&1 && [[ -S "$TMUX_SOCKET" ]]; then
    tmux -S "$TMUX_SOCKET" kill-server >/dev/null 2>&1 || true
  fi
  [[ -n "$TMP_DIR" ]] && rm -rf -- "$TMP_DIR"
  if ((STARTED)); then
    if [[ -t 1 ]]; then printf '\e[?7h\e[?25h\e[?1049l\e[0m'; fi
    printf '\nSentinel encerrado; coletores e arquivos temporários removidos.\n'
  fi
}
trap cleanup INT TERM EXIT

usage() {
  cat <<EOF
Uso: ${0##*/} [opções]
  -i SEG   intervalo de atualização (padrão e mínimo: 20 segundos)
  -r N     altura-base dos quadros (0 = automático)
  -f LISTA nomes a ocultar nas conexões, separados por vírgula
           exemplo: -f firefox,mega,antigravity
  -n LISTA interfaces de rede, separadas por vírgula (padrão: wlan0,eth0)
           exemplo: -n wlp2s0,enp3s0
  -p ALVO  host/IP do ping usado na média (padrão: 1.1.1.1)
  -c CMD   comando exibido no quarto quadro (padrão: htop)
           exemplo: -c 'df -h'
  -h       ajuda

Variáveis: SENTINEL_REFRESH, SENTINEL_ROWS, SENTINEL_PING_TARGET,
           SENTINEL_COMMAND, NO_COLOR
A coleta padrão é somente leitura; -c executa o texto informado pelo usuário.
Linux + Bash 4 ou superior.
EOF
}

while getopts ":i:r:f:n:p:c:h" opt; do
  case "$opt" in
    i) REFRESH_SECONDS="$OPTARG" ;;
    r) MAX_ROWS="$OPTARG" ;;
    f) CONNECTION_FILTER="$OPTARG" ;;
    n) NETWORK_INTERFACES="$OPTARG" ;;
    p) PING_TARGET="$OPTARG" ;;
    c) CUSTOM_COMMAND="$OPTARG" ;;
    h) usage; exit 0 ;;
    *) usage >&2; exit 2 ;;
  esac
done
[[ "$REFRESH_SECONDS" =~ ^[0-9]+([.][0-9]+)?$ ]] || { echo "Intervalo inválido" >&2; exit 2; }
refresh_whole="${REFRESH_SECONDS%%.*}"
((10#$refresh_whole >= 20)) || { echo "O intervalo mínimo é 20 segundos" >&2; exit 2; }
[[ "$MAX_ROWS" =~ ^[0-9]+$ ]] || { echo "Número de linhas inválido" >&2; exit 2; }
[[ -n "$PING_TARGET" && "$PING_TARGET" != -* && "$PING_TARGET" =~ ^[[:alnum:].:_%-]+$ ]] || {
  echo "Alvo de ping inválido" >&2; exit 2;
}
[[ -n "$CUSTOM_COMMAND" && "$CUSTOM_COMMAND" != *$'\n'* ]] || { echo "Comando inválido" >&2; exit 2; }
[[ ${BASH_VERSINFO[0]} -ge 4 ]] || { echo "Requer Bash 4+" >&2; exit 1; }
[[ -d /proc ]] || { echo "Requer Linux com /proc" >&2; exit 1; }

scan_dependencies() {
  local tool command_name
  MISSING_TOOLS=()
  NEED_CORE=0; NEED_AWK=0; NEED_SED=0; NEED_GREP=0; NEED_FIND=0
  NEED_PROCPS=0; NEED_TPUT=0; NEED_NETWORK=0; NEED_PING=0; NEED_HTTP=0
  NEED_TMUX=0; NEED_HTOP=0

  for tool in sort head cut paste who date getconf df readlink tr timeout tail sleep mktemp rm; do
    if ! command -v "$tool" >/dev/null 2>&1; then
      MISSING_TOOLS+=("$tool"); NEED_CORE=1
    fi
  done
  command -v awk >/dev/null 2>&1 || { MISSING_TOOLS+=(awk); NEED_AWK=1; }
  command -v sed >/dev/null 2>&1 || { MISSING_TOOLS+=(sed); NEED_SED=1; }
  command -v grep >/dev/null 2>&1 || { MISSING_TOOLS+=(grep); NEED_GREP=1; }
  command -v find >/dev/null 2>&1 || { MISSING_TOOLS+=(find); NEED_FIND=1; }
  for tool in ps top; do
    if ! command -v "$tool" >/dev/null 2>&1; then
      MISSING_TOOLS+=("$tool"); NEED_PROCPS=1
    fi
  done
  command -v tput >/dev/null 2>&1 || { MISSING_TOOLS+=(tput); NEED_TPUT=1; }
  if ! command -v ip >/dev/null 2>&1 || ! command -v ss >/dev/null 2>&1; then
    MISSING_TOOLS+=(ip/ss); NEED_NETWORK=1
  fi
  command -v ping >/dev/null 2>&1 || { MISSING_TOOLS+=(ping); NEED_PING=1; }
  if ! command -v curl >/dev/null 2>&1 && ! command -v wget >/dev/null 2>&1; then
    MISSING_TOOLS+=(curl/wget); NEED_HTTP=1
  fi

  command_name="${CUSTOM_COMMAND#"${CUSTOM_COMMAND%%[![:space:]]*}"}"
  command_name="${command_name%%[[:space:]]*}"
  if [[ "${command_name##*/}" == htop ]]; then
    command -v tmux >/dev/null 2>&1 || { MISSING_TOOLS+=(tmux); NEED_TMUX=1; }
    command -v "$command_name" >/dev/null 2>&1 || { MISSING_TOOLS+=(htop); NEED_HTOP=1; }
  fi
}

detect_package_manager() {
  local distro_id="" distro_like="" key value manager
  if [[ -r /etc/os-release ]]; then
    while IFS='=' read -r key value; do
      value="${value#\"}"; value="${value%\"}"
      case "$key" in
        ID) distro_id="$value" ;;
        ID_LIKE) distro_like="$value" ;;
      esac
    done < /etc/os-release
  fi
  case " $distro_id $distro_like " in
    *debian*|*ubuntu*) command -v apt-get >/dev/null 2>&1 && { printf apt; return; } ;;
    *fedora*|*rhel*|*centos*)
      command -v dnf >/dev/null 2>&1 && { printf dnf; return; }
      command -v yum >/dev/null 2>&1 && { printf yum; return; } ;;
    *arch*) command -v pacman >/dev/null 2>&1 && { printf pacman; return; } ;;
    *suse*) command -v zypper >/dev/null 2>&1 && { printf zypper; return; } ;;
    *alpine*) command -v apk >/dev/null 2>&1 && { printf apk; return; } ;;
  esac
  for manager in apt-get dnf yum pacman zypper apk; do
    if command -v "$manager" >/dev/null 2>&1; then
      printf '%s' "${manager/-get/}"
      return
    fi
  done
  return 1
}

install_missing_dependencies() {
  local manager
  local -a packages=() elevate=()
  scan_dependencies
  ((${#MISSING_TOOLS[@]} == 0)) && return 0

  printf 'Sentinel: dependências ausentes: %s\n' "${MISSING_TOOLS[*]}" >&2
  manager=$(detect_package_manager) || {
    printf 'Sentinel: nenhum gerenciador compatível encontrado (apt, dnf, yum, pacman, zypper ou apk).\n' >&2
    return 1
  }
  if ((EUID != 0)); then
    if command -v sudo >/dev/null 2>&1; then elevate=(sudo)
    elif command -v doas >/dev/null 2>&1; then elevate=(doas)
    else
      printf 'Sentinel: execute como root ou instale sudo/doas para preparar as dependências.\n' >&2
      return 1
    fi
  fi

  case "$manager" in
    apt)
      ((NEED_CORE)) && packages+=(coreutils)
      ((NEED_AWK)) && packages+=(gawk)
      ((NEED_SED)) && packages+=(sed)
      ((NEED_GREP)) && packages+=(grep)
      ((NEED_FIND)) && packages+=(findutils)
      ((NEED_PROCPS)) && packages+=(procps)
      ((NEED_TPUT)) && packages+=(ncurses-bin)
      ((NEED_NETWORK)) && packages+=(iproute2)
      ((NEED_PING)) && packages+=(iputils-ping)
      ((NEED_HTTP)) && packages+=(curl)
      ((NEED_TMUX)) && packages+=(tmux)
      ((NEED_HTOP)) && packages+=(htop)
      printf 'Sentinel: preparando dependências com apt...\n' >&2
      "${elevate[@]}" apt-get update || printf 'Sentinel: aviso: não foi possível atualizar o índice do apt; tentando instalar mesmo assim.\n' >&2
      "${elevate[@]}" env DEBIAN_FRONTEND=noninteractive apt-get install -y -- "${packages[@]}" || return 1
      ;;
    dnf|yum)
      ((NEED_CORE)) && packages+=(coreutils)
      ((NEED_AWK)) && packages+=(gawk)
      ((NEED_SED)) && packages+=(sed)
      ((NEED_GREP)) && packages+=(grep)
      ((NEED_FIND)) && packages+=(findutils)
      ((NEED_PROCPS)) && packages+=(procps-ng)
      ((NEED_TPUT)) && packages+=(ncurses)
      ((NEED_NETWORK)) && packages+=(iproute)
      ((NEED_PING)) && packages+=(iputils)
      ((NEED_HTTP)) && packages+=(curl)
      ((NEED_TMUX)) && packages+=(tmux)
      ((NEED_HTOP)) && packages+=(htop)
      printf 'Sentinel: preparando dependências com %s...\n' "$manager" >&2
      "${elevate[@]}" "$manager" install -y "${packages[@]}" || return 1
      ;;
    pacman)
      ((NEED_CORE)) && packages+=(coreutils)
      ((NEED_AWK)) && packages+=(gawk)
      ((NEED_SED)) && packages+=(sed)
      ((NEED_GREP)) && packages+=(grep)
      ((NEED_FIND)) && packages+=(findutils)
      ((NEED_PROCPS)) && packages+=(procps-ng)
      ((NEED_TPUT)) && packages+=(ncurses)
      ((NEED_NETWORK)) && packages+=(iproute2)
      ((NEED_PING)) && packages+=(iputils)
      ((NEED_HTTP)) && packages+=(curl)
      ((NEED_TMUX)) && packages+=(tmux)
      ((NEED_HTOP)) && packages+=(htop)
      printf 'Sentinel: preparando dependências com pacman...\n' >&2
      "${elevate[@]}" pacman -S --needed --noconfirm "${packages[@]}" || return 1
      ;;
    zypper)
      ((NEED_CORE)) && packages+=(coreutils)
      ((NEED_AWK)) && packages+=(gawk)
      ((NEED_SED)) && packages+=(sed)
      ((NEED_GREP)) && packages+=(grep)
      ((NEED_FIND)) && packages+=(findutils)
      ((NEED_PROCPS)) && packages+=(procps)
      ((NEED_TPUT)) && packages+=(ncurses-utils)
      ((NEED_NETWORK)) && packages+=(iproute2)
      ((NEED_PING)) && packages+=(iputils)
      ((NEED_HTTP)) && packages+=(curl)
      ((NEED_TMUX)) && packages+=(tmux)
      ((NEED_HTOP)) && packages+=(htop)
      printf 'Sentinel: preparando dependências com zypper...\n' >&2
      "${elevate[@]}" zypper --non-interactive install "${packages[@]}" || return 1
      ;;
    apk)
      ((NEED_CORE)) && packages+=(coreutils)
      ((NEED_AWK)) && packages+=(gawk)
      ((NEED_SED)) && packages+=(sed)
      ((NEED_GREP)) && packages+=(grep)
      ((NEED_FIND)) && packages+=(findutils)
      ((NEED_PROCPS)) && packages+=(procps)
      ((NEED_TPUT)) && packages+=(ncurses)
      ((NEED_NETWORK)) && packages+=(iproute2)
      ((NEED_PING)) && packages+=(iputils)
      ((NEED_HTTP)) && packages+=(curl)
      ((NEED_TMUX)) && packages+=(tmux)
      ((NEED_HTOP)) && packages+=(htop)
      printf 'Sentinel: preparando dependências com apk...\n' >&2
      "${elevate[@]}" apk add "${packages[@]}" || return 1
      ;;
  esac

  hash -r
  scan_dependencies
  if ((${#MISSING_TOOLS[@]} > 0)); then
    printf 'Sentinel: a instalação terminou, mas ainda faltam: %s\n' "${MISSING_TOOLS[*]}" >&2
    return 1
  fi
  printf 'Sentinel: dependências instaladas; iniciando o painel.\n' >&2
}

install_missing_dependencies || {
  printf 'Sentinel: não foi possível preparar o ambiente; o painel não será iniciado.\n' >&2
  exit 1
}
TMP_DIR=$(mktemp -d "${TMPDIR:-/tmp}/sentinel.XXXXXX") || {
  printf 'Sentinel: não foi possível criar o diretório temporário.\n' >&2
  exit 1
}
TMUX_SOCKET="$TMP_DIR/tmux-command.sock"

repeat_char() { local c="$1" n="$2" out=""; printf -v out '%*s' "$n" ''; printf '%s' "${out// /$c}"; }
clip() { local s="$1" n="$2"; ((${#s} > n)) && printf '%s…' "${s:0:n-1}" || printf '%s' "$s"; }
bar() {
  local pct="${1%.*}" width="${2:-16}" fill_color="${3:-$GREEN}" fill empty
  ((pct < 0)) && pct=0; ((pct > 100)) && pct=100
  fill=$((pct * width / 100)); empty=$((width - fill))
  printf '%s' "$fill_color"; repeat_char '█' "$fill"; printf '%s' "$DARK"; repeat_char '░' "$empty"; printf '%s' "$RESET"
}

temperature_badge() {
  local value="$1" warning="${2:-75}" critical="${3:-90}" numeric
  numeric="${value%°C}"
  if [[ ! "$numeric" =~ ^-?[0-9]+([.][0-9]+)?$ ]]; then
    printf '%s○%s %s' "$GRAY" "$RESET" "$value"
  elif awk -v n="$numeric" -v limit="$critical" 'BEGIN {exit !(n>=limit)}'; then
    printf '%s●%s %s' "$RED" "$RESET" "$value"
  elif awk -v n="$numeric" -v limit="$warning" 'BEGIN {exit !(n>=limit)}'; then
    printf '%s●%s %s' "$YELLOW" "$RESET" "$value"
  else
    printf '%s●%s %s' "$GREEN" "$RESET" "$value"
  fi
}

ping_badge() {
  local value="$1" numeric
  numeric="${value% ms}"
  if [[ ! "$numeric" =~ ^[0-9]+([.][0-9]+)?$ ]]; then
    printf '%s○%s %s' "$RED" "$RESET" "$value"
  elif awk -v n="$numeric" 'BEGIN {exit !(n>=150)}'; then
    printf '%s●%s %s' "$RED" "$RESET" "$value"
  elif awk -v n="$numeric" 'BEGIN {exit !(n>=80)}'; then
    printf '%s●%s %s' "$YELLOW" "$RESET" "$value"
  else
    printf '%s●%s %s' "$GREEN" "$RESET" "$value"
  fi
}

storage_bar() {
  local pct="${1%\%}" color="$GREEN"
  ((pct>=90)) && color="$RED"
  ((pct>=75 && pct<90)) && color="$YELLOW"
  bar "$pct" 8 "$color"
}

format_duration() {
  local seconds="$1" days hours minutes
  ((seconds<0)) && seconds=0
  days=$((seconds/86400)); hours=$((seconds%86400/3600)); minutes=$((seconds%3600/60))
  if ((days>0)); then printf '%dd %02dh %02dm' "$days" "$hours" "$minutes"
  elif ((hours>0)); then printf '%dh %02dm' "$hours" "$minutes"
  else printf '%dm' "$minutes"
  fi
}

millidegrees_to_celsius() {
  awk -v value="$1" 'BEGIN {printf "%.1f°C", value/1000}'
}

read_sensor_label() {
  local input="$1" label_file="${1%_input}_label"
  if [[ -r "$label_file" ]]; then
    IFS= read -r REPLY < "$label_file" 2>/dev/null || REPLY=""
  else
    REPLY=""
  fi
}

detect_cpu_temperature() {
  local hwmon chip input raw label best="" candidate=0
  local -a preferred=() labelled=()
  shopt -s nullglob
  for hwmon in /sys/class/hwmon/hwmon*; do
    chip=""; [[ -r "$hwmon/name" ]] && IFS= read -r chip < "$hwmon/name"
    for input in "$hwmon"/temp*_input; do
      [[ -r "$input" ]] || continue
      IFS= read -r raw < "$input" || continue
      [[ "$raw" =~ ^-?[0-9]+$ ]] || continue
      ((raw >= -10000 && raw <= 200000)) || continue
      read_sensor_label "$input"; label="$REPLY"
      case "${chip,,}" in
        coretemp|k10temp|zenpower|cpu_thermal|cpu-thermal|soc_thermal|soc-thermal)
          preferred+=("$raw") ;;
      esac
      [[ "${label,,}" =~ (cpu|package|tctl|tdie|soc) ]] && labelled+=("$raw")
    done
  done
  shopt -u nullglob
  if ((${#preferred[@]}>0)); then
    for raw in "${preferred[@]}"; do ((candidate==0 || raw>best)) && best="$raw"; candidate=1; done
  else
    for raw in "${labelled[@]}"; do ((candidate==0 || raw>best)) && best="$raw"; candidate=1; done
  fi
  [[ -n "$best" ]] && millidegrees_to_celsius "$best" || printf 'não detectada'
}

detect_gpu_temperature() {
  local line name temp hwmon chip input raw label best="" found=0
  if command -v nvidia-smi >/dev/null 2>&1; then
    line=$(nvidia-smi --query-gpu=temperature.gpu,name --format=csv,noheader,nounits 2>/dev/null | head -n 1 || true)
    IFS=',' read -r temp name <<< "$line"
    temp="${temp//[[:space:]]/}"
    if [[ "$temp" =~ ^[0-9]+([.][0-9]+)?$ ]]; then
      printf '%s°C' "$temp"
      return
    fi
  fi
  shopt -s nullglob
  for hwmon in /sys/class/hwmon/hwmon*; do
    chip=""; [[ -r "$hwmon/name" ]] && IFS= read -r chip < "$hwmon/name"
    for input in "$hwmon"/temp*_input; do
      [[ -r "$input" ]] || continue
      IFS= read -r raw < "$input" || continue
      [[ "$raw" =~ ^-?[0-9]+$ ]] || continue
      ((raw >= -10000 && raw <= 200000)) || continue
      read_sensor_label "$input"; label="$REPLY"
      if [[ "${chip,,}" =~ ^(amdgpu|nouveau|i915|xe)$ || "${label,,}" =~ (gpu|video|edge|junction) ]]; then
        ((found==0 || raw>best)) && best="$raw"
        found=1
      fi
    done
  done
  shopt -u nullglob
  [[ -n "$best" ]] && millidegrees_to_celsius "$best" || printf 'não detectada'
}

detect_fans() {
  local hwmon chip input raw label key labelled_found=0 first=1
  local -a labelled_entries=() generic_entries=()
  local -A seen
  shopt -s nullglob
  for hwmon in /sys/class/hwmon/hwmon*; do
    chip="hwmon"; [[ -r "$hwmon/name" ]] && IFS= read -r chip < "$hwmon/name"
    for input in "$hwmon"/fan*_input; do
      [[ -r "$input" ]] || continue
      IFS= read -r raw < "$input" || continue
      [[ "$raw" =~ ^[0-9]+$ ]] || continue
      read_sensor_label "$input"; label="$REPLY"
      if [[ -n "$label" ]]; then
        key="${label,,}"; key="${key/video/gpu}"
        [[ -n "${seen[$key]:-}" ]] && continue
        seen[$key]=1; labelled_entries+=("$label: $raw RPM"); labelled_found=1
      else
        generic_entries+=("$chip ${input##*/}: $raw RPM")
      fi
    done
  done
  shopt -u nullglob
  if ((labelled_found)); then
    for label in "${labelled_entries[@]}"; do
      ((first==0)) && printf '\n'
      printf '%s' "$label"; first=0
    done
  elif ((${#generic_entries[@]}>0)); then
    for label in "${generic_entries[@]}"; do
      ((first==0)) && printf '\n'
      printf '%s' "$label"; first=0
    done
  else
    printf 'não detectadas'
  fi
}

ping_average() {
  local output average
  if ! command -v ping >/dev/null 2>&1; then
    printf 'ping indisponível'
    return
  fi
  if command -v timeout >/dev/null 2>&1; then
    output=$(LC_ALL=C timeout 5s ping -n -c 3 -W 1 "$PING_TARGET" 2>/dev/null || true)
  else
    output=$(LC_ALL=C ping -n -c 3 -W 1 "$PING_TARGET" 2>/dev/null || true)
  fi
  average=$(awk -F' = ' '/^(rtt|round-trip)/ {split($2,v,"/"); print v[2]; exit}' <<< "$output")
  [[ "$average" =~ ^[0-9]+([.][0-9]+)?$ ]] && printf '%s ms' "$average" || printf 'sem resposta'
}

print_storage_summary() {
  local rows source type size used available use_pct mount pct
  if ! command -v df >/dev/null 2>&1; then
    printf 'df indisponível.\n'
    return
  fi
  rows=$(LC_ALL=C df -hPT 2>/dev/null | awk '
    NR==1 {next}
    $1 ~ /^\/dev\/loop[0-9]*$/ {next}
    $1 ~ /^(none|udev)$/ {next}
    $2 ~ /^(tmpfs|devtmpfs|squashfs|overlay|aufs|ramfs|proc|sysfs|cgroup|cgroup2|pstore|securityfs|debugfs|tracefs|configfs|fusectl|fuse\.portal|mqueue|hugetlbfs|devpts|binfmt_misc|autofs|rpc_pipefs|nsfs|efivarfs)$/ {next}
    {print}' || true)
  if [[ -z "$rows" ]]; then
    printf 'Nenhum disco físico ou remoto relevante detectado.\n'
    return
  fi
  while read -r source type size used available use_pct mount; do
    [[ -n "${source:-}" ]] || continue
    pct="${use_pct%\%}"
    [[ "$pct" =~ ^[0-9]+$ ]] || continue
    printf '%-12s %3s ' "$(clip "$mount" 12)" "$use_pct"
    storage_bar "$use_pct"
    printf '  %s/%s  %s (%s)\n' "$used" "$size" "$source" "$type"
  done <<< "$rows"
}

collect_network() {
  local public_ip="" iface private_ip gateway
  local -a requested_interfaces
  if command -v curl >/dev/null 2>&1; then
    public_ip=$(curl -4 -fsS --max-time 3 https://api.ipify.org 2>/dev/null || true)
  elif command -v wget >/dev/null 2>&1; then
    public_ip=$(wget -4 -qO- --timeout=3 https://api.ipify.org 2>/dev/null || true)
  fi
  [[ "$public_ip" =~ ^[0-9a-fA-F:.]+$ ]] || public_ip="indisponível/offline"
  {
    printf '\n%s── REDE ──%s\n' "$BLUE" "$RESET"
    printf 'PUBLIC IP  %s\n' "$public_ip"
    IFS=',' read -ra requested_interfaces <<< "$NETWORK_INTERFACES"
    for iface in "${requested_interfaces[@]}"; do
      iface="${iface#${iface%%[![:space:]]*}}"; iface="${iface%${iface##*[![:space:]]}}"
      [[ -z "$iface" ]] && continue
      if ! command -v ip >/dev/null 2>&1; then
        printf '%-10s iproute2 indisponível\n' "$iface"; continue
      fi
      if ! ip link show dev "$iface" >/dev/null 2>&1; then
        printf '%-10s interface inexistente\n' "$iface"; continue
      fi
      private_ip=$(ip -4 -o addr show dev "$iface" scope global 2>/dev/null | awk 'NR==1 {print $4}')
      gateway=$(ip -4 route show default dev "$iface" 2>/dev/null | awk 'NR==1 {for(i=1;i<=NF;i++) if($i=="via") {print $(i+1); exit}}')
      printf '%-10s IP %-18s GW %s\n' "$iface" "${private_ip:-sem IPv4}" "${gateway:-sem gateway}"
    done
  } > "$TMP_DIR/network"
}

collect_resources() {
  local load mem_total mem_avail mem_used mem_pct swap_total swap_free swap_pct uptime_s top_snapshot
  local cpu_temperature gpu_temperature fans ping_latency
  load=$(awk '{print $1" "$2" "$3}' /proc/loadavg)
  read -r mem_total mem_avail swap_total swap_free < <(awk '
    /MemTotal/ {mt=$2} /MemAvailable/ {ma=$2} /SwapTotal/ {st=$2} /SwapFree/ {sf=$2}
    END {print mt,ma,st,sf}' /proc/meminfo)
  mem_used=$((mem_total-mem_avail)); mem_pct=$((mem_used*100/(mem_total?mem_total:1)))
  swap_pct=$(((swap_total-swap_free)*100/(swap_total?swap_total:1)))
  uptime_s=${SECONDS}; [[ -r /proc/uptime ]] && read -r uptime_s _ < /proc/uptime
  uptime_s=${uptime_s%.*}
  top_snapshot=$(ps -eo pid=,user=,pcpu=,pmem=,comm= 2>/dev/null)
  cpu_temperature=$(detect_cpu_temperature)
  gpu_temperature=$(detect_gpu_temperature)
  fans=$(detect_fans)
  ping_latency=$(ping_average)
  {
    printf 'LOAD  %s    CPU cores: %s\n' "$load" "$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo '?')"
    printf 'RAM   %3d%% ' "$mem_pct"; bar "$mem_pct" 18; printf '  %d / %d MiB\n' "$((mem_used/1024))" "$((mem_total/1024))"
    printf 'SWAP  %3d%% ' "$swap_pct"; bar "$swap_pct" 18; printf '  uptime %dd %02dh %02dm\n' "$((uptime_s/86400))" "$((uptime_s%86400/3600))" "$((uptime_s%3600/60))"
    [[ -r "$TMP_DIR/network" ]] && sed -n '1,$p' "$TMP_DIR/network"
    printf 'PING AVG   '; ping_badge "$ping_latency"; printf '  alvo=%s\n' "$PING_TARGET"
    printf '\n%s── TOP 3 CPU + RAM ──%s\n' "$MAGENTA" "$RESET"
    awk '
      {score=$3+$4; printf "%s\t%-6s %-9s CPU %5s%% RAM %5s%% %s\n",score,$1,$2,$3,$4,$5}' |
      sort -rn | head -n 3 | cut -f2-
    printf '\n%s── USUÁRIOS ATIVOS / STATUS ──%s\n' "$CYAN" "$RESET"
    if [[ -s "$TMP_DIR/users" ]]; then
      tail -n +2 "$TMP_DIR/users"
    else
      printf 'Nenhum usuário apto a login encontrado.\n'
    fi
    printf '\n%s── HARDWARE ──%s\n' "$YELLOW" "$RESET"
    printf 'CPU TEMP   '; temperature_badge "$cpu_temperature"; printf '\n'
    printf 'GPU TEMP   '; temperature_badge "$gpu_temperature"; printf '\n'
    if [[ "$fans" == 'não detectadas' ]]; then
      printf 'FAN RPM    %s○%s %s\n' "$GRAY" "$RESET" "$fans"
    else
      while IFS= read -r fan; do
        [[ -n "$fan" ]] && printf 'FAN RPM    %s◆%s %s\n' "$CYAN" "$RESET" "$fan"
      done <<< "$fans"
    fi
    printf '\n%s── ARMAZENAMENTO / DF -H ──%s\n' "$BLUE" "$RESET"
    print_storage_summary
  } <<< "$top_snapshot" > "$TMP_DIR/resources"
}

collect_connections() {
  local raw="$TMP_DIR/connections.raw" enriched="$TMP_DIR/connections.enriched"
  : > "$raw"
  if command -v ss >/dev/null 2>&1; then
    # -H suppresses headings, -p adds PID/program where permissions allow.
    # Established TCP/UDP flows and TCP listeners are normalized together.
    printf "%-22s %-22s %-12s %s\n" "LOCAL IP:PORT" "REMOTE IP:PORT" "STATE" "PID/PROGRAM → EXE" > "$raw"
    ss -H -tunap state established 2>/dev/null | awk '
      {
        local=$4; remote=$5; proc="? (sem permissão ou kernel)"
        for(i=6;i<=NF;i++) if($i ~ /users:/) {proc=$i; for(j=i+1;j<=NF;j++) proc=proc" "$j; break}
        printf "%-22s %-22s %-12s %s\n",local,remote,"ESTABLISHED",proc
      }' >> "$raw"
    ss -H -lntp 2>/dev/null | awk '
      {
        local=$4; remote=$5; proc="? (sem permissão ou kernel)"
        for(i=6;i<=NF;i++) if($i ~ /users:/) {proc=$i; for(j=i+1;j<=NF;j++) proc=proc" "$j; break}
        printf "%-22s %-22s %-12s %s\n",local,remote,"LISTEN",proc
      }' >> "$raw"
  elif command -v netstat >/dev/null 2>&1; then
    netstat -tulnap 2>/dev/null | awk '
      BEGIN {printf "%-22s %-22s %-12s %s\n","LOCAL IP:PORT","REMOTE IP:PORT","STATE","PID/PROGRAM → EXE"}
      $6=="ESTABLISHED" || $6=="LISTEN" {printf "%-22s %-22s %-12s %s\n",$4,$5,$6,$7}' > "$raw"
  else
    printf 'Instale iproute2 (ss) ou net-tools (netstat).\n' > "$raw"
  fi
  awk '
    NR==1 {print; next}
    {
      line=$0
      if (match(line,/pid=[0-9]+/)) {pid=substr(line,RSTART+4,RLENGTH-4); exe=""
        cmd="readlink -f /proc/" pid "/exe 2>/dev/null"; cmd | getline exe; close(cmd)
        if(exe!="") line=line " → " exe
      } else if (match(line,/[0-9]+\//)) {pid=substr(line,RSTART,RLENGTH-1); exe=""
        cmd="readlink -f /proc/" pid "/exe 2>/dev/null"; cmd | getline exe; close(cmd)
        if(exe!="") line=line " → " exe
      }
      print line
    }' "$raw" > "$enriched"

  # Filter case-insensitively, number visible rows, and color the attached
  # program name. Literal substring matching avoids regex surprises in filters.
  awk -v filters="$CONNECTION_FILTER" '
    BEGIN {nfilters=split(tolower(filters),deny,","); shown=0}
    NR==1 {printf "%-4s %s\n","#",$0; next}
    {
      low=tolower($0); blocked=0
      for(i=1;i<=nfilters;i++) {gsub(/^[[:space:]]+|[[:space:]]+$/,"",deny[i]); if(deny[i]!="" && index(low,deny[i])) blocked=1}
      if(blocked) next
      line=$0
      printf "%-4d %s\n",++shown,line
    }' "$enriched" > "$TMP_DIR/connections"
}

collect_users() {
  local logged="$TMP_DIR/logged" uid_min user tty login_date login_time idle pid rest epoch now duration count
  local -A login_epoch login_tty login_count
  uid_min=$(awk '$1=="UID_MIN" {print $2; exit}' /etc/login.defs 2>/dev/null)
  uid_min=${uid_min:-1000}
  : > "$logged"; now=$(date +%s)
  while read -r user tty login_date login_time idle pid rest; do
    [[ -z "${user:-}" ]] && continue
    printf '%s\n' "$user" >> "$logged"
    epoch=$(date -d "$login_date $login_time" +%s 2>/dev/null || echo "$now")
    if [[ -z "${login_epoch[$user]:-}" || "$epoch" -lt "${login_epoch[$user]}" ]]; then
      login_epoch[$user]=$epoch; login_tty[$user]=$tty
    fi
    login_count[$user]=$(( ${login_count[$user]:-0} + 1 ))
  done < <(who -u 2>/dev/null)
  sort -u -o "$logged" "$logged"
  {
    printf '%-20s %s\n' USER STATUS
    while IFS=: read -r user _ uid _ _ home shell; do
      # Human/root accounts configured with a shell accepted by the system.
      ((uid != 0 && uid < uid_min)) && continue
      [[ -z "$shell" || "$shell" =~ /(nologin|false)$ ]] && continue
      [[ -r /etc/shells ]] && ! grep -qxF "$shell" /etc/shells && continue
      if grep -qxF "$user" "$logged"; then
        epoch=${login_epoch[$user]:-$now}; duration=$(format_duration "$((now-epoch))")
        count=${login_count[$user]:-1}
        printf '%-20s %sLOGGED IN%s for %s since %s %s tty=%s' "$user" "$GREEN" "$RESET" \
          "$duration" "$(date -d "@$epoch" '+%F %H:%M' 2>/dev/null || echo '?')" \
          "$([[ "$count" -gt 1 ]] && printf 'sessions=%s' "$count")" "${login_tty[$user]:-?}"
        printf '\n'
      else
        printf '%-20s %slogged out%s\n' "$user" "$GRAY" "$RESET"
      fi
    done < /etc/passwd
  } > "$TMP_DIR/users"
}

collect_tree_and_privileged() {
  {
    printf '%s\n' 'PROCESS TREE (recorte)'
    if ps --forest -eo user=,pid=,ppid=,comm= >/dev/null 2>&1; then
      ps --forest -eo user=,pid=,ppid=,comm= 2>/dev/null | head -n 10
    else
      ps -eo user=,pid=,ppid=,comm= 2>/dev/null | head -n 10
    fi
    printf '%s\n' '── root + nome/caminho atípico (heurística) ──'
    printf '%-7s %-20s %s\n' PID COMMAND REASON
    ps -U root -u root -o pid=,comm=,args= 2>/dev/null | awk '
      function odd(s) {return s ~ /^\.|[[:space:]]\.[^/]|[[:space:]]\/tmp\/|[[:space:]]\/dev\/shm\/|[[:space:]]\/var\/tmp\/|kworker.*\//}
      odd($0) {reason="nome oculto/caminho temporário"; printf "%-7s %-20s %s\n",$1,$2,reason}' | head -n 8
    printf '%s\n' 'Ausência de linhas não comprova que o sistema está seguro.'
  } > "$TMP_DIR/tree"
}

collect_persistence() {
  {
    printf '%s\n' 'SERVICES (running/failed)'
    if command -v systemctl >/dev/null 2>&1; then
      systemctl --no-pager --no-legend --plain --state=running,failed --type=service 2>/dev/null |
        awk '{printf "%-34s %-8s %s\n",$1,$3,$4}' | head -n 8
    else printf 'systemd indisponível\n'; fi
    printf '\n%s── SCHEDULED / AUTOSTART ──%s\n\n' "$YELLOW" "$RESET"
    if command -v systemctl >/dev/null 2>&1; then
      systemctl list-timers --all --no-pager --no-legend 2>/dev/null | awk '{print "timer: "$0}' | head -n 4
    fi
    [[ -r /etc/crontab ]] && awk '!/^($|#)/ {print "cron:  "$0}' /etc/crontab | head -n 4
    for d in /etc/xdg/autostart "$HOME/.config/autostart"; do
      [[ -d "$d" ]] && find "$d" -maxdepth 1 -type f -name '*.desktop' -printf 'auto:  %f\n' 2>/dev/null | head -n 4
    done
  } > "$TMP_DIR/persistence"
}

capture_tui_command() {
  local pane_cols="$1" pane_rows="$2" capture_status=0
  tmux -S "$TMUX_SOCKET" -f /dev/null new-session -d -s sentinel-command \
    -x "$pane_cols" -y "$pane_rows" >/dev/null 2>&1 || return 1
  tmux -S "$TMUX_SOCKET" set-option -t sentinel-command status off >/dev/null 2>&1 || true
  tmux -S "$TMUX_SOCKET" send-keys -t sentinel-command:0.0 C-l >/dev/null 2>&1 || true
  tmux -S "$TMUX_SOCKET" send-keys -t sentinel-command:0.0 -l -- "$CUSTOM_COMMAND" >/dev/null 2>&1 || true
  tmux -S "$TMUX_SOCKET" send-keys -t sentinel-command:0.0 Enter >/dev/null 2>&1 || true
  sleep 1
  tmux -S "$TMUX_SOCKET" capture-pane -p -t sentinel-command:0.0 -S 0 2>/dev/null || capture_status=$?
  tmux -S "$TMUX_SOCKET" kill-server >/dev/null 2>&1 || true
  return "$capture_status"
}

run_command_snapshot() {
  local status
  if command -v timeout >/dev/null 2>&1; then
    timeout 5s bash -lc "$CUSTOM_COMMAND" 2>&1 | head -n 200
    status=${PIPESTATUS[0]}
  else
    printf 'O utilitário timeout é necessário para executar comandos personalizados com segurança.\n'
    return
  fi
  ((status==0 || status==141)) && return
  if ((status==124)); then
    printf '\n[comando interrompido após 5 segundos]\n'
  else
    printf '\n[comando encerrado com status %d]\n' "$status"
  fi
}

collect_custom_command() {
  local cols lines pane_cols pane_rows command_name raw="$TMP_DIR/command.raw"
  cols=$(tput cols 2>/dev/null || echo 120); lines=$(tput lines 2>/dev/null || echo 40)
  if ((cols>=90)); then pane_cols=$((cols-cols/3-6)); else pane_cols=$((cols-3)); fi
  pane_rows=$(((lines-8)/2)); ((pane_cols<20)) && pane_cols=20; ((pane_rows<8)) && pane_rows=8
  command_name="${CUSTOM_COMMAND#"${CUSTOM_COMMAND%%[![:space:]]*}"}"
  command_name="${command_name%%[[:space:]]*}"
  {
    printf '$ %s\n' "$CUSTOM_COMMAND"
    if [[ "${command_name##*/}" == htop ]]; then
      if ! command -v "$command_name" >/dev/null 2>&1; then
        printf 'htop não está instalado.\n'
      elif command -v tmux >/dev/null 2>&1 && capture_tui_command "$pane_cols" "$pane_rows"; then
        :
      else
        printf 'Captura interativa indisponível; exibindo resumo compatível via top.\n'
        COLUMNS="$pane_cols" top -b -n 1 2>&1 | head -n 200
      fi
    else
      run_command_snapshot
    fi
  } > "$raw"
  LC_ALL=C sed $'s/\033\\[[0-9;?]*[ -\\/]*[@-~]//g; s/\033(B//g; s/\033[=>]//g' "$raw" |
    tr -d '\000\r' | head -n 200 > "$TMP_DIR/command"
  [[ -s "$TMP_DIR/command" ]] || printf 'Comando sem saída.\n' > "$TMP_DIR/command"
}

visible_len() { sed $'s/\033\\[[0-9;]*m//g' <<< "$1" | awk '{print length}'; }
panel() {
  local key="$1" title="$2" file="$3" width="$4" height="$5"
  local gap_at="${6:--1}" gap_count="${7:-0}"
  local line plain plain_len pad i=0 data_i v h total longest=0 available selected_color effective_height program_token
  local -a content=()
  mapfile -t content < "$file"
  total=${#content[@]}; v=${PANEL_V[$key]:-0}; h=${PANEL_H[$key]:-0}
  effective_height=$((height-gap_count)); ((effective_height<1)) && effective_height=1
  ((v>total-effective_height)) && v=$((total-effective_height)); ((v<0)) && v=0
  for line in "${content[@]}"; do
    plain=$(sed $'s/\033\\[[0-9;]*m//g' <<< "$line")
    ((${#plain}>longest)) && longest=${#plain}
  done
  available=$((width-3)); ((h>longest-available)) && h=$((longest-available)); ((h<0)) && h=0
  PANEL_V[$key]=$v; PANEL_H[$key]=$h
  selected_color="$GREEN"
  [[ "${PANEL_ORDER[$ACTIVE_PANEL]}" == "$key" ]] && title="▶ $title"
  ((total>effective_height || longest>available)) && title="$title  [v$((v+1))/$((total>0?total:1)) h$h]"
  ((${#title}>width-6)) && title="${title:0:width-7}…"
  printf '%s┌─ %s%s%s ' "$selected_color" "$BOLD" "$title" "$RESET$selected_color"
  local used=$((4+${#title})); repeat_char '─' "$((width-used-1))"; printf '┐%s\n' "$RESET"
  while ((i < height)); do
    if ((gap_count>0 && i>=gap_at && i<gap_at+gap_count)); then
      printf '%s│%s %*s%s│%s\n' "$selected_color" "$RESET" "$((width-3))" '' "$selected_color" "$RESET"
      ((i+=1)); continue
    fi
    data_i=$i; ((gap_count>0 && i>=gap_at+gap_count)) && data_i=$((i-gap_count))
    line="${content[v+data_i]:-}"
    # Literal tabs have terminal-dependent width and break the right border.
    line="${line//$'\t'/  }"
    plain=$(sed $'s/\033\\[[0-9;]*m//g' <<< "$line")
    if ((h==0 && ${#plain}<=available)); then
      plain_len=${#plain} # Keep semantic colors when no horizontal clipping is needed.
    else
      line="${plain:h:available}"; plain_len=${#line}
      ((${#plain}>h+available)) && line="${line:0:available-1}»" && plain_len=$available
    fi
    # Apply connection program color after horizontal clipping. Otherwise long
    # rows lose ANSI styling when converted to their visible substring.
    if [[ "$key" == connections ]]; then
      if [[ "$line" =~ \"[^\"]+\" ]]; then
        program_token=${BASH_REMATCH[0]}
        line="${line/"$program_token"/"$MAGENTA$program_token$RESET"}"
      elif [[ "$line" =~ [0-9]+/([[:alnum:]_.-]+) ]]; then
        program_token=${BASH_REMATCH[1]}
        line="${line/"$program_token"/"$MAGENTA$program_token$RESET"}"
      fi
    fi
    pad=$((width-3-plain_len)); ((pad<0)) && pad=0
    printf '%s│%s %s%*s%s│%s\n' "$selected_color" "$RESET" "$line" "$pad" '' "$selected_color" "$RESET"
    ((i+=1))
  done
  printf '%s└' "$selected_color"; repeat_char '─' "$((width-2))"; printf '┘%s' "$RESET"
}

render() {
  local cols lines width rows capacity resource_rows persistence_rows row_shift
  cols=$(tput cols 2>/dev/null || echo 120); lines=$(tput lines 2>/dev/null || echo 40)
  # Account for header, borders and gaps so the complete dashboard fits vertically.
  # Wide mode uses two stacked sections in each column; narrow mode stacks four panels.
  if ((cols >= 90)); then
    capacity=$(((lines-8)/2))
  else
    capacity=$(((lines-11)/4))
  fi
  ((capacity<1)) && capacity=1
  rows=$capacity
  ((MAX_ROWS>0 && MAX_ROWS<rows)) && rows=$MAX_ROWS
  ((rows<1)) && rows=1
  # Give the machine overview four rows taken from services/persistence while
  # preserving at least one content row in very small terminals.
  row_shift=4; ((row_shift>=rows)) && row_shift=$((rows-1))
  resource_rows=$((rows+row_shift)); persistence_rows=$((rows-row_shift))
  printf '\e[H\e[2J'
  printf '%s%s  ◈ SENTINEL // LIVE SYSTEM TELEMETRY%s  %s%s%s  refresh %ss  [Ctrl+C: sair]%s\n' \
    "$BOLD" "$LIME" "$RESET" "$CYAN" "$(date '+%F %T')" "$RESET" "$REFRESH_SECONDS" "$RESET"
  printf '%s' "$DARK"; repeat_char '═' "$cols"; printf '%s\n' "$RESET"
  if ((cols >= 90)); then
    local width1 width2 column_gap=3
    width1=$((cols/3)); width2=$((cols-width1-column_gap))
    # Left column uses one continuous frame with a named internal divider. This
    # avoids clusters of disconnected vertical borders between stacked panels.
    panel resources 'VISÃO GERAL DA MÁQUINA' "$TMP_DIR/resources" "$width1" "$resource_rows" > "$TMP_DIR/first.panel"
    panel persistence 'SERVIÇOS / PERSISTÊNCIA' "$TMP_DIR/persistence" "$width1" "$persistence_rows" > "$TMP_DIR/second.panel"
    {
      sed '$d' "$TMP_DIR/first.panel"
      sed -n '1{s/┌/├/;s/┐/┤/;p;}' "$TMP_DIR/second.panel"
      printf '%s│%s%*s%s│%s\n' "$GREEN" "$RESET" "$((width1-2))" '' "$GREEN" "$RESET"
      sed '1d' "$TMP_DIR/second.panel"
    } > "$TMP_DIR/left.column"
    panel connections 'CONEXÕES / PORTAS LISTEN' "$TMP_DIR/connections" "$width2" "$rows" > "$TMP_DIR/third.panel"
    panel command 'COMANDO PERSONALIZADO' "$TMP_DIR/command" "$width2" "$rows" > "$TMP_DIR/fourth.panel"
    {
      sed '$d' "$TMP_DIR/third.panel"
      sed -n '1{s/┌/├/;s/┐/┤/;p;}' "$TMP_DIR/fourth.panel"
      printf '%s│%s%*s%s│%s\n' "$GREEN" "$RESET" "$((width2-2))" '' "$GREEN" "$RESET"
      sed '1d' "$TMP_DIR/fourth.panel"
    } > "$TMP_DIR/right.column"
    # Three terminal columns between frames keep their vertical borders distinct.
    sed -i 's/$/  /' "$TMP_DIR/left.column"
    paste -d' ' "$TMP_DIR/left.column" "$TMP_DIR/right.column"
    printf '\n'
  else
    width=$cols
    panel resources 'VISÃO GERAL DA MÁQUINA' "$TMP_DIR/resources" "$width" "$resource_rows"; printf '\n'
    panel persistence 'SERVIÇOS / PERSISTÊNCIA' "$TMP_DIR/persistence" "$width" "$persistence_rows"; printf '\n'
    panel connections 'CONEXÕES / PORTAS LISTEN' "$TMP_DIR/connections" "$width" "$rows"; printf '\n'
    panel command 'COMANDO PERSONALIZADO' "$TMP_DIR/command" "$width" "$rows"; printf '\n'
  fi
  printf '%sTAB%s painel  %s↑↓%s vertical  %s←→%s horizontal  %sq%s sair  %sSelecionado: %s%s' \
    "$YELLOW" "$RESET" "$CYAN" "$RESET" "$CYAN" "$RESET" "$RED" "$RESET" \
    "$YELLOW" "${PANEL_ORDER[$ACTIVE_PANEL]}" "$RESET"
  printf '\e[J'
}

collect_static() { collect_users; collect_persistence; collect_network; }
collect_all() { collect_resources; collect_connections; collect_custom_command; }

STARTED=1
if [[ -t 1 ]]; then printf '\e[?1049h\e[?7l\e[?25l\e[2J'; fi
collect_static
static_tick=0
while ((STOPPED == 0)); do
  collect_all
  # User/service/timer discovery is comparatively expensive; refresh every ~60 s.
  static_tick=$((static_tick+1))
  if awk -v a="$static_tick" -v b="$REFRESH_SECONDS" 'BEGIN {exit !(a*b>=60)}'; then
    collect_static; static_tick=0
  fi
  render
  if [[ ! -t 0 ]]; then
    sleep "$REFRESH_SECONDS" & wait $! || true
    continue
  fi
  # Keep the interface responsive between collection cycles without polling.
  while IFS= read -rsn1 -t "$REFRESH_SECONDS" key; do
    current=${PANEL_ORDER[$ACTIVE_PANEL]}
    case "$key" in
      $'\t') ACTIVE_PANEL=$(((ACTIVE_PANEL+1)%${#PANEL_ORDER[@]})) ;;
      q|Q) STOPPED=1; break ;;
      $'\e')
        seq=""; IFS= read -rsn2 -t 0.1 seq || true
        case "$seq" in
          '[A') PANEL_V[$current]=$(( ${PANEL_V[$current]:-0} - 1 )) ;;
          '[B') PANEL_V[$current]=$(( ${PANEL_V[$current]:-0} + 1 )) ;;
          '[C') PANEL_H[$current]=$(( ${PANEL_H[$current]:-0} + 4 )) ;;
          '[D') PANEL_H[$current]=$(( ${PANEL_H[$current]:-0} - 4 )) ;;
        esac
        ;;
    esac
    ((STOPPED == 0)) && render
  done
done
