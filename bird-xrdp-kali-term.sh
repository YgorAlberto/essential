#!/usr/bin/env bash
# Instala, corrige e valida acesso gráfico por RDP em Debian e derivados.
set -Eeuo pipefail
IFS=$'\n\t'

readonly SCRIPT_NAME="${0##*/}"
readonly RDP_PORT=3389
readonly XSESSION_HOOK=/etc/X11/Xsession.d/45xrdp-native-session
readonly LOG_FILE=/var/log/bridge-xrdp-install.log
readonly REPAIR_ATTEMPTS=3
MODE=rdp
log()  { printf '[INFO] %s\n' "$*"; }
warn() { printf '[AVISO] %s\n' "$*" >&2; }
die()  { printf '[ERRO] %s: %s\n' "$SCRIPT_NAME" "$*" >&2; exit 1; }

usage() {
    cat <<USAGE
Uso: sudo bash $SCRIPT_NAME [opção]

Sem opção: instala e valida o acesso gráfico por RDP na porta TCP 3389.
  --terminal-only  Instala somente terminal, shell e utilitários CLI; não instala nem inicia RDP.
  --help           Exibe esta ajuda.
USAGE
}

case "${1:-}" in
    "") ;;
    --terminal-only) MODE=terminal ;;
    --help|-h) usage; exit 0 ;;
    *) usage >&2; die "Opção desconhecida: $1" ;;
esac
[[ $# -le 1 ]] || die "Informe apenas uma opção."

on_error() { printf '[ERRO] linha %s: comando falhou: %s\n' "$1" "$2" >&2; exit 1; }
trap 'on_error "$LINENO" "$BASH_COMMAND"' ERR

[[ ${EUID:-$(id -u)} -eq 0 ]] || die "Execute como root: sudo bash $SCRIPT_NAME"
command -v apt-get >/dev/null || die "Requer apt/apt-get (Debian, Ubuntu, Kali ou derivado)."
[[ -r /etc/os-release ]] || die "Não foi possível identificar o sistema (/etc/os-release ausente)."
# shellcheck disable=SC1091
source /etc/os-release
case "${ID:-}" in
    debian|ubuntu|kali|linuxmint|pop|zorin|elementary|parrot|raspbian|mx|deepin|devuan) ;;
    *)
        if [[ " ${ID_LIKE:-} " != *" debian "* && " ${ID_LIKE:-} " != *" ubuntu "* ]]; then
            die "Distribuição '${PRETTY_NAME:-desconhecida}' não é Debian/Ubuntu ou derivada."
        fi
        ;;
esac

mkdir -p "$(dirname "$LOG_FILE")"
exec > >(tee -a "$LOG_FILE") 2>&1

apt_update() {
    local n
    for n in 1 2 3; do
        apt-get update && return 0
        warn "apt-get update falhou (tentativa $n/3)."
        sleep $((n * 2))
    done
    return 1
}

install_with_retries() {
    local attempt
    for attempt in 1 2 3; do
        if DEBIAN_FRONTEND=noninteractive apt-get install -y "$@"; then
            return 0
        fi
        warn "Instalação falhou (tentativa $attempt/3); corrigindo dependências e atualizando índices."
        apt-get -f install -y || true
        apt_update || true
    done
    return 1
}

enforce_default_rdp_port() {
    local ini=/etc/xrdp/xrdp.ini tmp backup
    [[ -r $ini ]] || die "Configuração do xrdp não encontrada: $ini"
    tmp=$(mktemp)
    awk -v port="$RDP_PORT" '
        BEGIN { in_globals=0; found=0 }
        /^[[:space:]]*\[/ {
            if (in_globals && !found) { print "port=" port; found=1 }
            in_globals=(tolower($0) ~ /^[[:space:]]*\[globals\][[:space:]]*$/)
            print
            next
        }
        in_globals && /^[[:space:]]*port[[:space:]]*=/ {
            if (!found) { print "port=" port; found=1 }
            else print "; bird-xrdp disabled extra listener: " $0
            next
        }
        { print }
        END { if (in_globals && !found) print "port=" port }
    ' "$ini" > "$tmp"
    if ! cmp -s "$ini" "$tmp"; then
        backup="${ini}.bird-xrdp-backup.$(date +%Y%m%d-%H%M%S)"
        cp -a "$ini" "$backup" || { rm -f "$tmp"; die "Não foi possível salvar backup de $ini"; }
        cat "$tmp" > "$ini"
        chown --reference="$backup" "$ini"
        chmod --reference="$backup" "$ini"
        log "Porta do xrdp ajustada para TCP $RDP_PORT (backup: $backup)."
    fi
    rm -f "$tmp"
}

if [[ $MODE == terminal ]]; then
    log "Modo terminal-only: instalando em nível de sistema, disponível para todas as contas locais."
    apt_update || die "Falha ao atualizar APT após três tentativas."
    install_with_retries xfce4-terminal bash zsh tmux nano less procps iproute2 \
        || die "Não foi possível instalar o terminal/utilitários. Consulte $LOG_FILE."
    command -v xfce4-terminal >/dev/null || die "O executável xfce4-terminal não foi encontrado após a instalação."
    command -v bash >/dev/null && command -v zsh >/dev/null && command -v tmux >/dev/null \
        || die "A validação dos shells/utilitários instalados falhou."
    log "OK: xfce4-terminal, Bash, Zsh, tmux e utilitários de terminal instalados para todos os usuários."
    printf 'O modo terminal-only não instala nem inicia serviços RDP.\n'
    printf 'Terminal gráfico: xfce4-terminal (requer uma sessão gráfica já instalada).\n'
    printf 'Terminais de texto: Bash e Zsh; ferramentas adicionais: tmux, nano, less, procps e iproute2.\n'
    exit 0
fi

has_desktop_session() {
    local f
    for f in /usr/share/xsessions/*.desktop; do [[ -f "$f" ]] && return 0; done
    return 1
}
has_session_manager() {
    command -v x-session-manager >/dev/null 2>&1 || command -v gnome-session >/dev/null 2>&1 || \
    command -v startplasma-x11 >/dev/null 2>&1 || command -v xfce4-session >/dev/null 2>&1 || \
    command -v mate-session >/dev/null 2>&1 || command -v cinnamon-session >/dev/null 2>&1 || \
    command -v lxqt-session >/dev/null 2>&1
}
log "Sistema detectado: ${PRETTY_NAME:-$ID}."
log "Atualizando índices de pacotes."
apt_update || die "Falha ao atualizar APT após três tentativas. Verifique rede e repositórios."

packages=(xrdp xorgxrdp dbus-x11 x11-xserver-utils)
packages+=(xfce4-terminal)
if ! has_desktop_session || ! has_session_manager; then
    log "Ambiente gráfico ausente/incompleto; instalando XFCE como sessão gráfica de contingência."
    if [[ ${ID:-} == kali ]]; then
        packages+=(kali-desktop-xfce)
    else
        packages+=(xfce4 xfce4-session)
    fi
    packages+=(xfce4-terminal)
fi

install_with_retries "${packages[@]}" || die "Falha ao instalar dependências. Consulte $LOG_FILE."
enforce_default_rdp_port

[[ -d /etc/X11/Xsession.d ]] || die "Xsession não encontrado; confira o pacote x11-common."

tmp=$(mktemp)
cat >"$tmp" <<'HOOK'
# Sessão gráfica padrão para RDP. Respeita a escolha personalizada do usuário.
if [ -n "${XRDP_SESSION:-}" ] && [ -z "${STARTUP:-}" ] && [ ! -r "$HOME/.xsession" ]; then
    if command -v x-session-manager >/dev/null 2>&1; then
        STARTUP=x-session-manager
    elif command -v xfce4-session >/dev/null 2>&1; then
        STARTUP=xfce4-session
    elif command -v gnome-session >/dev/null 2>&1; then
        STARTUP=gnome-session
    elif command -v startplasma-x11 >/dev/null 2>&1; then
        STARTUP=startplasma-x11
    elif command -v mate-session >/dev/null 2>&1; then
        STARTUP=mate-session
    fi
    export STARTUP
fi
HOOK
install -o root -g root -m 0644 "$tmp" "$XSESSION_HOOK"
rm -f "$tmp"

configure_startwm() {
    local file=/etc/xrdp/startwm.sh tmp backup
    [[ -f $file ]] || { warn "$file não encontrado; mantendo a configuração do pacote."; return 0; }
    # Algumas imagens Kali substituem o fluxo Debian/Xsession por startxfce4
    # direto. Isso ignora ~/.xsession e o hook global acima. Use Xsession para
    # que as sessões pessoais e o padrão do sistema sejam realmente aplicados.
    if ! grep -Eq '^[[:space:]]*(exec[[:space:]]+)?startxfce4[[:space:]]*$' "$file"; then
        return 0
    fi
    tmp=$(mktemp)
    awk '
        /^[[:space:]]*(exec[[:space:]]+)?startxfce4[[:space:]]*$/ {
            print "if [ -r /etc/X11/Xsession ]; then"
            print "    exec /etc/X11/Xsession"
            print "fi"
            print "exec startxfce4"
            next
        }
        { print }
    ' "$file" > "$tmp"
    if cmp -s "$file" "$tmp"; then
        rm -f "$tmp"
        return 0
    fi
    backup="${file}.bird-xrdp-backup.$(date +%Y%m%d-%H%M%S)"
    cp -a "$file" "$backup" || { rm -f "$tmp"; die "Não foi possível salvar backup de $file"; }
    cat "$tmp" > "$file"
    chown --reference="$backup" "$file"
    chmod --reference="$backup" "$file"
    rm -f "$tmp"
    log "Ajustado $file para iniciar a sessão via Xsession (backup: $backup)."
}
configure_startwm

if getent group ssl-cert >/dev/null 2>&1 && id xrdp >/dev/null 2>&1; then
    usermod -aG ssl-cert xrdp || warn "Não foi possível adicionar xrdp ao grupo ssl-cert."
fi

if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q '^Status: active'; then
    ufw allow "${RDP_PORT}/tcp" || warn "Não foi possível liberar ${RDP_PORT}/tcp no UFW ativo."
fi
if command -v firewall-cmd >/dev/null 2>&1 && firewall-cmd --state >/dev/null 2>&1; then
    warn "firewalld está ativo; libere ${RDP_PORT}/tcp na zona apropriada."
fi

start_services() {
    systemctl enable xrdp xrdp-sesman && systemctl restart xrdp-sesman xrdp && \
        systemctl is-active --quiet xrdp && systemctl is-active --quiet xrdp-sesman
}
verify() {
    dpkg-query -W -f='${Status}\n' xrdp 2>/dev/null | grep -qx 'install ok installed' || return 1
    dpkg-query -W -f='${Status}\n' xorgxrdp 2>/dev/null | grep -qx 'install ok installed' || return 1
    [[ -x /usr/sbin/xrdp && -r /etc/xrdp/xrdp.ini && -r "$XSESSION_HOOK" ]] || return 1
    awk -v port="$RDP_PORT" '
        /^[[:space:]]*\[/ { in_globals=(tolower($0) ~ /^[[:space:]]*\[globals\][[:space:]]*$/); next }
        in_globals && /^[[:space:]]*port[[:space:]]*=/ {
            value=$0; sub(/^[^=]*=[[:space:]]*/, "", value); sub(/[[:space:]].*$/, "", value)
            if (value == port) found=1
        }
        END { exit !found }
    ' /etc/xrdp/xrdp.ini || return 1
    systemctl is-active --quiet xrdp && systemctl is-active --quiet xrdp-sesman || return 1
    if command -v ss >/dev/null 2>&1; then
        ss -lntH '( sport = :3389 )' 2>/dev/null | grep -q . || return 1
    elif command -v netstat >/dev/null 2>&1; then
        netstat -lnt 2>/dev/null | awk '$4 ~ /:3389$/ {found=1} END {exit !found}' || return 1
    else
        return 1
    fi
}

log "Habilitando e iniciando os serviços RDP."
for attempt in 1 2 3; do
    if start_services; then break; fi
    warn "Serviços não iniciaram (tentativa $attempt/3); tentando reparar."
    apt-get -f install -y || true
    systemctl daemon-reload || true
    sleep 2
done
systemctl is-active --quiet xrdp && systemctl is-active --quiet xrdp-sesman || {
    systemctl --no-pager --full status xrdp xrdp-sesman || true
    journalctl -u xrdp -u xrdp-sesman -n 80 --no-pager || true
    die "Serviços RDP continuam inativos. Consulte $LOG_FILE."
}

for attempt in 1 2 3; do
    if verify; then break; fi
    warn "Validação falhou (tentativa $attempt/3); reaplicando permissões e reiniciando."
    enforce_default_rdp_port
    getent group ssl-cert >/dev/null 2>&1 && id xrdp >/dev/null 2>&1 && usermod -aG ssl-cert xrdp || true
    start_services || true
    sleep 2
done
verify || {
    systemctl --no-pager --full status xrdp xrdp-sesman || true
    journalctl -u xrdp -u xrdp-sesman -n 80 --no-pager || true
    die "Validação final falhou após três tentativas. Consulte $LOG_FILE."
}

log "OK: xrdp e sesman ativos; pacotes Xorg instalados; porta TCP ${RDP_PORT} escutando."
printf '\nConecte-se ao IP deste computador na porta %s.\n' "$RDP_PORT"
printf 'Use uma conta local com senha (não root). As contas existentes e futuras usam a sessão nativa padrão; ~/.xsession personalizado é respeitado.\n'
printf 'A validação local confirma os serviços e a porta. O login visual precisa ser confirmado pelo cliente RDP.\n'
printf 'Log: %s\n' "$LOG_FILE"
