#!/bin/bash

#===============================================================================
# Instalador de Dependências
# Execute: chmod +x execute-me-primeiro-com-ponto-barra.sh && ./execute-me-primeiro-com-ponto-barra.sh
#===============================================================================

set -e

# Cores
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

# O Ollama é opcional porque o modelo local pode exigir bastante memória e disco.
# A escolha também pode ser automatizada com --with-ollama/--without-ollama.
INSTALL_OLLAMA="${INSTALL_OLLAMA:-}"

show_help() {
    cat <<'EOF'
Uso: ./execute-me-primeiro-com-ponto-barra.sh [opção]

Opções:
  --with-ollama       instala/configura o Ollama e baixa o modelo local
  --without-ollama    não instala o Ollama (padrão em modo não interativo)
  -h, --help          mostra esta ajuda
EOF
}

while [ "$#" -gt 0 ]; do
    case "$1" in
        --with-ollama)
            INSTALL_OLLAMA=1
            ;;
        --without-ollama)
            INSTALL_OLLAMA=0
            ;;
        -h|--help)
            show_help
            exit 0
            ;;
        *)
            echo -e "${RED}[ERRO]${NC} Opção desconhecida: $1" >&2
            show_help >&2
            exit 2
            ;;
    esac
    shift
done

echo -e "${CYAN}"
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║                    INSTALADOR                                ║"
echo "║              Instalando dependências...                      ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo -e "${NC}"

if [ -z "$INSTALL_OLLAMA" ]; then
    if [ -t 0 ]; then
        echo -e "${YELLOW}[OPCIONAL]${NC} O Ollama executa IA local e pode consumir bastante RAM, disco e CPU."
        if ! read -r -p "Deseja instalar o Ollama e o modelo local? [s/N]: " OLLAMA_ANSWER; then
            OLLAMA_ANSWER=""
        fi
        case "$OLLAMA_ANSWER" in
            s|S|sim|SIM|Sim|y|Y|yes|YES|Yes) INSTALL_OLLAMA=1 ;;
            *) INSTALL_OLLAMA=0 ;;
        esac
    else
        INSTALL_OLLAMA=0
        echo -e "${YELLOW}[OPCIONAL]${NC} Entrada não interativa: Ollama não será instalado. Use --with-ollama para habilitar."
    fi
fi

if [ "$INSTALL_OLLAMA" = "1" ]; then
    echo -e "${BLUE}[INFO]${NC} Ollama selecionado para instalação."
else
    echo -e "${BLUE}[INFO]${NC} Ollama não será instalado. O restante das ferramentas funcionará normalmente."
fi

# Detectar distribuição
detect_distro() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        echo "$ID"
    elif [ -f /etc/debian_version ]; then
        echo "debian"
    elif [ -f /etc/redhat-release ]; then
        echo "rhel"
    else
        echo "unknown"
    fi
}

DISTRO=$(detect_distro)
echo -e "${BLUE}[INFO]${NC} Distribuição detectada: $DISTRO"

#===============================================================================
# Instalar dependências do sistema
#===============================================================================

echo -e "\n${GREEN}[1/5]${NC} Instalando dependências do sistema..."

case "$DISTRO" in
    ubuntu|debian|kali|parrot|linuxmint)
        sudo apt update
        sudo apt install -y \
            python3 python3-pip python3-venv python3-dev \
            curl wget ca-certificates openssl dnsutils \
            build-essential libffi-dev libssl-dev
        sudo apt install -y firefox-esr || sudo apt install -y firefox || true
        sudo apt install -y chromium || sudo apt install -y chromium-browser || true
        ;;
    fedora)
        sudo dnf install -y \
            python3 python3-pip python3-devel gcc \
            curl wget ca-certificates openssl bind-utils \
            libffi-devel openssl-devel
        sudo dnf install -y firefox chromium || true
        ;;
    centos|rhel|rocky|almalinux)
        sudo yum install -y \
            python3 python3-pip python3-devel gcc \
            curl wget ca-certificates openssl bind-utils \
            libffi-devel openssl-devel
        sudo yum install -y firefox chromium || true
        ;;
    arch|manjaro)
        sudo pacman -Sy --noconfirm \
            python python-pip base-devel \
            curl wget ca-certificates openssl bind \
            firefox chromium
        ;;
    opensuse*|suse)
        sudo zypper install -y \
            python3 python3-pip python3-devel gcc \
            curl wget ca-certificates openssl bind-utils \
            libffi-devel libopenssl-devel
        sudo zypper install -y MozillaFirefox chromium || true
        ;;
    *)
        echo -e "${YELLOW}[!]${NC} Distribuição não reconhecida. Instalando manualmente..."
        echo "    Instale: python3, pip, curl, wget, openssl, dig e Chromium/Chrome."
        ;;
esac

#===============================================================================
# Verificar Python
#===============================================================================

echo -e "\n${GREEN}[2/5]${NC} Verificando Python..."

if ! command -v python3 &> /dev/null; then
    echo -e "${RED}[ERRO]${NC} Python3 não encontrado!"
    exit 1
fi

PYTHON_VERSION=$(python3 --version)
echo -e "${BLUE}[INFO]${NC} $PYTHON_VERSION"

#===============================================================================
# Instalar pacotes Python
#===============================================================================

echo -e "\n${GREEN}[3/5]${NC} Instalando pacotes Python..."

# Usar pip com --user ou --break-system-packages dependendo da versão
PIP_OPTS=""
if python3 -c "import sys; sys.exit(0 if sys.version_info >= (3,11) else 1)" 2>/dev/null; then
    # Python 3.11+ requer --break-system-packages para pip global
    PIP_OPTS="--break-system-packages"
fi

python3 -m pip install --upgrade pip $PIP_OPTS 2>/dev/null || python3 -m pip install --upgrade pip --user

PYTHON_PACKAGES=(
    requests
    dnspython
    cryptography
    ipwhois
    playwright
    selenium
    webdriver-manager
    Pillow
)

python3 -m pip install $PIP_OPTS "${PYTHON_PACKAGES[@]}" 2>/dev/null || \
python3 -m pip install --user "${PYTHON_PACKAGES[@]}"

echo -e "${GREEN}[✓]${NC} Pacotes Python instalados: ${PYTHON_PACKAGES[*]}"

# O bird-final-findings usa Chromium headless apenas para confirmar redirects.
# Quando a distribuição não fornece um navegador, baixar o binário do Playwright.
if command -v chromium >/dev/null 2>&1 || \
   command -v chromium-browser >/dev/null 2>&1 || \
   command -v google-chrome >/dev/null 2>&1; then
    echo -e "${GREEN}[✓]${NC} Chromium/Chrome do sistema disponível para o bird-final-findings."
else
    echo -e "${YELLOW}[!]${NC} Chromium do sistema não encontrado; instalando o navegador do Playwright..."
    if ! python3 -m playwright install chromium; then
        echo -e "${YELLOW}[AVISO]${NC} Não foi possível baixar o Chromium."
        echo "        O scanner continuará funcionando, mas não confirmará redirects no navegador headless."
    fi
fi

# ============================================
# LLM / AI Dashboard - Ollama + Modelo
# ============================================
OLLAMA_MODEL="${OLLAMA_MODEL:-qwen2.5:7b}"
OLLAMA_START_LOG="${TMPDIR:-/tmp}/ollama-serve.log"

ollama_is_ready() {
    ollama list >/dev/null 2>&1
}

wait_for_ollama() {
    local attempt
    for ((attempt = 1; attempt <= 60; attempt++)); do
        if ollama_is_ready; then
            return 0
        fi
        sleep 1
    done
    return 1
}

configure_ollama() {
    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "🤖 Configurando Ollama (LLM para Dashboard IA)"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

    if command -v ollama >/dev/null 2>&1; then
        echo "✅ Ollama já está instalado: $(ollama --version 2>/dev/null || echo 'versão não identificada')"
    else
        echo "📦 Ollama não encontrado. Instalando..."
        if ! (set -o pipefail; curl -fsSL https://ollama.com/install.sh | sh); then
            echo -e "${RED}[ERRO]${NC} Não foi possível instalar o Ollama."
            return 1
        fi
        hash -r

        if ! command -v ollama >/dev/null 2>&1; then
            echo -e "${RED}[ERRO]${NC} A instalação terminou, mas o comando ollama não foi encontrado."
            return 1
        fi
    fi

    if ollama_is_ready; then
        echo "✅ Servidor Ollama já está respondendo."
    else
        echo "⏳ Iniciando o servidor Ollama..."
        OLLAMA_SYSTEMD_STARTED=0

        if command -v systemctl >/dev/null 2>&1 && \
           systemctl list-unit-files ollama.service >/dev/null 2>&1; then
            if sudo systemctl enable --now ollama; then
                OLLAMA_SYSTEMD_STARTED=1
            else
                echo -e "${YELLOW}[!]${NC} Não foi possível iniciar o serviço systemd do Ollama."
            fi
        fi

        if [ "$OLLAMA_SYSTEMD_STARTED" -eq 0 ]; then
            echo "ℹ️  Iniciando 'ollama serve' em segundo plano (log: $OLLAMA_START_LOG)..."
            nohup ollama serve >"$OLLAMA_START_LOG" 2>&1 &
        fi

        echo "⏳ Aguardando o Ollama ficar disponível (até 60 segundos)..."
        if ! wait_for_ollama; then
            echo -e "${RED}[ERRO]${NC} O servidor Ollama não respondeu após 60 segundos."
            if [ "$OLLAMA_SYSTEMD_STARTED" -eq 1 ]; then
                echo "Consulte o diagnóstico com: sudo journalctl -u ollama -n 50 --no-pager"
            else
                echo "Consulte o log em: $OLLAMA_START_LOG"
            fi
            return 1
        fi
        echo "✅ Servidor Ollama pronto."
    fi

    echo ""
    if ollama show "$OLLAMA_MODEL" >/dev/null 2>&1; then
        echo "✅ Modelo $OLLAMA_MODEL já está instalado."
    else
        echo "📦 Baixando modelo $OLLAMA_MODEL..."
        if ! ollama pull "$OLLAMA_MODEL"; then
            echo -e "${RED}[ERRO]${NC} Não foi possível baixar o modelo $OLLAMA_MODEL."
            return 1
        fi
    fi

    echo ""
    echo "✅ Ollama + $OLLAMA_MODEL disponíveis com sucesso"
}

if [ "$INSTALL_OLLAMA" = "1" ]; then
    if ! configure_ollama; then
        echo -e "${YELLOW}[AVISO]${NC} A configuração opcional do Ollama falhou."
        echo "        A instalação das ferramentas principais continuará normalmente."
    fi
else
    echo ""
    echo -e "${BLUE}[INFO]${NC} Etapa do Ollama ignorada por escolha do usuário."
fi

#===============================================================================
# Instalar GeckoDriver (Firefox)
#===============================================================================

echo -e "\n${GREEN}[4/5]${NC} Configurando GeckoDriver (Firefox)..."

# webdriver-manager vai baixar automaticamente, mas podemos pré-baixar
python3 -c "
try:
    from webdriver_manager.firefox import GeckoDriverManager
    path = GeckoDriverManager().install()
    print(f'GeckoDriver instalado em: {path}')
except Exception as e:
    print(f'Aviso: {e}')
    print('O driver será baixado automaticamente na primeira execução')
"

#===============================================================================
# Verificar instalação
#===============================================================================

echo -e "\n${GREEN}[5/5]${NC} Verificando instalação..."

echo -e "${BLUE}[CHECK]${NC} Verificando dependências:"

check_python_module() {
    local module="$1"
    local label="$2"
    if python3 -c "import $module" 2>/dev/null; then
        echo -e "  ${GREEN}✓${NC} $label: instalado"
    else
        echo -e "  ${RED}✗${NC} $label: NÃO INSTALADO"
    fi
}

# Python
if command -v python3 &> /dev/null; then
    echo -e "  ${GREEN}✓${NC} Python3: $(python3 --version)"
else
    echo -e "  ${RED}✗${NC} Python3: NÃO ENCONTRADO"
fi

# Pip
if python3 -m pip --version &> /dev/null; then
    echo -e "  ${GREEN}✓${NC} Pip: $(python3 -m pip --version | cut -d' ' -f1-2)"
else
    echo -e "  ${RED}✗${NC} Pip: NÃO ENCONTRADO"
fi

# Selenium
if python3 -c "import selenium" 2>/dev/null; then
    VERSION=$(python3 -c "import selenium; print(selenium.__version__)")
    echo -e "  ${GREEN}✓${NC} Selenium: $VERSION"
else
    echo -e "  ${RED}✗${NC} Selenium: NÃO INSTALADO"
fi

# Pillow
if python3 -c "from PIL import Image" 2>/dev/null; then
    VERSION=$(python3 -c "from PIL import __version__; print(__version__)")
    echo -e "  ${GREEN}✓${NC} Pillow: $VERSION"
else
    echo -e "  ${RED}✗${NC} Pillow: NÃO INSTALADO"
fi

# webdriver-manager
if python3 -c "import webdriver_manager" 2>/dev/null; then
    echo -e "  ${GREEN}✓${NC} webdriver-manager: instalado"
else
    echo -e "  ${RED}✗${NC} webdriver-manager: NÃO INSTALADO"
fi

# Dependências específicas do bird-final-findings.py
check_python_module requests "requests"
check_python_module dns "dnspython"
check_python_module cryptography "cryptography"
check_python_module ipwhois "ipwhois"
check_python_module playwright.sync_api "Playwright"

# Firefox
if command -v firefox &> /dev/null; then
    VERSION=$(firefox --version 2>/dev/null | head -1)
    echo -e "  ${GREEN}✓${NC} Firefox: $VERSION"
elif command -v firefox-esr &> /dev/null; then
    VERSION=$(firefox-esr --version 2>/dev/null | head -1)
    echo -e "  ${GREEN}✓${NC} Firefox ESR: $VERSION"
else
    echo -e "  ${YELLOW}!${NC} Firefox: NÃO ENCONTRADO (opcional, fallback para Chrome)"
fi

# Chrome (fallback)
if command -v google-chrome &> /dev/null || command -v chromium &> /dev/null || command -v chromium-browser &> /dev/null; then
    echo -e "  ${GREEN}✓${NC} Chrome/Chromium: disponível para validação headless"
else
    echo -e "  ${YELLOW}!${NC} Chrome/Chromium: não está no PATH; o Playwright poderá usar o binário próprio"
fi

# Curl
if command -v curl &> /dev/null; then
    echo -e "  ${GREEN}✓${NC} curl: $(curl --version | head -1 | cut -d' ' -f1-2)"
else
    echo -e "  ${RED}✗${NC} curl: NÃO ENCONTRADO (necessário para modo --normal)"
fi

# OpenSSL e dig são usados nos comandos de evidência e reprodução.
if command -v openssl &> /dev/null; then
    echo -e "  ${GREEN}✓${NC} OpenSSL: $(openssl version)"
else
    echo -e "  ${RED}✗${NC} OpenSSL: NÃO ENCONTRADO"
fi

if command -v dig &> /dev/null; then
    echo -e "  ${GREEN}✓${NC} dig: disponível"
else
    echo -e "  ${RED}✗${NC} dig: NÃO ENCONTRADO"
fi

if [ -f bird-final-findings.py ] && python3 bird-final-findings.py --version >/dev/null 2>&1; then
    echo -e "  ${GREEN}✓${NC} bird-final-findings.py: pronto para uso"
else
    echo -e "  ${RED}✗${NC} bird-final-findings.py: arquivo ausente ou dependências incompletas"
fi

#===============================================================================
# Finalização
#===============================================================================
echo -e "\n${GREEN}[FINAL]${NC} Publicando as ferramentas em /usr/local/bin..."

# A finalização possui seu próprio controle de erros. Desabilitar o `set -e`
# aqui garante que uma etapa com falha não impeça a execução das seguintes.
set +e
FINALIZATION_ERRORS=0
SOURCE_DIR="$(pwd -P)"

report_final_error() {
    local description="$1"
    local exit_code="$2"
    FINALIZATION_ERRORS=$((FINALIZATION_ERRORS + 1))
    echo -e "  ${RED}✗ ERRO${NC} — $description (código $exit_code)"
}

run_final_step() {
    local description="$1"
    shift

    if "$@"; then
        echo -e "  ${GREEN}✓ OK${NC} — $description"
    else
        local exit_code=$?
        report_final_error "$description" "$exit_code"
    fi

    # A função sempre retorna sucesso para que o `set -e` não interrompa
    # as demais etapas da finalização.
    return 0
}

remove_previous_tools() {
    local previous_tools
    shopt -s nullglob
    previous_tools=(
        /usr/local/bin/bird*
        /usr/local/bin/myip.sh
        /usr/local/bin/normal_validator.sh
        /usr/local/bin/selenium_validator.py
        /usr/local/bin/update.sh
    )
    shopt -u nullglob

    if [ "${#previous_tools[@]}" -eq 0 ]; then
        return 0
    fi
    sudo rm -f -- "${previous_tools[@]}"
}

# Expande os padrões sem gerar erro quando algum arquivo legado não existir.
shopt -s nullglob
TOOL_CANDIDATES=(bird* myip.sh normal_validator.sh selenium_validator.py update.sh)
shopt -u nullglob

TOOLS_TO_INSTALL=()
for tool in "${TOOL_CANDIDATES[@]}"; do
    if [ -f "$tool" ]; then
        TOOLS_TO_INSTALL+=("$tool")
    fi
done

if [ "${#TOOLS_TO_INSTALL[@]}" -eq 0 ]; then
    report_final_error "nenhuma ferramenta foi encontrada para instalação" 1
else
    for tool in "${TOOLS_TO_INSTALL[@]}"; do
        run_final_step "permissão de execução em $tool" chmod +x -- "$tool"
    done

    run_final_step "remoção segura das versões anteriores" remove_previous_tools

    # `install` copia cada arquivo individualmente e define a permissão final.
    # Assim, uma falha não remove os fontes nem impede os próximos arquivos.
    for tool in "${TOOLS_TO_INSTALL[@]}"; do
        destination="/usr/local/bin/$(basename "$tool")"
        run_final_step "instalação de $tool em $destination" \
            sudo install -m 0755 -- "$tool" "$destination"
    done
fi

if [ -e dependencias.sh ]; then
    run_final_step "remoção do arquivo auxiliar dependencias.sh" rm -f -- dependencias.sh
else
    echo -e "  ${BLUE}ℹ INFO${NC} — dependencias.sh não existe; nada para remover"
fi

# Só apaga o diretório de origem quando todas as ferramentas foram publicadas.
# Em caso de erro, os arquivos são preservados para correção ou nova tentativa.
if [ "$FINALIZATION_ERRORS" -eq 0 ]; then
    SOURCE_PARENT="$(dirname "$SOURCE_DIR")"
    SOURCE_NAME="$(basename "$SOURCE_DIR")"

    if [ "$SOURCE_NAME" = "essential" ] && [ "$SOURCE_DIR" != "/" ]; then
        if cd "$SOURCE_PARENT"; then
            if rm -rf -- "$SOURCE_DIR"; then
                echo -e "  ${GREEN}✓ OK${NC} — diretório de origem removido: $SOURCE_DIR"
            else
                report_final_error "não foi possível remover $SOURCE_DIR" "$?"
            fi
        else
            report_final_error "não foi possível acessar $SOURCE_PARENT" "$?"
        fi
    else
        echo -e "  ${YELLOW}! AVISO${NC} — diretório de origem preservado por segurança: $SOURCE_DIR"
    fi
else
    echo -e "  ${YELLOW}! AVISO${NC} — diretório de origem preservado devido aos erros: $SOURCE_DIR"
fi

echo ""
if [ "$FINALIZATION_ERRORS" -eq 0 ]; then
    echo -e "${CYAN}╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║${NC}          ${GREEN}INSTALAÇÃO CONCLUÍDA SEM ERROS!${NC}                     ${CYAN}║${NC}"
    echo -e "${CYAN}╚══════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "${CYAN}╔════════════════════════════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║${NC}          ${GREEN}DIGITE 'BIRD' E DÊ TAB PARA RODAR AS FERRAMENTAS${NC}                              ${CYAN}║${NC}"
    echo -e "${CYAN}╚════════════════════════════════════════════════════════════════════════════════════════╝${NC}"
else
    echo -e "${YELLOW}╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${YELLOW}║${NC}  FINALIZAÇÃO CONCLUÍDA COM ${RED}${FINALIZATION_ERRORS} ERRO(S)${NC}; veja os detalhes acima.  ${YELLOW}║${NC}"
    echo -e "${YELLOW}╚══════════════════════════════════════════════════════════════╝${NC}"
    echo -e "${YELLOW}[!] Corrija os erros informados e execute novamente o instalador.${NC}"
fi
echo ""

# Depois de executar e relatar todas as etapas, sinalize a falha também para
# automações/CI sem esconder o resultado parcial da instalação.
if [ "$FINALIZATION_ERRORS" -gt 0 ]; then
    exit 1
fi
