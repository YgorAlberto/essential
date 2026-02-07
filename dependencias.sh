#!/bin/bash

#===============================================================================
# Instalador de Dependências
# Execute: chmod +x install.sh && ./install.sh
#===============================================================================

set -e

# Cores
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

echo -e "${CYAN}"
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║                    INSTALADOR                                ║"
echo "║              Instalando dependências...                      ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo -e "${NC}"

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
        sudo apt install -y python3 python3-pip python3-venv curl wget firefox-esr || sudo apt install -y python3 python3-pip python3-venv curl wget firefox
        ;;
    fedora)
        sudo dnf install -y python3 python3-pip curl wget firefox
        ;;
    centos|rhel|rocky|almalinux)
        sudo yum install -y python3 python3-pip curl wget firefox
        ;;
    arch|manjaro)
        sudo pacman -Sy --noconfirm python python-pip curl wget firefox
        ;;
    opensuse*|suse)
        sudo zypper install -y python3 python3-pip curl wget firefox
        ;;
    *)
        echo -e "${YELLOW}[!]${NC} Distribuição não reconhecida. Instalando manualmente..."
        echo "    Certifique-se de ter: python3, pip, curl, wget, firefox"
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

python3 -m pip install $PIP_OPTS selenium webdriver-manager Pillow 2>/dev/null || \
python3 -m pip install --user selenium webdriver-manager Pillow

echo -e "${GREEN}[✓]${NC} Pacotes instalados: selenium, webdriver-manager, Pillow"

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
    echo -e "  ${GREEN}✓${NC} Chrome/Chromium: disponível como fallback"
else
    echo -e "  ${YELLOW}!${NC} Chrome: NÃO ENCONTRADO (Firefox será usado)"
fi

# Curl
if command -v curl &> /dev/null; then
    echo -e "  ${GREEN}✓${NC} curl: $(curl --version | head -1 | cut -d' ' -f1-2)"
else
    echo -e "  ${RED}✗${NC} curl: NÃO ENCONTRADO (necessário para modo --normal)"
fi

#===============================================================================
# Finalização
#===============================================================================
chmod +x *
sudo rm /usr/local/bin/bird* && sudo rm /usr/local/bin/myip.sh && sudo rm /usr/local/bin/normal_validator.sh && sudo rm /usr/local/bin/selenium_validator.py && sudo rm /usr/local/bin/update.sh
rm dependencias.sh
sudo mv * /usr/local/bin
cd ..
rm -rf essential

echo ""
echo -e "${CYAN}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║${NC}          ${GREEN}INSTALAÇÃO CONCLUÍDA!${NC}      ${CYAN}║${NC}"
echo -e "${CYAN}╚══════════════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "${CYAN}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║${NC}          ${GREEN}ARQUIVO MOVIDOS PARA BIN!${NC}  ${CYAN}║${NC}"
echo -e "${CYAN}╚══════════════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "${CYAN}╔════════════════════════════════════════════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║${NC}          ${GREEN}DIGITE 'BIRD' E DÊ TAB PARA RODAR AS FERRAMENTAS${NC}     ${CYAN}║${NC}"
echo -e "${CYAN}╚════════════════════════════════════════════════════════════════════════════════════════╝${NC}"
echo ""
