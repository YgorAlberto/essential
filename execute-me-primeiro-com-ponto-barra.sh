#!/bin/bash
#===============================================================================
# Bird Nmap Web Validator
# Valida portas web descobertas pelo nmap
# Arquivo único: parser, modo Normal e modo Selenium
#
# Uso:
#   ./bird-nmap-url-MAIN-web.sh <nmap-output-pattern> [--selenium|--normal]
#   ./bird-nmap-url-MAIN-web.sh --ports <arquivo-portas> --target <arquivo-alvos> [--selenium|--normal]
#   ./bird-nmap-url-MAIN-web.sh -p 80,443,8080 -t example.com [--selenium|--normal]
#
# Suporta glob patterns: nmap-* ou *nmap* etc.
#===============================================================================

# Cores para output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Banner
print_banner() {
    echo -e "${CYAN}"
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║                    BIRD NMAP WEB VALIDATOR                   ║"
    echo "║              Validador de Portas Web do Nmap                 ║"
    echo "╚══════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

# Função de ajuda
show_help() {
    local exit_status="${1:-0}"

    echo -e "${GREEN}Uso:${NC}"
    echo "  $0 <padrão-arquivos-nmap> [--selenium|--normal]"
    echo "  $0 --ports <arquivo-portas> --target <arquivo-alvos> [--selenium|--normal]"
    echo "  $0 -p <porta1,porta2,...> -t <IP/domain> [--selenium|--normal]"
    echo ""
    echo -e "${YELLOW}Argumentos para arquivo Nmap:${NC}"
    echo "  <padrão>           Arquivo(s) nmap - suporta glob patterns"
    echo "                     Exemplos: scan.txt, nmap-*, *nmap-output*"
    echo ""
    echo -e "${YELLOW}Argumentos para portas customizadas:${NC}"
    echo "  --ports <arquivo>  Arquivo com lista de portas (uma por linha)"
    echo "  -p <portas>        Portas separadas por vírgula (80,443,8080)"
    echo ""
    echo -e "${YELLOW}Argumentos para alvos:${NC}"
    echo "  --target <arquivo> Arquivo com lista de alvos (um por linha)"
    echo "  -t <alvo>          IP ou domínio único"
    echo ""
    echo -e "${YELLOW}Modos de validação:${NC}"
    echo "  --selenium         Modo Selenium (padrão) - Screenshots + HTML"
    echo "  --normal           Modo Normal - Requisições furtivas + TXT"
    echo ""
    echo -e "${YELLOW}Exemplos:${NC}"
    echo "  $0 scan.txt --selenium"
    echo "  $0 'nmap-*' --normal"
    echo "  $0 --ports portas.txt --target alvos.txt --selenium"
    echo "  $0 -p 80,443,8080,8443 -t 192.168.1.1 --normal"
    echo "  $0 -p 80,443 --target alvos.txt --selenium"
    exit "$exit_status"
}

argument_error() {
    echo -e "${RED}[ERRO]${NC} $1" >&2
    echo "Use '$0 --help' para ver os exemplos de uso." >&2
    exit 1
}

require_option_value() {
    local option="$1"
    local value="${2:-}"

    if [[ -z "$value" || "$value" == -* ]]; then
        argument_error "A opção $option exige um valor."
    fi
}

# Verificar argumentos
if [[ $# -lt 1 ]]; then
    print_banner
    show_help
fi

if [[ "$1" == "-h" || "$1" == "--help" ]]; then
    print_banner
    show_help
fi

# Variáveis de configuração
FILE_PATTERNS=()
PORTS_FILE=""
PORTS_INLINE=""
TARGET_FILE=""
TARGET_INLINE=""
MODE="--selenium"

# Parse de argumentos
while [[ $# -gt 0 ]]; do
    case "$1" in
        --ports)
            require_option_value "$1" "${2:-}"
            PORTS_FILE="$2"
            shift 2
            ;;
        -p)
            require_option_value "$1" "${2:-}"
            PORTS_INLINE="$2"
            shift 2
            ;;
        --target)
            require_option_value "$1" "${2:-}"
            TARGET_FILE="$2"
            shift 2
            ;;
        -t)
            require_option_value "$1" "${2:-}"
            TARGET_INLINE="$2"
            shift 2
            ;;
        --selenium)
            MODE="--selenium"
            shift
            ;;
        --normal)
            MODE="--normal"
            shift
            ;;
        -h|--help)
            print_banner
            show_help
            ;;
        *)
            if [[ "$1" == -* ]]; then
                argument_error "Opção desconhecida: $1"
            fi
            # Aceita um padrão entre aspas ou vários arquivos expandidos pelo shell.
            FILE_PATTERNS+=("$1")
            shift
            ;;
    esac
done

if [[ -n "$PORTS_FILE" && -n "$PORTS_INLINE" ]]; then
    argument_error "Use apenas uma origem de portas: --ports ou -p."
fi

if [[ -n "$TARGET_FILE" && -n "$TARGET_INLINE" ]]; then
    argument_error "Use apenas uma origem de alvos: --target ou -t."
fi

if [[ ${#FILE_PATTERNS[@]} -gt 0 ]] && \
   [[ -n "$PORTS_FILE" || -n "$PORTS_INLINE" || -n "$TARGET_FILE" || -n "$TARGET_INLINE" ]]; then
    argument_error "Não misture arquivos Nmap com portas/alvos customizados."
fi

print_banner

echo -e "${BLUE}[INFO]${NC} Modo: $MODE"
echo ""

#===============================================================================
# Funções de Parsing
#===============================================================================

# Detectar formato do arquivo
detect_format() {
    local file="$1"
    
    # Verifica se é XML
    if head -5 "$file" | grep -q "<?xml"; then
        echo "xml"
    elif head -5 "$file" | grep -q "<nmaprun"; then
        echo "xml"
    else
        echo "text"
    fi
}

# Parser para formato texto (-oN) - retorna host|porta para cada linha
# Captura portas open E filtered
parse_text_format() {
    local file="$1"
    local current_host=""
    local current_hostname=""
    
    while IFS= read -r line || [[ -n "$line" ]]; do
        # Extrair host
        if echo "$line" | grep -qE "^Nmap scan report for"; then
            # Formato: "Nmap scan report for hostname (IP)" ou "Nmap scan report for IP"
            if echo "$line" | grep -qE "\([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+\)"; then
                current_host=$(echo "$line" | grep -oE "\([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+\)" | tr -d '()')
                current_hostname=$(echo "$line" | sed 's/Nmap scan report for //' | sed 's/ (.*//')
            else
                current_host=$(echo "$line" | awk '{print $NF}')
                current_hostname="$current_host"
            fi
        fi
        
        # Extrair portas - captura open E filtered
        if echo "$line" | grep -qE "^[0-9]+/tcp.*(open|filtered)"; then
            local port
            port=$(echo "$line" | grep -oE "^[0-9]+")
            if [[ -n "$current_host" && -n "$port" ]]; then
                echo "${current_hostname}|${current_host}|${port}"
                # Adicionar entrada apenas por IP se o hostname for diferente
                if [[ "$current_hostname" != "$current_host" ]]; then
                    echo "${current_host}|${current_host}|${port}"
                fi
            fi
        fi
    done < "$file"
}

# Parser para formato XML (-oX)
# Captura portas open E filtered
parse_xml_format() {
    local file="$1"
    
    local current_host=""
    local current_hostname=""
    local current_port=""
    local in_host=0
    
    while IFS= read -r line || [[ -n "$line" ]]; do
        # Início de host
        if echo "$line" | grep -qE '<host([[:space:]>])'; then
            in_host=1
            current_host=""
            current_hostname=""
            current_port=""
        fi
        
        # Extrair endereço IP
        if [[ $in_host -eq 1 ]] && echo "$line" | grep -qE '<address.*addrtype="ipv4"'; then
            current_host=$(echo "$line" | grep -oE 'addr="[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+"' | cut -d'"' -f2)
        fi
        
        # Extrair hostname
        if [[ $in_host -eq 1 ]] && echo "$line" | grep -qE '<hostname.*name='; then
            current_hostname=$(echo "$line" | grep -oE 'name="[^"]+"' | cut -d'"' -f2)
        fi
        
        # Extrair porta - captura open E filtered
        if [[ $in_host -eq 1 ]] && echo "$line" | grep -qE '<port[^>]*protocol="tcp"'; then
            current_port=$(echo "$line" | grep -oE 'portid="[0-9]+"' | cut -d'"' -f2)
        fi

        # O Nmap pode colocar <port> e <state> na mesma linha ou em linhas separadas.
        if [[ $in_host -eq 1 && -n "$current_port" ]] && \
           echo "$line" | grep -qE 'state="(open|filtered|open\|filtered)"'; then
                if [[ -n "$current_host" ]]; then
                    local hostname="${current_hostname:-$current_host}"
                    echo "${hostname}|${current_host}|${current_port}"
                    # Adicionar entrada apenas por IP se o hostname for diferente
                    if [[ -n "$current_hostname" && "$current_hostname" != "$current_host" ]]; then
                        echo "${current_host}|${current_host}|${current_port}"
                    fi
                fi
                current_port=""
        elif [[ $in_host -eq 1 ]] && echo "$line" | grep -qE '</port>'; then
            current_port=""
        fi
        
        # Fim de host
        if echo "$line" | grep -qE '</host>'; then
            in_host=0
        fi
    done < "$file"
}

validate_ports() {
    local port

    for port in "$@"; do
        if [[ ! "$port" =~ ^[0-9]+$ ]] || \
           (( 10#$port < 1 || 10#$port > 65535 )); then
            echo -e "${RED}[ERRO]${NC} Porta inválida: $port (use valores de 1 a 65535)" >&2
            return 1
        fi
    done
}

resolve_ipv4() {
    local target="$1"
    local resolved=""

    if command -v dig &> /dev/null; then
        resolved=$(dig +short "$target" 2>/dev/null | grep -E '^[0-9]+(\.[0-9]+){3}$' | head -1)
    elif command -v getent &> /dev/null; then
        resolved=$(getent ahostsv4 "$target" 2>/dev/null | awk 'NR == 1 {print $1}')
    fi

    printf '%s' "$resolved"
}

# Gerar dados a partir de portas e targets customizados
generate_from_ports_target() {
    local ports_source="$1"  # arquivo ou inline
    local ports_type="$2"    # file ou inline
    local target_source="$3" # arquivo ou inline
    local target_type="$4"   # file ou inline
    
    # Ler portas
    local ports=()
    
    if [[ "$ports_type" == "file" ]]; then
        if [[ -f "$ports_source" ]]; then
            while IFS= read -r line || [[ -n "$line" ]]; do
                # Remover espaços e comentários
                line=$(echo "$line" | sed 's/#.*//' | tr -d ' \t\r')
                [[ -z "$line" ]] && continue
                
                # Suporta formato: porta ou porta1,porta2,porta3
                IFS=',' read -ra port_arr <<< "$line"
                for p in "${port_arr[@]}"; do
                    [[ -n "$p" ]] && ports+=("$p")
                done
            done < "$ports_source"
        else
            echo -e "${RED}[ERRO]${NC} Arquivo de portas não encontrado: $ports_source" >&2
            return 1
        fi
    elif [[ "$ports_type" == "inline" ]]; then
        # Portas passadas via -p (separadas por vírgula)
        IFS=',' read -ra port_arr <<< "$ports_source"
        for p in "${port_arr[@]}"; do
            p=$(echo "$p" | tr -d ' ')
            [[ -n "$p" ]] && ports+=("$p")
        done
    fi
    
    if [[ ${#ports[@]} -eq 0 ]]; then
        echo -e "${RED}[ERRO]${NC} Nenhuma porta especificada" >&2
        return 1
    fi

    if ! validate_ports "${ports[@]}"; then
        return 1
    fi

    # Canonicalizar (ex.: 080 -> 80) para manter a regra especial de 80/443.
    local i
    for i in "${!ports[@]}"; do
        ports[$i]="$((10#${ports[$i]}))"
    done
    
    echo -e "${GREEN}[+]${NC} Portas carregadas: ${ports[*]}" >&2
    
    # Ler targets
    local targets=()
    
    if [[ "$target_type" == "file" ]]; then
        if [[ -f "$target_source" ]]; then
            while IFS= read -r line || [[ -n "$line" ]]; do
                line=$(echo "$line" | sed 's/#.*//' | tr -d ' \t\r')
                [[ -n "$line" ]] && targets+=("$line")
            done < "$target_source"
        else
            echo -e "${RED}[ERRO]${NC} Arquivo de targets não encontrado: $target_source" >&2
            return 1
        fi
    elif [[ "$target_type" == "inline" ]]; then
        # Target único passado via -t
        targets+=("$target_source")
    fi
    
    if [[ ${#targets[@]} -eq 0 ]]; then
        echo -e "${RED}[ERRO]${NC} Nenhum target especificado" >&2
        return 1
    fi

    for t in "${targets[@]}"; do
        if [[ "$t" == *"|"* || "$t" =~ [[:space:]] || "$t" == *"://"* ]]; then
            echo -e "${RED}[ERRO]${NC} Target inválido: $t (informe apenas IP ou domínio)" >&2
            return 1
        fi
    done
    
    echo -e "${GREEN}[+]${NC} Targets carregados: ${#targets[@]}" >&2
    
    # Gerar combinações hostname|ip|porta
    for t in "${targets[@]}"; do
        # Tentar resolver IP se for um domínio
        local target_ip="$t"
        if [[ ! "$t" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
            # É provavelmente um domínio, tenta resolver
            local resolved
            resolved=$(resolve_ipv4 "$t")
            if [[ -n "$resolved" ]]; then
                target_ip="$resolved"
            fi
        fi

        for p in "${ports[@]}"; do
            echo "${t}|${target_ip}|${p}"
            # Se resolveu IP diferente do target original, adiciona entrada para o IP
            if [[ "$t" != "$target_ip" ]]; then
                echo "${target_ip}|${target_ip}|${p}"
            fi
        done
    done
}

#===============================================================================
# Processar arquivos
#===============================================================================

# Criar diretório temporário para dados processados
if ! TEMP_DIR=$(mktemp -d); then
    echo -e "${RED}[ERRO]${NC} Não foi possível criar o diretório temporário." >&2
    exit 1
fi
cleanup() {
    rm -rf -- "$TEMP_DIR"
}
trap cleanup EXIT

# Arquivo para acumular todos os dados
ALL_DATA_FILE="$TEMP_DIR/all_data.txt"
> "$ALL_DATA_FILE"

# Determinar fonte de portas
PORTS_SOURCE=""
PORTS_TYPE=""

if [[ -n "$PORTS_FILE" ]]; then
    PORTS_SOURCE="$PORTS_FILE"
    PORTS_TYPE="file"
elif [[ -n "$PORTS_INLINE" ]]; then
    PORTS_SOURCE="$PORTS_INLINE"
    PORTS_TYPE="inline"
fi

# Determinar fonte de targets
TARGET_SOURCE=""
TARGET_TYPE=""

if [[ -n "$TARGET_FILE" ]]; then
    TARGET_SOURCE="$TARGET_FILE"
    TARGET_TYPE="file"
elif [[ -n "$TARGET_INLINE" ]]; then
    TARGET_SOURCE="$TARGET_INLINE"
    TARGET_TYPE="inline"
fi

# Verificar modo de operação
if [[ -n "$PORTS_SOURCE" && -n "$TARGET_SOURCE" ]]; then
    # Modo portas + targets customizados
    echo -e "${BLUE}[INFO]${NC} Modo: Portas e Targets customizados"
    
    if [[ "$PORTS_TYPE" == "file" ]]; then
        echo -e "${BLUE}[INFO]${NC} Arquivo de portas: $PORTS_SOURCE"
    else
        echo -e "${BLUE}[INFO]${NC} Portas: $PORTS_SOURCE"
    fi
    
    if [[ "$TARGET_TYPE" == "file" ]]; then
        echo -e "${BLUE}[INFO]${NC} Arquivo de targets: $TARGET_SOURCE"
    else
        echo -e "${BLUE}[INFO]${NC} Target: $TARGET_SOURCE"
    fi
    echo ""
    
    if ! generate_from_ports_target "$PORTS_SOURCE" "$PORTS_TYPE" "$TARGET_SOURCE" "$TARGET_TYPE" >> "$ALL_DATA_FILE"; then
        exit 1
    fi
    
    if [[ ! -s "$ALL_DATA_FILE" ]]; then
        echo -e "${RED}[ERRO]${NC} Falha ao gerar dados de portas/targets"
        exit 1
    fi
    
elif [[ -n "$PORTS_SOURCE" && -z "$TARGET_SOURCE" ]]; then
    echo -e "${RED}[ERRO]${NC} Portas especificadas mas falta o target (--target ou -t)"
    show_help 1
    
elif [[ -z "$PORTS_SOURCE" && -n "$TARGET_SOURCE" ]]; then
    echo -e "${RED}[ERRO]${NC} Target especificado mas faltam as portas (--ports ou -p)"
    show_help 1
    
elif [[ ${#FILE_PATTERNS[@]} -gt 0 ]]; then
    # Modo arquivo nmap
    echo -e "${BLUE}[INFO]${NC} Origem Nmap: ${FILE_PATTERNS[*]}"
    
    # Expandir cada padrão sem quebrar nomes de arquivo que contenham espaços.
    FILES=()
    declare -A FILES_SEEN=()
    for pattern in "${FILE_PATTERNS[@]}"; do
        matches=()
        mapfile -t matches < <(compgen -G "$pattern")
        for matched_file in "${matches[@]}"; do
            if [[ -z "${FILES_SEEN[$matched_file]+x}" ]]; then
                FILES+=("$matched_file")
                FILES_SEEN["$matched_file"]=1
            fi
        done
    done
    
    if [[ ${#FILES[@]} -eq 0 ]]; then
        echo -e "${RED}[ERRO]${NC} Nenhum arquivo encontrado com a origem informada."
        exit 1
    fi
    
    echo -e "${GREEN}[+]${NC} Arquivos encontrados: ${#FILES[@]}"
    for f in "${FILES[@]}"; do
        echo "    - $(basename "$f")"
    done
    echo ""
    
    # Processar cada arquivo
    for NMAP_FILE in "${FILES[@]}"; do
        if [[ ! -f "$NMAP_FILE" ]]; then
            echo -e "${YELLOW}[!]${NC} Ignorando (não é arquivo): $NMAP_FILE"
            continue
        fi
        
        echo -e "${BLUE}[*]${NC} Processando: $(basename "$NMAP_FILE")"
        
        # Detectar formato
        FORMAT=$(detect_format "$NMAP_FILE")
        echo -e "${BLUE}[INFO]${NC} Formato detectado: $FORMAT"
        
        # Parsear arquivo
        if [[ "$FORMAT" == "xml" ]]; then
            parse_xml_format "$NMAP_FILE" >> "$ALL_DATA_FILE"
        else
            parse_text_format "$NMAP_FILE" >> "$ALL_DATA_FILE"
        fi
    done
    
else
    echo -e "${RED}[ERRO]${NC} Especifique um arquivo nmap ou use portas/targets customizados"
    echo ""
    echo "Exemplos:"
    echo "  $0 nmap-output.txt --normal"
    echo "  $0 -p 80,443,8080 -t example.com --selenium"
    echo "  $0 --ports portas.txt --target alvos.txt --normal"
    exit 1
fi

# Remover duplicatas
sort -u "$ALL_DATA_FILE" -o "$ALL_DATA_FILE"

# Conta exatamente as URLs únicas geradas pelos dois validadores.
# Portas 80/443 geram um teste; as demais geram HTTP e HTTPS.
calculate_test_count() {
    local data_file="$1"
    local hostname ip port target url
    local -a urls=()
    local -A urls_seen=()

    while IFS='|' read -r hostname ip port _; do
        [[ -z "$port" ]] && continue
        target="${hostname:-$ip}"
        [[ -z "$target" ]] && continue

        if [[ "$port" == "80" ]]; then
            urls=("http://${target}")
        elif [[ "$port" == "443" ]]; then
            urls=("https://${target}")
        else
            urls=("http://${target}:${port}" "https://${target}:${port}")
        fi

        for url in "${urls[@]}"; do
            urls_seen["$url"]=1
        done
    done < "$data_file"

    printf '%d' "${#urls_seen[@]}"
}

# Verificar se há dados
LINE_COUNT=$(wc -l < "$ALL_DATA_FILE")

if [[ $LINE_COUNT -eq 0 ]]; then
    echo -e "${RED}[!]${NC} Nenhuma porta encontrada para validar."
    echo -e "${YELLOW}[INFO]${NC} Verifique se o arquivo nmap contém portas abertas ou filtradas."
    exit 1
fi

TEST_COUNT=$(calculate_test_count "$ALL_DATA_FILE")

echo ""
echo -e "${GREEN}[+]${NC} Entradas processadas: $LINE_COUNT"
echo -e "${GREEN}[+]${NC} Total real de URLs/testes: $TEST_COUNT"
echo ""

# Debug: mostrar algumas entradas
echo -e "${BLUE}[DEBUG]${NC} Primeiras entradas:"
head -5 "$ALL_DATA_FILE" | while read -r line; do
    echo "    $line"
done
echo ""

# Executar validador apropriado
if [[ "$MODE" == "--selenium" ]]; then
    echo -e "${GREEN}[+]${NC} Iniciando validação com Selenium..."
    echo ""
    
    # Verificar Python e dependências
    if ! command -v python3 &> /dev/null; then
        echo -e "${RED}[ERRO]${NC} Python3 não encontrado!"
        exit 1
    fi
    
    # Executar validador Selenium incorporado
    python3 - "$ALL_DATA_FILE" <<'BIRD_SELENIUM_VALIDATOR'
"""
Bird Nmap Web Validator - Selenium Module
Valida URLs usando Selenium, captura screenshots e gera relatório HTML
Versão 3.0 - Index por ativo + Master dinâmico + Firefox primeiro
"""

import os
import sys
import time
import hashlib
import re
import json
import shlex
from datetime import datetime
from html import escape
from urllib.parse import urlparse
from collections import defaultdict

# Verificar e instalar dependências
def check_dependencies():
    """Verifica e instala dependências necessárias"""
    required = ['selenium', 'PIL']
    module_names = {'PIL': 'Pillow'}
    missing = []
    
    for module in required:
        try:
            __import__(module)
        except ImportError:
            pkg_name = module_names.get(module, module)
            missing.append(pkg_name)
    
    if missing:
        print(f"[*] Instalando dependências: {', '.join(missing)}")
        import subprocess
        for module in missing:
            subprocess.check_call([sys.executable, '-m', 'pip', 'install', module, '-q'])

check_dependencies()

from selenium import webdriver
from selenium.webdriver.chrome.service import Service as ChromeService
from selenium.webdriver.chrome.options import Options as ChromeOptions
from selenium.webdriver.firefox.service import Service as FirefoxService
from selenium.webdriver.firefox.options import Options as FirefoxOptions
from selenium.webdriver.common.by import By
from selenium.common.exceptions import WebDriverException, TimeoutException
from PIL import Image, ImageDraw, ImageFont

# Webdriver Manager foi removido em favor do Selenium Manager (nativo do Selenium 4.6+)


class SeleniumValidator:
    """Validador de URLs usando Selenium"""
    
    def __init__(self, output_dir="paginas-web-encontradas"):
        self.output_dir = output_dir
        self.results = defaultdict(list)  # Organizado por ativo
        self.all_tests = []               # Todos os testes realizados (validos e invalidos)
        self.active_hosts = set()         # Conjunto de (scheme, host, port) ativos
        self.driver = None
        
        # Criar diretório de saída
        os.makedirs(self.output_dir, exist_ok=True)
    
    def init_driver(self):
        """Inicializa o WebDriver (Firefox primeiro, depois Chrome/Chromium)"""
        
        # 1. Tentar Firefox
        try:
            options = FirefoxOptions()
            options.add_argument('--headless')
            options.add_argument('--width=1920')
            options.add_argument('--height=1080')
            options.set_preference('network.stricttransportsecurity.preloadlist', False)
            options.set_preference('security.cert_pinning.enforcement_level', 0)
            options.accept_insecure_certs = True
            
            # Selenium Manager (nativo) cuidará do driver
            self.driver = webdriver.Firefox(options=options)
            
            self.driver.set_page_load_timeout(15)
            print("[+] Firefox WebDriver inicializado com sucesso")
            return True
        except Exception as e:
            if "reach host" in str(e):
                print("[!] Erro: Selenium não conseguiu baixar o Geckodriver (sem internet?)")
            else:
                print(f"[!] Erro ao inicializar Firefox: {e}")
        
        # 2. Tentar Chrome/Chromium
        try:
            options = ChromeOptions()
            options.add_argument('--headless')
            options.add_argument('--no-sandbox')
            options.add_argument('--disable-dev-shm-usage')
            options.add_argument('--disable-gpu')
            options.add_argument('--window-size=1920,1080')
            options.add_argument('--ignore-certificate-errors')
            options.add_argument('--ignore-ssl-errors')
            options.add_argument('--user-agent=Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36')
            
            # Priorizar Chromium se encontrado (comum em Kali/Linux)
            chromium_paths = ['/usr/bin/chromium', '/usr/bin/chromium-browser', '/snap/bin/chromium']
            for path in chromium_paths:
                if os.path.exists(path):
                    options.binary_location = path
                    print(f"[*] Usando binário do Chromium: {path}")
                    break
            
            # Selenium Manager cuidará da detecção e download do driver compatível
            self.driver = webdriver.Chrome(options=options)
            
            self.driver.set_page_load_timeout(15)
            print("[+] Chrome/Chromium WebDriver inicializado com sucesso")
            return True
        except Exception as e:
            if "session not created" in str(e) or "version" in str(e):
                print(f"[!] Erro de compatibilidade entre Chrome e Driver: {e}")
                print("[TIP] Tente instalar o driver manualmente: sudo apt install chromium-driver")
            elif "reach host" in str(e):
                print("[!] Erro: Selenium não conseguiu baixar o Chromedriver (sem internet?)")
            else:
                print(f"[!] Erro ao inicializar Chrome/Chromium: {e}")
            
        return False
    
    def add_url_to_screenshot(self, screenshot_path, url):
        """Adiciona a URL na parte superior da imagem"""
        try:
            img = Image.open(screenshot_path)
            
            # Criar barra superior para a URL
            bar_height = 40
            new_img = Image.new('RGB', (img.width, img.height + bar_height), color=(30, 30, 50))
            new_img.paste(img, (0, bar_height))
            
            # Adicionar texto da URL
            draw = ImageDraw.Draw(new_img)
            
            # Tentar usar fonte do sistema
            try:
                font = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf", 16)
            except:
                try:
                    font = ImageFont.truetype("/usr/share/fonts/TTF/DejaVuSansMono.ttf", 16)
                except:
                    font = ImageFont.load_default()
            
            # Desenhar URL
            text_color = (0, 212, 255)  # Cyan
            draw.text((10, 10), f"URL: {url}", fill=text_color, font=font)
            
            # Salvar imagem
            new_img.save(screenshot_path)
            return True
            
        except Exception as e:
            print(f"    [!] Erro ao adicionar URL na imagem: {e}")
            return False
    
    def validate_url(self, url, asset):
        """
        Valida uma URL e captura screenshot.
        Salva se a página responde (mesmo 4xx), não salva se timeout/conexão falhou.
        """
        
        result = {
            'url': url,
            'valid': False,
            'title': '',
            'description': '',
            'screenshot': '',
            'error': '',
            'status_hint': ''
        }
        
        try:
            print(f"  [*] Testando: {url}")
            
            self.driver.get(url)
            time.sleep(2)  # Aguardar carregamento
            
            # Obter título
            title = self.driver.title or "Sem título"
            result['title'] = title[:100] if title else "Sem título"
            
            # Detectar status pelo título (4xx, 5xx são válidos - serviço existe!)
            title_lower = title.lower()
            if any(code in title_lower for code in ['404', '403', '401', '500', '502', '503']):
                result['status_hint'] = 'Página de erro HTTP (serviço existe)'
            
            # Obter descrição (meta description ou primeiro parágrafo)
            description = self._get_description()
            result['description'] = description[:300] if description else "Sem descrição disponível"
            
            # Criar diretório para o ativo
            safe_asset = re.sub(r'[^\w\-.]', '_', asset)
            asset_dir = os.path.join(self.output_dir, safe_asset)
            os.makedirs(asset_dir, exist_ok=True)
            
            # Gerar nome único para screenshot
            url_hash = hashlib.md5(url.encode()).hexdigest()[:8]
            parsed = urlparse(url)
            port = parsed.port or (443 if parsed.scheme == 'https' else 80)
            screenshot_name = f"port_{port}_{url_hash}.png"
            screenshot_path = os.path.join(asset_dir, screenshot_name)
            
            # Capturar screenshot
            if not self.driver.save_screenshot(screenshot_path):
                raise WebDriverException("WebDriver não conseguiu salvar o screenshot")
            
            # Adicionar URL na imagem
            self.add_url_to_screenshot(screenshot_path, url)
            
            result['screenshot'] = screenshot_name  # Só o nome, não o caminho completo
            result['valid'] = True
            
            print(f"  [+] Válida: {title[:50]}...")
            
        except TimeoutException:
            result['error'] = "Timeout ao carregar página"
            print(f"  [-] Timeout (não salvo): {url}")
            
        except WebDriverException as e:
            error_msg = str(e)[:100]
            result['error'] = error_msg
            # Não salvar se for erro de conexão
            print(f"  [-] Erro de conexão (não salvo): {url}")
            
        except Exception as e:
            result['error'] = str(e)[:100]
            print(f"  [-] Erro inesperado (não salvo): {url}")
        
        return result
    
    def _get_description(self):
        """Extrai descrição da página"""
        
        # Tentar meta description
        try:
            meta = self.driver.find_element(By.CSS_SELECTOR, 'meta[name="description"]')
            content = meta.get_attribute('content')
            if content:
                return content.strip()
        except:
            pass
        
        # Tentar og:description
        try:
            meta = self.driver.find_element(By.CSS_SELECTOR, 'meta[property="og:description"]')
            content = meta.get_attribute('content')
            if content:
                return content.strip()
        except:
            pass
        
        # Tentar primeiro parágrafo
        try:
            paragraphs = self.driver.find_elements(By.TAG_NAME, 'p')
            for p in paragraphs[:5]:
                text = p.text.strip()
                if len(text) > 50:
                    return text
        except:
            pass
        
        # Tentar h1
        try:
            h1 = self.driver.find_element(By.TAG_NAME, 'h1')
            if h1.text:
                return f"Página: {h1.text.strip()}"
        except:
            pass
        
        return "Sem descrição disponível"
    
    def validate_data(self, data_list):
        """Valida lista de dados (hostname|ip|port)"""

        # Agrupar por ativo
        assets = defaultdict(list)
        for data in data_list:
            parts = data.strip().split('|')
            if len(parts) >= 3:
                hostname, ip, port = parts[0], parts[1], parts[2]
                asset = hostname if hostname else ip
                assets[asset].append((hostname, ip, port))

        planned_total = 0
        for entries in assets.values():
            planned_urls = set()
            for hostname, ip, port in entries:
                target = hostname if hostname else ip
                if port == "80":
                    planned_urls.add(f"http://{target}")
                elif port == "443":
                    planned_urls.add(f"https://{target}")
                else:
                    planned_urls.add(f"http://{target}:{port}")
                    planned_urls.add(f"https://{target}:{port}")
            planned_total += len(planned_urls)

        print(
            f"\n[*] Iniciando {planned_total} testes de URL "
            f"a partir de {len(data_list)} entradas...\n"
        )
        
        total = 0
        for asset, entries in assets.items():
            print(f"\n[*] Ativo: {asset}")
            
            # Gerar URLs únicas para este ativo
            urls_seen = set()
            for hostname, ip, port in entries:
                target = hostname if hostname else ip
                
                if port == "80":
                    urls = [f"http://{target}"]
                elif port == "443":
                    urls = [f"https://{target}"]
                else:
                    urls = [f"http://{target}:{port}", f"https://{target}:{port}"]
                
                for url in urls:
                    if url not in urls_seen:
                        urls_seen.add(url)
                        total += 1
                        print(f"[{total}]")
                        result = self.validate_url(url, asset)
                        self.all_tests.append(result)
                        
                        # Só adicionar se válido (página carregou)
                        if result['valid']:
                            self.results[asset].append(result)
                            
                            # Registrar host:porta ativo para comandos de fuzzing
                            parsed = urlparse(url)
                            port = parsed.port or (443 if parsed.scheme == 'https' else 80)
                            self.active_hosts.add((parsed.scheme, parsed.hostname, port))
                        
                        time.sleep(0.5)
        
        return self.results
    
    def generate_asset_index(self, asset, results):
        """Gera index.html para um ativo específico"""
        
        safe_asset = re.sub(r'[^\w\-.]', '_', asset)
        asset_dir = os.path.join(self.output_dir, safe_asset)
        escaped_asset = escape(asset)
        
        html = f'''<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{escaped_asset} - Bird Nmap Web Validator</title>
    <style>
        :root {{
            --bg-primary: #0f0f23;
            --bg-secondary: #1a1a2e;
            --bg-card: #16213e;
            --text-primary: #e0e0e0;
            --text-secondary: #a0a0a0;
            --accent: #00d4ff;
            --accent-hover: #00b8e6;
            --success: #00ff88;
            --border: #2d2d4a;
        }}
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: var(--bg-primary);
            color: var(--text-primary);
            min-height: 100vh;
            padding: 20px;
        }}
        .container {{ max-width: 1400px; margin: 0 auto; }}
        header {{
            text-align: center;
            padding: 30px 20px;
            background: linear-gradient(135deg, var(--bg-secondary) 0%, var(--bg-card) 100%);
            border-radius: 16px;
            margin-bottom: 30px;
            border: 1px solid var(--border);
        }}
        h1 {{
            font-size: 2rem;
            color: var(--accent);
            margin-bottom: 10px;
        }}
        .back-link {{
            color: var(--text-secondary);
            text-decoration: none;
            display: inline-block;
            margin-bottom: 15px;
        }}
        .back-link:hover {{ color: var(--accent); }}
        .stats {{
            display: flex;
            justify-content: center;
            gap: 30px;
            margin-top: 15px;
        }}
        .stat-value {{ font-size: 1.8rem; font-weight: bold; color: var(--success); }}
        .stat-label {{ color: var(--text-secondary); font-size: 0.9rem; }}
        .grid {{
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(400px, 1fr));
            gap: 20px;
        }}
        .card {{
            background: var(--bg-card);
            border-radius: 12px;
            overflow: hidden;
            border: 1px solid var(--border);
            transition: transform 0.3s, box-shadow 0.3s;
        }}
        .card:hover {{
            transform: translateY(-5px);
            box-shadow: 0 10px 30px rgba(0, 212, 255, 0.1);
        }}
        .card-image {{
            width: 100%;
            height: 280px;
            object-fit: cover;
            object-position: top;
            border-bottom: 1px solid var(--border);
            cursor: pointer;
        }}
        .card-content {{ padding: 20px; }}
        .card-title {{
            font-size: 1.1rem;
            margin-bottom: 10px;
            color: var(--text-primary);
            word-break: break-word;
        }}
        .card-url {{
            color: var(--accent);
            text-decoration: none;
            font-size: 0.9rem;
            word-break: break-all;
            display: block;
            margin-bottom: 10px;
        }}
        .card-url:hover {{ color: var(--accent-hover); text-decoration: underline; }}
        .card-description {{
            color: var(--text-secondary);
            font-size: 0.9rem;
            line-height: 1.5;
        }}
        .status-hint {{
            background: var(--bg-secondary);
            color: #ffaa00;
            padding: 5px 10px;
            border-radius: 5px;
            font-size: 0.8rem;
            margin-top: 10px;
            display: inline-block;
        }}
        .modal {{
            display: none;
            position: fixed;
            top: 0; left: 0;
            width: 100%; height: 100%;
            background: rgba(0, 0, 0, 0.9);
            z-index: 1000;
            justify-content: center;
            align-items: center;
        }}
        .modal.active {{ display: flex; }}
        .modal img {{ max-width: 95%; max-height: 95%; border-radius: 8px; }}
        .modal-close {{
            position: absolute;
            top: 20px; right: 30px;
            font-size: 2rem;
            color: white;
            cursor: pointer;
        }}
        footer {{
            text-align: center;
            padding: 30px;
            color: var(--text-secondary);
            font-size: 0.9rem;
        }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <a href="../index.html" class="back-link">← Voltar ao índice</a>
            <h1>🖥️ {escaped_asset}</h1>
            <div class="stats">
                <div>
                    <div class="stat-value">{len(results)}</div>
                    <div class="stat-label">Páginas Encontradas</div>
                </div>
            </div>
        </header>
        
        <div class="grid">
'''
        
        for result in results:
            status_html = ""
            if result.get('status_hint'):
                status_html = f'<span class="status-hint">⚠️ {escape(result["status_hint"])}</span>'

            escaped_url = escape(result['url'], quote=True)
            escaped_title = escape(result['title'])
            escaped_description = escape(result['description'])
            escaped_screenshot = escape(result['screenshot'], quote=True)
            
            html += f'''
            <div class="card">
                <img src="{escaped_screenshot}" alt="{escaped_title}" class="card-image" onclick="openModal(this.src)">
                <div class="card-content">
                    <h3 class="card-title">{escaped_title}</h3>
                    <a href="{escaped_url}" target="_blank" class="card-url">{escaped_url}</a>
                    <p class="card-description">{escaped_description}</p>
                    {status_html}
                </div>
            </div>
'''
        
        html += f'''
        </div>
        
        <footer>
            <p>Gerado em {datetime.now().strftime("%d/%m/%Y às %H:%M:%S")}</p>
            <p>Bird Nmap Web Validator</p>
        </footer>
    </div>
    
    <div class="modal" id="imageModal" onclick="closeModal()">
        <span class="modal-close">&times;</span>
        <img src="" alt="Screenshot ampliado" id="modalImage">
    </div>
    
    <script>
        function openModal(src) {{
            document.getElementById('modalImage').src = src;
            document.getElementById('imageModal').classList.add('active');
        }}
        function closeModal() {{
            document.getElementById('imageModal').classList.remove('active');
        }}
        document.addEventListener('keydown', function(e) {{
            if (e.key === 'Escape') closeModal();
        }});
    </script>
</body>
</html>
'''
        
        # Salvar index do ativo
        index_path = os.path.join(asset_dir, 'index.html')
        with open(index_path, 'w', encoding='utf-8') as f:
            f.write(html)
        
        # Salvar metadata JSON para o master index
        metadata = {
            'asset': asset,
            'count': len(results),
            'updated': datetime.now().isoformat(),
            'pages': [{'url': r['url'], 'title': r['title']} for r in results]
        }
        metadata_path = os.path.join(asset_dir, 'metadata.json')
        with open(metadata_path, 'w', encoding='utf-8') as f:
            json.dump(metadata, f, ensure_ascii=False, indent=2)
        
        return index_path
    def generate_master_index(self):
        """Gera index.html master ESTÁTICO com todos os dados embutidos"""
        
        # Calcular totais
        total_assets = len(self.results)
        total_pages = sum(len(results) for results in self.results.values())
        total_tested = len(self.all_tests)
        total_valid = sum(1 for t in self.all_tests if t['valid'])
        total_invalid = total_tested - total_valid
        
        # Gerar comando único de fuzzing com os alvos protegidos contra
        # interpretação acidental pelo shell.
        active_urls = [
            f"{scheme}://{host}"
            + (f":{port}/" if (scheme == 'http' and port != 80)
               or (scheme == 'https' and port != 443) else "/")
            for scheme, host, port in sorted(self.active_hosts)
        ]
        if active_urls:
            quoted_urls = " ".join(shlex.quote(url) for url in active_urls)
            fuzzing_command = (
                f"printf '%s\\n' {quoted_urls} | feroxbuster --stdin --methods GET "
                "-r -A -w /usr/share/dirb/wordlists/big.txt -o fuzz-feroxbuster "
                "-x php bkp old txt xml cgi pdf html htm asp aspx pl sql js png "
                "jpg jpeg config sh cfm zip log -k"
            )
        else:
            fuzzing_command = "# Nenhuma URL ativa encontrada para fuzzing."
        fuzzing_content = escape(fuzzing_command)

        html = f'''<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Bird Nmap Web Validator - Master Index</title>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;600;700&family=JetBrains+Mono&display=swap" rel="stylesheet">
    <style>
        :root {{
            --bg-primary: #0a0a12;
            --bg-secondary: #121225;
            --bg-card: #1c1c3a;
            --bg-tab-active: #252550;
            --text-primary: #f0f0f0;
            --text-secondary: #b0b0d0;
            --accent: #00d4ff;
            --accent-glow: rgba(0, 212, 255, 0.4);
            --success: #00ff88;
            --danger: #ff4d4d;
            --border: #2d2d5a;
            --glass: rgba(255, 255, 255, 0.03);
        }}
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            font-family: 'Inter', system-ui, -apple-system, sans-serif;
            background: var(--bg-primary);
            color: var(--text-primary);
            min-height: 100vh;
            line-height: 1.6;
        }}
        .container {{ max-width: 1400px; margin: 0 auto; padding: 40px 20px; }}
        
        /* Header & Stats */
        header {{
            text-align: center;
            padding: 50px 30px;
            background: linear-gradient(135deg, var(--bg-secondary) 0%, #1a1a3a 100%);
            border-radius: 24px;
            margin-bottom: 40px;
            border: 1px solid var(--border);
            box-shadow: 0 20px 50px rgba(0,0,0,0.3);
            position: relative;
            overflow: hidden;
        }}
        header::before {{
            content: '';
            position: absolute;
            top: -50%; left: -50%;
            width: 200%; height: 200%;
            background: radial-gradient(circle, var(--accent-glow) 0%, transparent 70%);
            opacity: 0.1;
            pointer-events: none;
        }}
        h1 {{
            font-size: 3rem;
            font-weight: 800;
            background: linear-gradient(90deg, var(--accent), var(--success));
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            margin-bottom: 10px;
            letter-spacing: -1px;
        }}
        .subtitle {{ color: var(--text-secondary); font-size: 1.2rem; font-weight: 300; }}
        
        .stats-container {{
            display: flex;
            justify-content: center;
            gap: 30px;
            margin-top: 35px;
            flex-wrap: wrap;
        }}
        .stat-card {{
            background: var(--glass);
            padding: 20px 35px;
            border-radius: 16px;
            border: 1px solid var(--border);
            backdrop-filter: blur(10px);
            min-width: 160px;
            transition: transform 0.3s;
        }}
        .stat-card:hover {{ transform: translateY(-5px); }}
        .stat-value {{ font-size: 2.2rem; font-weight: 700; color: var(--accent); }}
        .stat-value.valid {{ color: var(--success); }}
        .stat-value.invalid {{ color: var(--danger); }}
        .stat-label {{ color: var(--text-secondary); font-size: 0.85rem; text-transform: uppercase; letter-spacing: 1px; margin-top: 5px; }}

        /* Tabs Interface */
        .tabs-header {{
            display: flex;
            gap: 10px;
            margin-bottom: 25px;
            border-bottom: 1px solid var(--border);
            padding-bottom: 15px;
        }}
        .tab-btn {{
            padding: 12px 24px;
            background: transparent;
            border: 1px solid transparent;
            color: var(--text-secondary);
            font-size: 1rem;
            font-weight: 600;
            cursor: pointer;
            border-radius: 12px;
            transition: all 0.3s;
        }}
        .tab-btn:hover {{
            background: var(--glass);
            color: var(--text-primary);
        }}
        .tab-btn.active {{
            background: var(--bg-tab-active);
            color: var(--accent);
            border-color: var(--accent-glow);
            box-shadow: 0 0 20px var(--accent-glow);
        }}
        .tab-content {{ display: none; animation: fadeIn 0.4s ease-out; }}
        .tab-content.active {{ display: block; }}
        @keyframes fadeIn {{ from {{ opacity: 0; transform: translateY(10px); }} to {{ opacity: 1; transform: translateY(0); }} }}

        /* Assets Grid */
        .assets-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(380px, 1fr));
            gap: 25px;
        }}
        .asset-card {{
            background: var(--bg-card);
            border-radius: 20px;
            padding: 30px;
            border: 1px solid var(--border);
            transition: all 0.4s cubic-bezier(0.175, 0.885, 0.32, 1.275);
            text-decoration: none;
            display: block;
            box-shadow: 0 10px 30px rgba(0,0,0,0.2);
        }}
        .asset-card:hover {{
            transform: translateY(-8px) scale(1.02);
            border-color: var(--accent);
            box-shadow: 0 15px 40px rgba(0, 212, 255, 0.15);
        }}
        .asset-name {{
            font-size: 1.4rem;
            font-weight: 700;
            color: var(--accent);
            margin-bottom: 15px;
            display: flex;
            align-items: center;
            justify-content: space-between;
        }}
        .asset-count {{
            background: rgba(0, 255, 136, 0.15);
            color: var(--success);
            padding: 4px 12px;
            border-radius: 20px;
            font-size: 0.8rem;
            font-weight: 700;
            border: 1px solid rgba(0, 255, 136, 0.3);
        }}
        .asset-pages {{ color: var(--text-secondary); font-size: 0.95rem; margin-top: 15px; list-style: none; }}
        .asset-pages li {{ margin: 8px 0; padding-left: 20px; position: relative; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }}
        .asset-pages li::before {{ content: '📄'; position: absolute; left: 0; }}

        /* Links Table */
        .links-controls {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 20px;
            background: var(--bg-card);
            padding: 15px 25px;
            border-radius: 16px;
            border: 1px solid var(--border);
        }}
        .filter-group {{ display: flex; gap: 10px; }}
        .btn {{
            padding: 8px 16px;
            border-radius: 8px;
            border: 1px solid var(--border);
            background: var(--bg-secondary);
            color: var(--text-secondary);
            cursor: pointer;
            font-weight: 600;
            transition: all 0.2s;
        }}
        .btn:hover {{ background: var(--bg-tab-active); color: var(--text-primary); }}
        .btn.active {{ background: var(--accent); color: var(--bg-primary); border-color: var(--accent); }}
        .btn-copy {{ background: var(--success); color: var(--bg-primary); border: none; }}
        .btn-copy:hover {{ opacity: 0.9; transform: scale(1.05); }}

        .table-container {{
            background: var(--bg-card);
            border-radius: 16px;
            border: 1px solid var(--border);
            overflow: hidden;
            box-shadow: 0 10px 30px rgba(0,0,0,0.2);
        }}
        table {{ width: 100%; border-collapse: collapse; text-align: left; }}
        th {{ background: rgba(255,255,255,0.05); padding: 18px 25px; font-weight: 700; color: var(--accent); text-transform: uppercase; font-size: 0.8rem; letter-spacing: 1px; }}
        td {{ padding: 15px 25px; border-bottom: 1px solid var(--border); font-size: 0.95rem; }}
        tr:hover {{ background: rgba(255,255,255,0.02); }}
        .status-badge {{
            padding: 4px 10px;
            border-radius: 6px;
            font-size: 0.8rem;
            font-weight: 700;
            display: inline-block;
        }}
        .status-badge.valid {{ background: rgba(0, 255, 136, 0.15); color: var(--success); border: 1px solid rgba(0, 255, 136, 0.3); }}
        .status-badge.invalid {{ background: rgba(255, 77, 77, 0.15); color: var(--danger); border: 1px solid rgba(255, 77, 77, 0.3); }}
        .link-url {{ color: var(--text-primary); text-decoration: none; word-break: break-all; }}
        .link-url:hover {{ color: var(--accent); text-decoration: underline; }}

        /* Fuzzing Tools */
        .fuzz-container {{
            background: var(--bg-card);
            border-radius: 20px;
            padding: 40px;
            border: 1px solid var(--border);
            box-shadow: 0 10px 30px rgba(0,0,0,0.2);
        }}
        .terminal-box {{
            background: #000;
            color: #00ff88;
            padding: 30px;
            border-radius: 12px;
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.9rem;
            white-space: pre-wrap;
            overflow-x: auto;
            border: 1px solid var(--border);
            margin-top: 25px;
            position: relative;
        }}
        .copy-banner {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 15px;
        }}
        .tool-title {{ font-size: 1.3rem; font-weight: 700; color: var(--accent); }}

        footer {{
            text-align: center;
            padding: 60px 20px;
            color: var(--text-secondary);
            font-size: 0.9rem;
            border-top: 1px solid var(--border);
            margin-top: 60px;
        }}
        .toast {{
            position: fixed;
            bottom: 30px;
            right: 30px;
            background: var(--success);
            color: var(--bg-primary);
            padding: 12px 25px;
            border-radius: 12px;
            font-weight: 700;
            box-shadow: 0 10px 30px rgba(0,255,136,0.3);
            display: none;
            z-index: 2000;
            animation: slideUp 0.3s ease-out;
        }}
        @keyframes slideUp {{ from {{ transform: translateY(50px); opacity: 0; }} to {{ transform: translateY(0); opacity: 1; }} }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>🐦 Bird Nmap Web Validator</h1>
            <p class="subtitle">Security Reconnaissance & Web Surface Analysis</p>
            <div class="stats-container">
                <div class="stat-card">
                    <div class="stat-value">{total_assets}</div>
                    <div class="stat-label">Hosts Ativos</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value">{total_tested}</div>
                    <div class="stat-label">Total Testados</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value valid">{total_valid}</div>
                    <div class="stat-label">Válidos</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value invalid">{total_invalid}</div>
                    <div class="stat-label">Inválidos</div>
                </div>
            </div>
        </header>

        <div class="tabs-header">
            <button class="tab-btn active" onclick="openTab('assets-tab', this)">🖥️ Ativos</button>
            <button class="tab-btn" onclick="openTab('links-tab', this)">🔗 Links Testados</button>
            <button class="tab-btn" onclick="openTab('fuzz-tab', this)">🚀 Fuzzing Tools</button>
        </div>

        <!-- TAB ASSETS -->
        <div id="assets-tab" class="tab-content active">
            <div class="assets-grid">
'''

        # Gerar cards para cada ativo (ordenado)
        for asset in sorted(self.results.keys()):
            results = self.results[asset]
            safe_asset = re.sub(r'[^\w\-.]', '_', asset)
            escaped_asset = escape(asset)
            
            pages_html = ""
            for r in results[:5]:
                title = r['title'][:50] + "..." if len(r['title']) > 50 else r['title']
                pages_html += f"<li>{escape(title)}</li>"
            
            if len(results) > 5:
                pages_html += f"<li>... e mais {len(results) - 5} resultados</li>"
            
            html += f'''
                <a href="{safe_asset}/index.html" class="asset-card">
                    <div class="asset-name">
                        {escaped_asset}
                        <span class="asset-count">{len(results)} páginas</span>
                    </div>
                    <ul class="asset-pages">
                        {pages_html}
                    </ul>
                </a>
'''
        
        html += '''
            </div>
        </div>

        <!-- TAB LINKS -->
        <div id="links-tab" class="tab-content">
            <div class="links-controls">
                <div class="filter-group">
                    <button class="btn active" onclick="filterLinks('all', this)">Todos</button>
                    <button class="btn" onclick="filterLinks('valid', this)">Válidos ✅</button>
                    <button class="btn" onclick="filterLinks('invalid', this)">Inválidos ❌</button>
                </div>
                <button class="btn btn-copy" onclick="copyLinks()">📋 Copiar Lista</button>
            </div>
            <div class="table-container">
                <table id="linksTable">
                    <thead>
                        <tr>
                            <th>URL</th>
                            <th>Status</th>
                            <th>Info</th>
                        </tr>
                    </thead>
                    <tbody>
'''
        # Gerar linhas da tabela (Válidos primeiro)
        sorted_tests = sorted(self.all_tests, key=lambda x: x['valid'], reverse=True)
        for test in sorted_tests:
            status_class = "valid" if test['valid'] else "invalid"
            status_label = "VÁLIDO" if test['valid'] else "INVÁLIDO"
            info = test.get('title') or test.get('error') or 'Sem informações'
            escaped_url = escape(test['url'], quote=True)
            escaped_info = escape(info)
            
            html += f'''
                        <tr class="link-row row-{status_class}">
                            <td><a href="{escaped_url}" target="_blank" class="link-url">{escaped_url}</a></td>
                            <td><span class="status-badge {status_class}">{status_label}</span></td>
                            <td>{escaped_info}</td>
                        </tr>
'''

        html += f'''
                    </tbody>
                </table>
            </div>
        </div>

        <!-- TAB FUZZING -->
        <div id="fuzz-tab" class="tab-content">
            <div class="fuzz-container">
                <div class="copy-banner">
                    <div class="tool-title">Comando Único de Fuzzing (Feroxbuster)</div>
                    <button class="btn btn-copy" onclick="copyFuzzCommands()">📋 Copiar Comando</button>
                </div>
                <p style="color: var(--text-secondary); margin-bottom: 20px;">
                    Comando único para execução imediata em todos os targets ativos. 
                    Otimizado com recursão, wordlists padrão e filtros de extensões.
                </p>
                <div class="terminal-box" id="fuzzCommands">
{fuzzing_content}
                </div>
            </div>
        </div>

        <footer>
            <p>Gerado em {datetime.now().strftime("%d/%m/%Y às %H:%M:%S")}</p>
            <p>Bird Nmap Web Validator &copy; 2024</p>
        </footer>
    </div>

    <div id="toast" class="toast">Conteúdo copiado!</div>

    <script>
        function openTab(tabId, btn) {{
            const contents = document.querySelectorAll('.tab-content');
            const buttons = document.querySelectorAll('.tab-btn');
            
            contents.forEach(c => c.classList.remove('active'));
            buttons.forEach(b => b.classList.remove('active'));
            
            document.getElementById(tabId).classList.add('active');
            btn.classList.add('active');
        }}

        function filterLinks(type, btn) {{
            const rows = document.querySelectorAll('.link-row');
            const buttons = document.querySelectorAll('.filter-group .btn');
            
            buttons.forEach(b => b.classList.remove('active'));
            btn.classList.add('active');
            
            rows.forEach(row => {{
                if (type === 'all') {{
                    row.style.display = 'table-row';
                }} else if (type === 'valid') {{
                    row.style.display = row.classList.contains('row-valid') ? 'table-row' : 'none';
                }} else if (type === 'invalid') {{
                    row.style.display = row.classList.contains('row-invalid') ? 'table-row' : 'none';
                }}
            }});
        }}

        function showToast(msg) {{
            const toast = document.getElementById('toast');
            toast.innerText = msg;
            toast.style.display = 'block';
            setTimeout(() => {{ toast.style.display = 'none'; }}, 2000);
        }}

        function copyLinks() {{
            const type = document.querySelector('.filter-group .btn.active').innerText.toLowerCase();
            const rows = document.querySelectorAll('.link-row');
            let links = [];
            
            rows.forEach(row => {{
                if (row.style.display !== 'none') {{
                    links.push(row.querySelector('.link-url').innerText);
                }}
            }});
            
            navigator.clipboard.writeText(links.join('\\n')).then(() => {{
                showToast(links.length + ' links copiados!');
            }});
        }}

        function copyFuzzCommands() {{
            const text = document.getElementById('fuzzCommands').innerText;
            navigator.clipboard.writeText(text).then(() => {{
                showToast('Comandos de fuzzing copiados!');
            }});
        }}
    </script>
</body>
</html>
'''
        
        # Salvar master index
        master_path = os.path.join(self.output_dir, 'index.html')
        with open(master_path, 'w', encoding='utf-8') as f:
            f.write(html)
        
        print(f"\n[+] Master index salvo em: {master_path}")
        return master_path
    
    def generate_reports(self):
        """Gera todos os relatórios (index por ativo + master)"""
        
        if not self.results:
            print("\n[!] Nenhuma página válida encontrada")

        # Gerar index para cada ativo
        for asset, results in self.results.items():
            asset_index = self.generate_asset_index(asset, results)
            print(f"[+] Index do ativo '{asset}' salvo")
        
        # Gerar master index
        master_path = self.generate_master_index()
        
        return master_path
    
    def close(self):
        """Fecha o WebDriver"""
        if self.driver:
            try:
                self.driver.quit()
            except WebDriverException as error:
                print(f"[!] Falha ao fechar o WebDriver: {error}")


def main():
    if len(sys.argv) < 2:
        print("[ERRO] O módulo Selenium incorporado não recebeu o arquivo de dados")
        print("Formato do arquivo: hostname|ip|porta (uma por linha)")
        sys.exit(1)
    
    data_file = sys.argv[1]
    
    if not os.path.exists(data_file):
        print(f"[ERRO] Arquivo não encontrado: {data_file}")
        sys.exit(1)
    
    # Ler dados
    with open(data_file, 'r', encoding='utf-8', errors='replace') as f:
        data_list = [line.strip() for line in f if line.strip() and '|' in line]
    
    if not data_list:
        print("[ERRO] Nenhum dado encontrado no arquivo")
        sys.exit(1)
    
    # Inicializar validador
    validator = SeleniumValidator()
    
    if not validator.init_driver():
        print("[ERRO] Não foi possível inicializar o WebDriver")
        print("[INFO] Instale Firefox ou Chrome com os respectivos drivers")
        sys.exit(1)
    
    try:
        # Validar dados
        validator.validate_data(data_list)
        
        # Gerar relatórios
        validator.generate_reports()
        
        # Estatísticas
        total_valid = sum(len(results) for results in validator.results.values())
        total_tested = len(validator.all_tests)
        print(f"\n[*] Resumo:")
        print(f"    - Ativos com páginas: {len(validator.results)}")
        print(f"    - Total de páginas: {total_valid}")
        print(f"    - URLs testadas: {total_tested}")
        print(f"    - URLs sem resposta: {total_tested - total_valid}")
        
    finally:
        validator.close()


if __name__ == '__main__':
    main()

BIRD_SELENIUM_VALIDATOR

    VALIDATOR_STATUS=$?
    if [[ $VALIDATOR_STATUS -ne 0 ]]; then
        echo -e "${RED}[ERRO]${NC} O validador Selenium terminou com código $VALIDATOR_STATUS."
        exit "$VALIDATOR_STATUS"
    fi
    
elif [[ "$MODE" == "--normal" ]]; then
    echo -e "${GREEN}[+]${NC} Iniciando validação normal (furtiva)..."
    echo ""

    if ! command -v curl &> /dev/null; then
        echo -e "${RED}[ERRO]${NC} curl não encontrado!"
        exit 1
    fi
    
    # Executar validador normal incorporado
    bash -s -- "$ALL_DATA_FILE" <<'BIRD_NORMAL_VALIDATOR'

#===============================================================================
# Bird Nmap Web Validator - Normal Mode
# Validação furtiva de URLs usando curl com headers de navegador real
# Versão 3.0 - Mantém 4xx (serviço existe), organizado por ativo
#===============================================================================

# Não usar set -e para permitir que o script continue mesmo com falhas

# Cores
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

# Arquivo de entrada (formato: hostname|ip|porta)
DATA_FILE="$1"

if [[ ! -f "$DATA_FILE" ]]; then
    echo -e "${RED}[ERRO]${NC} Arquivo de dados não encontrado: $DATA_FILE"
    exit 1
fi

# Arquivo de saída
OUTPUT_FILE="out-bird-nmap-web.txt"

# User Agents realistas
USER_AGENTS=(
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0"
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15"
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
)

# Função para obter User Agent aleatório
get_random_ua() {
    local idx=$((RANDOM % ${#USER_AGENTS[@]}))
    echo "${USER_AGENTS[$idx]}"
}

# Função para delay aleatório (simular comportamento humano)
random_delay() {
    local min_delay=1
    local max_delay=3
    local delay=$(awk -v min=$min_delay -v max=$max_delay 'BEGIN{srand(); print min + rand() * (max - min)}')
    sleep "$delay"
}

# Função para extrair título da página
extract_title() {
    local html="$1"
    echo "$html" | sed -n 's/.*<title[^>]*>\([^<]*\)<\/title>.*/\1/Ip' | head -1 | tr -d '\n\r' | sed 's/^[[:space:]]*//;s/[[:space:]]*$//'
}

# Função para extrair meta description
extract_description() {
    local html="$1"
    local desc=""
    
    desc=$(echo "$html" | sed -n 's/.*<meta[^>]*name="description"[^>]*content="\([^"]*\)".*/\1/Ip' | head -1)
    
    if [[ -z "$desc" ]]; then
        desc=$(echo "$html" | sed -n 's/.*<meta[^>]*content="\([^"]*\)"[^>]*name="description".*/\1/Ip' | head -1)
    fi
    
    if [[ -z "$desc" ]]; then
        desc=$(echo "$html" | sed -n 's/.*<meta[^>]*property="og:description"[^>]*content="\([^"]*\)".*/\1/Ip' | head -1)
    fi
    
    echo "$desc" | tr -d '\n\r' | sed 's/^[[:space:]]*//;s/[[:space:]]*$//'
}

# Função para extrair servidor
extract_server() {
    local headers="$1"
    echo "$headers" | grep -i "^server:" | head -1 | cut -d':' -f2- | tr -d '\r' | sed 's/^[[:space:]]*//;s/[[:space:]]*$//'
}

# Função para extrair tecnologias
detect_technologies() {
    local html="$1"
    local headers="$2"
    local techs=""
    
    if echo "$headers" | grep -qi "x-powered-by:.*php"; then
        techs="${techs}PHP, "
    fi
    if echo "$headers" | grep -qi "x-powered-by:.*asp"; then
        techs="${techs}ASP.NET, "
    fi
    if echo "$headers" | grep -qi "x-powered-by:.*express"; then
        techs="${techs}Node.js/Express, "
    fi
    
    if echo "$html" | grep -qi "wp-content\|wordpress"; then
        techs="${techs}WordPress, "
    fi
    if echo "$html" | grep -qi "drupal"; then
        techs="${techs}Drupal, "
    fi
    if echo "$html" | grep -qi "joomla"; then
        techs="${techs}Joomla, "
    fi
    if echo "$html" | grep -qi "react"; then
        techs="${techs}React, "
    fi
    if echo "$html" | grep -qi "angular"; then
        techs="${techs}Angular, "
    fi
    if echo "$html" | grep -qi "vue\.js\|vuejs"; then
        techs="${techs}Vue.js, "
    fi
    if echo "$html" | grep -qi "bootstrap"; then
        techs="${techs}Bootstrap, "
    fi
    if echo "$html" | grep -qi "jquery"; then
        techs="${techs}jQuery, "
    fi
    
    echo "$techs" | sed 's/, $//'
}

# Função para validar uma URL
# Retorna 0 se a URL responde (mesmo 4xx), 1 se timeout/conexão falhou
# Se válida, imprime os dados para captura
validate_url() {
    local url="$1"
    local ua
    ua=$(get_random_ua)
    
    echo -e "${YELLOW}[*]${NC} Testando: $url" >&2
    
    # Arquivo temporário para o corpo da resposta
    local tmp_body tmp_headers
    tmp_body=$(mktemp) || return 1
    tmp_headers=$(mktemp) || {
        rm -f -- "$tmp_body"
        return 1
    }
    
    # Fazer requisição com curl
    local curl_output
    curl_output=$(curl -s -k -L \
        --max-time 10 \
        --connect-timeout 5 \
        -w "%{http_code}|%{url_effective}|%{content_type}" \
        -H "User-Agent: $ua" \
        -H "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8" \
        -H "Accept-Language: en-US,en;q=0.9,pt-BR;q=0.8" \
        -H "Connection: keep-alive" \
        -H "Upgrade-Insecure-Requests: 1" \
        -D "$tmp_headers" \
        -o "$tmp_body" \
        "$url" 2>/dev/null) || true
    
    # Extrair informações do write-out
    local status_code effective_url redirect_url content_type
    status_code=$(echo "$curl_output" | cut -d'|' -f1)
    effective_url=$(echo "$curl_output" | cut -d'|' -f2)
    content_type=$(echo "$curl_output" | cut -d'|' -f3)
    redirect_url=""
    if [[ -n "$effective_url" && "$effective_url" != "$url" ]]; then
        redirect_url="$effective_url"
    fi
    
    # Verificar se conexão falhou (status 000 = timeout/conexão falhou)
    # NÃO salvar neste caso
    if [[ -z "$status_code" ]] || [[ "$status_code" == "000" ]]; then
        echo -e "${RED}[-]${NC} Sem resposta (não salvo): $url" >&2
        rm -f -- "$tmp_body" "$tmp_headers"
        return 1
    fi
    
    # Verificar se é número válido
    if [[ ! "$status_code" =~ ^[0-9]+$ ]]; then
        echo -e "${RED}[-]${NC} Resposta inválida (não salvo): $url" >&2
        rm -f -- "$tmp_body" "$tmp_headers"
        return 1
    fi
    
    # 4xx e 5xx são VÁLIDOS - significa que o serviço existe!
    local status_note=""
    if [[ "$status_code" -ge 400 ]]; then
        status_note=" (serviço existe)"
    fi
    
    # Ler headers e body
    local headers body
    headers=$(cat "$tmp_headers" 2>/dev/null || echo "")
    body=$(cat "$tmp_body" 2>/dev/null || echo "")
    
    # Extrair informações
    local title description server technologies
    title=$(extract_title "$body")
    description=$(extract_description "$body")
    server=$(extract_server "$headers")
    technologies=$(detect_technologies "$body" "$headers")

    # Impede tabs do conteúdo remoto de quebrarem o formato interno do relatório.
    server=$(printf '%s' "$server" | tr '\t\r\n' '   ')
    content_type=$(printf '%s' "$content_type" | tr '\t\r\n' '   ')
    title=$(printf '%s' "$title" | tr '\t\r\n' '   ')
    description=$(printf '%s' "$description" | tr '\t\r\n' '   ')
    technologies=$(printf '%s' "$technologies" | tr '\t\r\n' '   ')
    redirect_url=$(printf '%s' "$redirect_url" | tr '\t\r\n' '   ')
    
    echo -e "${GREEN}[+]${NC} Válida: $url (HTTP $status_code${status_note})" >&2
    
    # Retornar dados separados por tabulação para captura
    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
        "$url" "$status_code" "${server:-Não identificado}" "$content_type" \
        "${title:-Sem título}" "${description:-Sem descrição}" \
        "${technologies:-Nenhuma}" "$redirect_url"

    rm -f -- "$tmp_body" "$tmp_headers"
    
    return 0
}

#===============================================================================
# Main
#===============================================================================

echo -e "${BLUE}[INFO]${NC} Iniciando validação furtiva..."
echo -e "${BLUE}[INFO]${NC} Arquivo de saída: $OUTPUT_FILE"
echo ""

# Limpar arquivo de saída
> "$OUTPUT_FILE"

# Adicionar cabeçalho
{
    echo "╔══════════════════════════════════════════════════════════════════════════════╗"
    echo "║                        BIRD NMAP WEB VALIDATOR                               ║"
    echo "║                      Relatório de Validação de URLs                          ║"
    echo "╠══════════════════════════════════════════════════════════════════════════════╣"
    echo "║ Data: $(date '+%d/%m/%Y %H:%M:%S')"
    echo "║ Modo: Normal (Furtivo)"
    echo "║ Nota: Códigos 4xx/5xx indicam que o serviço existe"
    echo "╚══════════════════════════════════════════════════════════════════════════════╝"
    echo ""
} > "$OUTPUT_FILE"

# Agrupar dados por ativo
declare -A ASSET_DATA

while IFS= read -r line; do
    [[ -z "$line" ]] && continue
    [[ ! "$line" == *"|"* ]] && continue
    
    hostname=$(echo "$line" | cut -d'|' -f1)
    ip=$(echo "$line" | cut -d'|' -f2)
    port=$(echo "$line" | cut -d'|' -f3)
    
    asset="${hostname:-$ip}"
    ASSET_DATA["$asset"]+="${line}"$'\n'
    
done < "$DATA_FILE"

# Contadores
total_assets=0
total_valid=0
total_invalid=0

# Processar cada ativo
for asset in "${!ASSET_DATA[@]}"; do
    echo -e "\n${CYAN}[*]${NC} Processando ativo: ${CYAN}$asset${NC}"
    
    valid_results=""
    asset_valid=0
    asset_invalid=0
    
    declare -A urls_seen
    
    while IFS= read -r line; do
        [[ -z "$line" ]] && continue
        
        hostname=$(echo "$line" | cut -d'|' -f1)
        ip=$(echo "$line" | cut -d'|' -f2)
        port=$(echo "$line" | cut -d'|' -f3)
        
        target="${hostname:-$ip}"
        
        if [[ "$port" == "80" ]]; then
            urls=("http://${target}")
        elif [[ "$port" == "443" ]]; then
            urls=("https://${target}")
        else
            urls=("http://${target}:${port}" "https://${target}:${port}")
        fi
        
        for url in "${urls[@]}"; do
            if [[ -n "${urls_seen[$url]}" ]]; then
                continue
            fi
            urls_seen["$url"]=1
            
            result=$(validate_url "$url")
            if [[ $? -eq 0 ]] && [[ -n "$result" ]]; then
                valid_results+="${result}"$'\n'
                asset_valid=$((asset_valid + 1))
                total_valid=$((total_valid + 1))
            else
                asset_invalid=$((asset_invalid + 1))
                total_invalid=$((total_invalid + 1))
            fi
            
            random_delay
        done
        
    done <<< "${ASSET_DATA[$asset]}"
    
    unset urls_seen
    declare -A urls_seen
    
    # Só escrever se há resultados válidos
    if [[ -n "$valid_results" ]]; then
        total_assets=$((total_assets + 1))
        
        {
            echo ""
            echo "╔══════════════════════════════════════════════════════════════════════════════╗"
            echo "║ ATIVO: $asset"
            echo "║ Páginas encontradas: $asset_valid"
            echo "╚══════════════════════════════════════════════════════════════════════════════╝"
            echo ""
            
            while IFS=$'\t' read -r url status server content_type title description technologies redirect; do
                [[ -z "$url" ]] && continue
                
                status_note=""
                if [[ "$status" -ge 400 ]]; then
                    status_note=" ⚠️ (serviço existe, retorna erro HTTP)"
                fi
                
                echo "--------------------------------------------------------------------------------"
                echo "URL: $url"
                echo "Status: $status$status_note"
                echo "Server: $server"
                echo "Content-Type: $content_type"
                echo "Título: $title"
                echo "Descrição: $description"
                echo "Tecnologias: $technologies"
                if [[ -n "$redirect" ]]; then
                    echo "Redirecionado para: $redirect"
                fi
                echo "--------------------------------------------------------------------------------"
                echo ""
            done <<< "$valid_results"
            
        } >> "$OUTPUT_FILE"
    fi
    
done

# Adicionar resumo
{
    echo ""
    echo "╔══════════════════════════════════════════════════════════════════════════════╗"
    echo "║                               RESUMO                                         ║"
    echo "╠══════════════════════════════════════════════════════════════════════════════╣"
    echo "║ Ativos com páginas: $total_assets"
    echo "║ Total de URLs respondendo: $total_valid"
    echo "║ Total sem resposta: $total_invalid"
    echo "╚══════════════════════════════════════════════════════════════════════════════╝"
} >> "$OUTPUT_FILE"

echo ""
echo -e "${GREEN}[✓]${NC} Validação concluída!"
echo -e "${BLUE}[INFO]${NC} Resultados salvos em: $OUTPUT_FILE"
echo ""
echo -e "${YELLOW}[*]${NC} Resumo:"
echo "    - Ativos com páginas: $total_assets"
echo "    - URLs respondendo: $total_valid"
echo "    - URLs sem resposta: $total_invalid"
BIRD_NORMAL_VALIDATOR

    VALIDATOR_STATUS=$?
    if [[ $VALIDATOR_STATUS -ne 0 ]]; then
        echo -e "${RED}[ERRO]${NC} O validador normal terminou com código $VALIDATOR_STATUS."
        exit "$VALIDATOR_STATUS"
    fi
    
else
    echo -e "${RED}[ERRO]${NC} Modo inválido: $MODE"
    echo "Use --selenium ou --normal"
    exit 1
fi

echo ""
echo -e "${GREEN}[✓]${NC} Validação concluída!"
