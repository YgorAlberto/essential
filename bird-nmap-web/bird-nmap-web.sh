#!/bin/bash

#===============================================================================
# Bird Nmap Web Validator
# Valida portas web descobertas pelo nmap
#
# Uso:
#   ./bird-nmap-web.sh <nmap-output-pattern> [--selenium|--normal]
#   ./bird-nmap-web.sh --ports <arquivo-portas> --target <arquivo-alvos> [--selenium|--normal]
#   ./bird-nmap-web.sh -p 80,443,8080 -t example.com [--selenium|--normal]
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
    exit 0
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

# Diretório do script
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Variáveis de configuração
FILE_PATTERN=""
PORTS_FILE=""
PORTS_INLINE=""
TARGET_FILE=""
TARGET_INLINE=""
MODE="--selenium"

# Parse de argumentos
while [[ $# -gt 0 ]]; do
    case "$1" in
        --ports)
            PORTS_FILE="$2"
            shift 2
            ;;
        -p)
            PORTS_INLINE="$2"
            shift 2
            ;;
        --target)
            TARGET_FILE="$2"
            shift 2
            ;;
        -t)
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
            # Se não é um argumento conhecido, assume que é o padrão de arquivo
            if [[ -z "$FILE_PATTERN" && -z "$PORTS_FILE" && -z "$PORTS_INLINE" ]]; then
                FILE_PATTERN="$1"
            fi
            shift
            ;;
    esac
done

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
    
    while IFS= read -r line; do
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
            local port=$(echo "$line" | grep -oE "^[0-9]+")
            if [[ -n "$current_host" && -n "$port" ]]; then
                echo "${current_hostname}|${current_host}|${port}"
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
    local in_host=0
    
    while IFS= read -r line; do
        # Início de host
        if echo "$line" | grep -qE '<host '; then
            in_host=1
            current_host=""
            current_hostname=""
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
        if [[ $in_host -eq 1 ]] && echo "$line" | grep -qE '<port.*protocol="tcp"'; then
            local port=$(echo "$line" | grep -oE 'portid="[0-9]+"' | cut -d'"' -f2)
            if echo "$line" | grep -qE 'state="(open|filtered)"'; then
                if [[ -n "$current_host" && -n "$port" ]]; then
                    local hostname="${current_hostname:-$current_host}"
                    echo "${hostname}|${current_host}|${port}"
                fi
            fi
        fi
        
        # Fim de host
        if echo "$line" | grep -qE '</host>'; then
            in_host=0
        fi
    done < "$file"
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
            while IFS= read -r line; do
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
    
    echo -e "${GREEN}[+]${NC} Portas carregadas: ${ports[*]}" >&2
    
    # Ler targets
    local targets=()
    
    if [[ "$target_type" == "file" ]]; then
        if [[ -f "$target_source" ]]; then
            while IFS= read -r line; do
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
    
    echo -e "${GREEN}[+]${NC} Targets carregados: ${#targets[@]}" >&2
    
    # Gerar combinações hostname|ip|porta
    for t in "${targets[@]}"; do
        for p in "${ports[@]}"; do
            echo "${t}|${t}|${p}"
        done
    done
}

#===============================================================================
# Processar arquivos
#===============================================================================

# Criar diretório temporário para dados processados
TEMP_DIR=$(mktemp -d)
trap "rm -rf $TEMP_DIR" EXIT

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
    
    generate_from_ports_target "$PORTS_SOURCE" "$PORTS_TYPE" "$TARGET_SOURCE" "$TARGET_TYPE" >> "$ALL_DATA_FILE"
    
    if [[ ! -s "$ALL_DATA_FILE" ]]; then
        echo -e "${RED}[ERRO]${NC} Falha ao gerar dados de portas/targets"
        exit 1
    fi
    
elif [[ -n "$PORTS_SOURCE" && -z "$TARGET_SOURCE" ]]; then
    echo -e "${RED}[ERRO]${NC} Portas especificadas mas falta o target (--target ou -t)"
    show_help
    
elif [[ -z "$PORTS_SOURCE" && -n "$TARGET_SOURCE" ]]; then
    echo -e "${RED}[ERRO]${NC} Target especificado mas faltam as portas (--ports ou -p)"
    show_help
    
elif [[ -n "$FILE_PATTERN" ]]; then
    # Modo arquivo nmap
    echo -e "${BLUE}[INFO]${NC} Padrão de arquivos: $FILE_PATTERN"
    
    # Expandir glob pattern
    shopt -s nullglob
    FILES=($FILE_PATTERN)
    shopt -u nullglob
    
    if [[ ${#FILES[@]} -eq 0 ]]; then
        echo -e "${RED}[ERRO]${NC} Nenhum arquivo encontrado com o padrão: $FILE_PATTERN"
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

# Verificar se há dados
LINE_COUNT=$(wc -l < "$ALL_DATA_FILE")

if [[ $LINE_COUNT -eq 0 ]]; then
    echo -e "${RED}[!]${NC} Nenhuma porta encontrada para validar."
    echo -e "${YELLOW}[INFO]${NC} Verifique se o arquivo nmap contém portas abertas ou filtradas."
    exit 1
fi

echo ""
echo -e "${GREEN}[+]${NC} Total de entradas para validar: $LINE_COUNT"
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
    
    # Executar validador Selenium
    python3 "${SCRIPT_DIR}/selenium_validator.py" "$ALL_DATA_FILE"
    
elif [[ "$MODE" == "--normal" ]]; then
    echo -e "${GREEN}[+]${NC} Iniciando validação normal (furtiva)..."
    echo ""
    
    # Executar validador normal
    bash "${SCRIPT_DIR}/normal_validator.sh" "$ALL_DATA_FILE"
    
else
    echo -e "${RED}[ERRO]${NC} Modo inválido: $MODE"
    echo "Use --selenium ou --normal"
    exit 1
fi

echo ""
echo -e "${GREEN}[✓]${NC} Validação concluída!"
