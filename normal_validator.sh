#!/bin/bash

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
    local ua=$(get_random_ua)
    
    echo -e "${YELLOW}[*]${NC} Testando: $url" >&2
    
    # Arquivo temporário para o corpo da resposta
    local tmp_body=$(mktemp)
    local tmp_headers=$(mktemp)
    trap "rm -f $tmp_body $tmp_headers" RETURN
    
    # Fazer requisição com curl
    local curl_output
    curl_output=$(curl -s -k -L \
        --max-time 10 \
        --connect-timeout 5 \
        -w "%{http_code}|%{redirect_url}|%{content_type}" \
        -H "User-Agent: $ua" \
        -H "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8" \
        -H "Accept-Language: en-US,en;q=0.9,pt-BR;q=0.8" \
        -H "Connection: keep-alive" \
        -H "Upgrade-Insecure-Requests: 1" \
        -D "$tmp_headers" \
        -o "$tmp_body" \
        "$url" 2>/dev/null) || true
    
    # Extrair informações do write-out
    local status_code=$(echo "$curl_output" | cut -d'|' -f1)
    local redirect_url=$(echo "$curl_output" | cut -d'|' -f2)
    local content_type=$(echo "$curl_output" | cut -d'|' -f3)
    
    # Verificar se conexão falhou (status 000 = timeout/conexão falhou)
    # NÃO salvar neste caso
    if [[ -z "$status_code" ]] || [[ "$status_code" == "000" ]]; then
        echo -e "${RED}[-]${NC} Sem resposta (não salvo): $url" >&2
        return 1
    fi
    
    # Verificar se é número válido
    if [[ ! "$status_code" =~ ^[0-9]+$ ]]; then
        echo -e "${RED}[-]${NC} Resposta inválida (não salvo): $url" >&2
        return 1
    fi
    
    # 4xx e 5xx são VÁLIDOS - significa que o serviço existe!
    local status_note=""
    if [[ "$status_code" -ge 400 ]]; then
        status_note=" (serviço existe)"
    fi
    
    # Ler headers e body
    local headers=$(cat "$tmp_headers" 2>/dev/null || echo "")
    local body=$(cat "$tmp_body" 2>/dev/null || echo "")
    
    # Extrair informações
    local title=$(extract_title "$body")
    local description=$(extract_description "$body")
    local server=$(extract_server "$headers")
    local technologies=$(detect_technologies "$body" "$headers")
    
    echo -e "${GREEN}[+]${NC} Válida: $url (HTTP $status_code${status_note})" >&2
    
    # Retornar dados separados por tabulação para captura
    echo -e "${url}\t${status_code}\t${server:-Não identificado}\t${content_type}\t${title:-Sem título}\t${description:-Sem descrição}\t${technologies:-Nenhuma}\t${redirect_url}"
    
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
