#!/bin/bash
# Exemplos:
#   bird-leak-searcher-v3.sh "termo"
#   bird-leak-searcher-v3.sh "termo1|termo2|termo3"
#FERRAMENTA DE PROCURA POR DADOS DENTRO DE DISCOS INFORMADOS NAS VARIAVEIS
# Verifica se o padrão foi passado como argumento
if [ $# -ne 1 ]; then
    echo "Uso: $0 'termo1|termo2|termo3'"
    exit 1
fi

# Variáveis
SEARCH_PATTERN="$1"
BASE_DIR="${BASE_DIR:-/media/unknown}"
OUTPUT_ROOT="${OUTPUT_ROOT:-/home/unknown/Desktop/LEAK-LEAKED}"
THREADS="${THREADS:-8}"

if [ -z "$SEARCH_PATTERN" ]; then
    echo "Erro: informe ao menos um termo para pesquisa."
    exit 1
fi

# Valida a expressão antes de iniciar todas as buscas. O código 1 significa
# apenas "nenhuma ocorrência"; o código 2 indica uma expressão inválida.
grep -E -- "$SEARCH_PATTERN" /dev/null >/dev/null 2>&1
REGEX_STATUS=$?
if [ "$REGEX_STATUS" -eq 2 ]; then
    echo "Erro: expressão regular inválida: $SEARCH_PATTERN"
    exit 1
fi

# Evita que caracteres do regex (/, |, *, espaços...) quebrem os nomes dos
# diretórios e relatórios. O padrão original continua sendo usado na busca.
SEARCH_LABEL=$(printf '%s' "$SEARCH_PATTERN" | sed 's/[^[:alnum:]._-]/_/g' | cut -c1-120)
[ -n "$SEARCH_LABEL" ] || SEARCH_LABEL="pesquisa"
OUTPUT_DIR="${OUTPUT_ROOT}/${SEARCH_LABEL}"

if command -v rg >/dev/null 2>&1; then
    SEARCH_ENGINE="rg"
else
    SEARCH_ENGINE="grep"
    echo "Aviso: ripgrep (rg) não encontrado; usando grep -E como fallback."
fi

# Criar diretório de saída se não existir
mkdir -p "$OUTPUT_DIR"

echo "Iniciando busca pelo padrão: '$SEARCH_PATTERN'"
echo "Resultados serão salvos em: $OUTPUT_DIR"

# Função para realizar a busca em cada disco
search_in_disk() {
    local DISK_PATH="$1"
    local DISK_NAME
    local OUTPUT_FILE
    local TIME_FILE
    local ERROR_FILE
    local SEARCH_STATUS
    local START_TIME START_DATE END_TIME END_DATE DURATION MINUTES SECONDS

    DISK_NAME=$(basename "$DISK_PATH")
    OUTPUT_FILE="$OUTPUT_DIR/LEAK-${SEARCH_LABEL}-${DISK_NAME}.txt"
    TIME_FILE="$OUTPUT_DIR/TIME-${SEARCH_LABEL}-${DISK_NAME}.log"
    ERROR_FILE="$OUTPUT_DIR/ERROR-${SEARCH_LABEL}-${DISK_NAME}.log"

    START_TIME=$(date +%s)
    START_DATE=$(date '+%Y-%m-%d %H:%M:%S')

    echo "Pesquisando no disco: $DISK_NAME..."

    if [ "$SEARCH_ENGINE" = "rg" ]; then
        # O rg já usa expressões regulares por padrão. --regexp evita que um
        # padrão iniciado por hífen seja confundido com uma opção.
        rg --ignore-case --text --line-number --with-filename \
            --hidden --no-ignore --no-heading --color never --threads "$THREADS" \
            --regexp "$SEARCH_PATTERN" "$DISK_PATH" \
            >> "$OUTPUT_FILE" 2> "$ERROR_FILE"
        SEARCH_STATUS=$?
    else
        grep -Erina --binary-files=text -- "$SEARCH_PATTERN" "$DISK_PATH" \
            >> "$OUTPUT_FILE" 2> "$ERROR_FILE"
        SEARCH_STATUS=$?
    fi

    END_TIME=$(date +%s)
    END_DATE=$(date '+%Y-%m-%d %H:%M:%S')
    DURATION=$((END_TIME - START_TIME))
    MINUTES=$((DURATION / 60))
    SECONDS=$((DURATION % 60))

    # Salvar informações de tempo
    {
        echo "Início: $START_DATE"
        echo "Fim: $END_DATE"
        echo "Duração: $MINUTES min $SECONDS seg"
        echo "Mecanismo: $SEARCH_ENGINE"
        echo "Padrão: $SEARCH_PATTERN"
        echo "Status da busca: $SEARCH_STATUS"
    } > "$TIME_FILE"

    # rg/grep retornam 1 quando simplesmente não encontram ocorrências.
    if [ "$SEARCH_STATUS" -le 1 ]; then
        [ -s "$ERROR_FILE" ] || rm -f -- "$ERROR_FILE"
        echo "Finalizado: $DISK_NAME (Duração: $MINUTES min $SECONDS seg)"
    else
        echo "Erro ao pesquisar $DISK_NAME (código $SEARCH_STATUS). Detalhes: $ERROR_FILE"
    fi
}

# Percorre os discos e inicia buscas em paralelo
for DISK in "$BASE_DIR"/*; do
    if [ -d "$DISK" ]; then
        search_in_disk "$DISK" &
    fi
done

# Espera todas as buscas terminarem
wait

if [ "$SEARCH_ENGINE" = "rg" ]; then
    echo "Busca concluída com ripgrep!"
else
    echo "Busca concluída com grep. Para maior velocidade, instale: apt install ripgrep"
fi
