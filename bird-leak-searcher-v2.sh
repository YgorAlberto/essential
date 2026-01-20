#!/bin/bash

# Verifica se o termo foi passado como argumento
if [ $# -ne 1 ]; then
    echo "Uso: $0 <termo_procurado>"
    exit 1
fi

# Variáveis
SEARCH_TERM="$1"
BASE_DIR="/media/unknown"
OUTPUT_DIR="/home/unknown/Desktop/LEAK-LEAKED/${SEARCH_TERM}"
THREADS=8

# Criar diretório de saída se não existir
mkdir -p "$OUTPUT_DIR"

echo "Iniciando busca pelo termo: '$SEARCH_TERM'"
echo "Resultados serão salvos em: $OUTPUT_DIR"

# Função para realizar a busca em cada disco
search_in_disk() {
    local DISK_PATH="$1"
    local DISK_NAME=$(basename "$DISK_PATH")
    local OUTPUT_FILE="$OUTPUT_DIR/LEAK-${SEARCH_TERM}-${DISK_NAME}.txt"
    local TIME_FILE="$OUTPUT_DIR/TIME-${SEARCH_TERM}-${DISK_NAME}.log"

    START_TIME=$(date +%s)
    START_DATE=$(date '+%Y-%m-%d %H:%M:%S')

    echo "Pesquisando no disco: $DISK_NAME..."

    rg -INia --threads "$THREADS" "$SEARCH_TERM" "$DISK_PATH" > "$OUTPUT_FILE" 2>/dev/null

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
    } > "$TIME_FILE"

    echo "Finalizado: $DISK_NAME (Duração: $MINUTES min $SECONDS seg)"
}

# Percorre os discos e inicia buscas em paralelo
for DISK in "$BASE_DIR"/*; do
    if [ -d "$DISK" ]; then
        search_in_disk "$DISK" &
    fi
done

# Espera todas as buscas terminarem
wait

echo "Busca concluída! MUITO RAPIDO? INSTALE O RG... apt install ripgrep"
