#!/bin/bash

# Bird Leak Searcher v3
# Exemplos:
#   bird-leak-searcher-v3.sh "termo"
#   bird-leak-searcher-v3.sh "termo1|termo2|termo3"
#   bird-leak-searcher-v3.sh -vars "termo1|termo2" -threads 4
#   bird-leak-searcher-v3.sh -vars "termo1|termo2" -force
#
# Variáveis opcionais:
#   BASE_DIR=/media/unknown       Diretório que contém os discos
#   OUTPUT_ROOT=/caminho/saida    Raiz dos resultados
#   THREADS=8                     Threads internas de CADA processo rg

BASE_DIR="${BASE_DIR:-/media/unknown}"
OUTPUT_ROOT="${OUTPUT_ROOT:-/home/unknown/Desktop/LEAK-LEAKED}"
THREADS="${THREADS:-8}"
SEARCH_PATTERN=""
FORCE_RESCAN=0

show_usage() {
    echo "Uso:"
    echo "  $0 'termo1|termo2|termo3'"
    echo "  $0 -vars 'termo1|termo2|termo3' [-threads 8] [-force]"
}

while [ "$#" -gt 0 ]; do
    case "$1" in
        -vars|--vars)
            if [ "$#" -lt 2 ] || [ -n "$SEARCH_PATTERN" ]; then
                echo "Erro: -vars requer um único padrão de pesquisa."
                show_usage
                exit 1
            fi
            SEARCH_PATTERN="$2"
            shift 2
            ;;
        -threads|--threads|-t)
            if [ "$#" -lt 2 ]; then
                echo "Erro: $1 requer a quantidade de threads."
                show_usage
                exit 1
            fi
            THREADS="$2"
            shift 2
            ;;
        -force|--force)
            FORCE_RESCAN=1
            shift
            ;;
        -h|--help)
            show_usage
            exit 0
            ;;
        --)
            shift
            if [ "$#" -ne 1 ] || [ -n "$SEARCH_PATTERN" ]; then
                show_usage
                exit 1
            fi
            SEARCH_PATTERN="$1"
            shift
            ;;
        -*)
            echo "Erro: opção desconhecida: $1"
            show_usage
            exit 1
            ;;
        *)
            if [ -n "$SEARCH_PATTERN" ]; then
                echo "Erro: informe o padrão de pesquisa apenas uma vez."
                show_usage
                exit 1
            fi
            SEARCH_PATTERN="$1"
            shift
            ;;
    esac
done

if [ -z "$SEARCH_PATTERN" ]; then
    echo "Erro: informe ao menos um termo para pesquisa."
    exit 1
fi

if ! [[ "$THREADS" =~ ^[1-9][0-9]*$ ]]; then
    echo "Erro: THREADS deve ser um número inteiro maior que zero."
    exit 1
fi

if [ ! -d "$BASE_DIR" ]; then
    echo "Erro: diretório base não encontrado: $BASE_DIR"
    exit 1
fi

if ! mkdir -p "$OUTPUT_ROOT"; then
    echo "Erro: não foi possível criar o diretório de saída: $OUTPUT_ROOT"
    exit 1
fi

if command -v rg >/dev/null 2>&1; then
    SEARCH_ENGINE="rg"
else
    SEARCH_ENGINE="grep"
    echo "Aviso: ripgrep (rg) não encontrado; usando grep -E como fallback."
fi

# O caractere | separa os termos para organização dos resultados. A busca nos
# discos usa uma única expressão combinada, sem criar um rg para cada termo.
IFS='|' read -r -a RAW_SEARCH_TERMS <<< "$SEARCH_PATTERN"
SEARCH_TERMS=()
declare -A SEEN_TERMS

for RAW_TERM in "${RAW_SEARCH_TERMS[@]}"; do
    TERM=$(printf '%s' "$RAW_TERM" | sed 's/^[[:space:]]*//; s/[[:space:]]*$//')

    if [ -z "$TERM" ]; then
        echo "Erro: existe um termo vazio em: $SEARCH_PATTERN"
        exit 1
    fi

    # O status 1 significa apenas que /dev/null não possui correspondência;
    # status 2 indica uma expressão regular inválida.
    grep -E -- "$TERM" /dev/null >/dev/null 2>&1
    REGEX_STATUS=$?
    if [ "$REGEX_STATUS" -eq 2 ]; then
        echo "Erro: expressão regular inválida: $TERM"
        exit 1
    fi

    if [ -n "${SEEN_TERMS[$TERM]+presente}" ]; then
        echo "Aviso: termo repetido ignorado: $TERM"
        continue
    fi

    SEEN_TERMS["$TERM"]=1
    SEARCH_TERMS+=("$TERM")
done

if [ "${#SEARCH_TERMS[@]}" -eq 0 ]; then
    echo "Erro: nenhum termo válido foi informado."
    exit 1
fi

# Carrega todos os discos antes de iniciar a busca.
shopt -s nullglob
DISK_CANDIDATES=("$BASE_DIR"/*)
shopt -u nullglob

DISKS=()
for DISK in "${DISK_CANDIDATES[@]}"; do
    [ -d "$DISK" ] && DISKS+=("$DISK")
done

if [ "${#DISKS[@]}" -eq 0 ]; then
    echo "Erro: nenhum disco/diretório foi encontrado dentro de $BASE_DIR."
    exit 1
fi

# Prepara uma pasta separada por termo. Quando dois regex diferentes geram o
# mesmo nome sanitizado, um sufixo garante que continuem separados.
RUN_TERMS=()
RUN_LABELS=()
RUN_OUTPUT_DIRS=()
declare -A USED_LABELS

for CURRENT_TERM in "${SEARCH_TERMS[@]}"; do
    SEARCH_LABEL=$(printf '%s' "$CURRENT_TERM" | sed 's/[^[:alnum:]._-]/_/g' | cut -c1-120)
    [ -n "$SEARCH_LABEL" ] || SEARCH_LABEL="pesquisa"

    ORIGINAL_LABEL="$SEARCH_LABEL"
    LABEL_SUFFIX=2
    while [ -n "${USED_LABELS[$SEARCH_LABEL]+presente}" ]; do
        SEARCH_LABEL="${ORIGINAL_LABEL}_${LABEL_SUFFIX}"
        LABEL_SUFFIX=$((LABEL_SUFFIX + 1))
    done
    USED_LABELS["$SEARCH_LABEL"]=1

    OUTPUT_DIR="${OUTPUT_ROOT}/${SEARCH_LABEL}"
    if ! mkdir -p "$OUTPUT_DIR"; then
        echo "[$CURRENT_TERM] ERRO ao criar a pasta: $OUTPUT_DIR" >&2
        continue
    fi

    RUN_TERMS+=("$CURRENT_TERM")
    RUN_LABELS+=("$SEARCH_LABEL")
    RUN_OUTPUT_DIRS+=("$OUTPUT_DIR")

    echo "Termo: '$CURRENT_TERM'"
    echo "Pasta: $OUTPUT_DIR"
done

if [ "${#RUN_TERMS[@]}" -eq 0 ]; then
    echo "Erro: nenhuma pasta de pesquisa pôde ser preparada." >&2
    exit 1
fi

# Reconstrói o padrão com os termos validados e sem duplicações. Este é o único
# padrão enviado ao rg/grep em cada disco.
COMBINED_PATTERN=""
for CURRENT_TERM in "${RUN_TERMS[@]}"; do
    if [ -z "$COMBINED_PATTERN" ]; then
        COMBINED_PATTERN="$CURRENT_TERM"
    else
        COMBINED_PATTERN="${COMBINED_PATTERN}|${CURRENT_TERM}"
    fi
done

hash_text() {
    local VALUE="$1"
    if command -v sha256sum >/dev/null 2>&1; then
        printf '%s' "$VALUE" | sha256sum | awk '{print substr($1, 1, 20)}'
    else
        printf '%s' "$VALUE" | cksum | awk '{print $1}'
    fi
}

SEARCH_ID=$(hash_text "$COMBINED_PATTERN")

state_file_path() {
    local TERM_INDEX="$1"
    local DISK_PATH="$2"
    local DISK_NAME DISK_LABEL DISK_ID

    DISK_NAME=$(basename "$DISK_PATH")
    DISK_LABEL=$(printf '%s' "$DISK_NAME" | sed 's/[^[:alnum:]._-]/_/g' | cut -c1-80)
    [ -n "$DISK_LABEL" ] || DISK_LABEL="disco"
    DISK_ID=$(hash_text "$DISK_PATH")
    printf '%s/.bird-leak-complete-%s-%s.state\n' \
        "${RUN_OUTPUT_DIRS[$TERM_INDEX]}" "$DISK_LABEL" "$DISK_ID"
}

mark_disk_complete() {
    local DISK_PATH="$1"
    local DISK_NAME TERM_INDEX STATE_FILE TEMP_STATE MARK_ERRORS=0

    DISK_NAME=$(basename "$DISK_PATH")
    for TERM_INDEX in "${!RUN_TERMS[@]}"; do
        STATE_FILE=$(state_file_path "$TERM_INDEX" "$DISK_PATH")
        TEMP_STATE="${STATE_FILE}.tmp.$$"

        if {
            printf 'status=complete\n'
            printf 'search_id=%s\n' "$SEARCH_ID"
            printf 'term=%s\n' "${RUN_TERMS[$TERM_INDEX]}"
            printf 'disk=%s\n' "$DISK_NAME"
            printf 'completed_at=%s\n' "$(date '+%Y-%m-%d %H:%M:%S')"
        } > "$TEMP_STATE" && mv -f -- "$TEMP_STATE" "$STATE_FILE"; then
            :
        else
            echo "[$DISK_NAME] ERRO ao registrar conclusão em: $STATE_FILE" >&2
            rm -f -- "$TEMP_STATE"
            MARK_ERRORS=$((MARK_ERRORS + 1))
        fi
    done

    [ "$MARK_ERRORS" -eq 0 ]
}

state_markers_are_complete() {
    local DISK_PATH="$1"
    local TERM_INDEX STATE_FILE

    for TERM_INDEX in "${!RUN_TERMS[@]}"; do
        STATE_FILE=$(state_file_path "$TERM_INDEX" "$DISK_PATH")
        if [ ! -f "$STATE_FILE" ] || \
           ! grep -Fqx 'status=complete' "$STATE_FILE" 2>/dev/null || \
           ! grep -Fqx "search_id=$SEARCH_ID" "$STATE_FILE" 2>/dev/null; then
            return 1
        fi
    done
    return 0
}

time_log_is_complete() {
    local TIME_FILE="$1"
    local EXPECTED_TERM="$2"

    [ -f "$TIME_FILE" ] || return 1
    awk -v expected_term="$EXPECTED_TERM" '
        /^============================================================$/ {
            term = ""
            search_status = ""
            classifier_status = ""
            next
        }
        /^Termo: / {
            term = substr($0, 8)
            next
        }
        /^Status da busca: / {
            search_status = substr($0, 18)
            next
        }
        /^Status da classificação: / {
            classifier_status = substr($0, 26)
        }
        END {
            completed = (term == expected_term && (search_status == "0" || search_status == "1") && classifier_status == "0")
            exit(completed ? 0 : 1)
        }
    ' "$TIME_FILE"
}

time_logs_are_complete() {
    local DISK_PATH="$1"
    local DISK_NAME TERM_INDEX TIME_FILE

    DISK_NAME=$(basename "$DISK_PATH")
    for TERM_INDEX in "${!RUN_TERMS[@]}"; do
        TIME_FILE="${RUN_OUTPUT_DIRS[$TERM_INDEX]}/TIME-${RUN_LABELS[$TERM_INDEX]}-${DISK_NAME}.log"
        if ! time_log_is_complete "$TIME_FILE" "${RUN_TERMS[$TERM_INDEX]}"; then
            return 1
        fi
    done
    return 0
}

disk_is_complete() {
    local DISK_PATH="$1"

    if state_markers_are_complete "$DISK_PATH"; then
        return 0
    fi

    # Migra automaticamente execuções concluídas antes da criação dos
    # marcadores, usando o último bloco válido dos históricos TIME-*.
    if time_logs_are_complete "$DISK_PATH" && mark_disk_complete "$DISK_PATH"; then
        return 0
    fi
    return 1
}

classify_matches() {
    local DISK_NAME="$1"
    local TERM_INDEX OUTPUT_FILE
    local -a CLASSIFIER_ARGS=()

    # Os argumentos T:/F: transportam termos e destinos sem gerar processos
    # por termo. Um único awk classifica o fluxo produzido pelo rg deste disco.
    for TERM_INDEX in "${!RUN_TERMS[@]}"; do
        OUTPUT_FILE="${RUN_OUTPUT_DIRS[$TERM_INDEX]}/LEAK-${RUN_LABELS[$TERM_INDEX]}-${DISK_NAME}.txt"
        CLASSIFIER_ARGS+=(
            "T:${RUN_TERMS[$TERM_INDEX]}"
            "F:${OUTPUT_FILE}"
        )
    done

    awk -v term_count="${#RUN_TERMS[@]}" '
        BEGIN {
            IGNORECASE = 1
            for (i = 0; i < term_count; i++) {
                term_arg = 1 + (i * 2)
                file_arg = term_arg + 1
                terms[i] = substr(ARGV[term_arg], 3)
                files[i] = substr(ARGV[file_arg], 3)
                delete ARGV[term_arg]
                delete ARGV[file_arg]
            }
        }
        {
            for (i = 0; i < term_count; i++) {
                if ($0 ~ terms[i]) {
                    print $0 >> files[i]
                    fflush(files[i])
                }
            }
        }
    ' "${CLASSIFIER_ARGS[@]}"
}

search_in_disk() {
    local DISK_PATH="$1"
    local DISK_NAME TIME_FILE SEARCH_STATUS CLASSIFIER_STATUS FINAL_STATUS
    local TERM_INDEX
    local START_TIME START_DATE END_TIME END_DATE DURATION MINUTES SECONDS
    local -a PIPELINE_STATUS

    DISK_NAME=$(basename "$DISK_PATH")

    START_TIME=$(date +%s)
    START_DATE=$(date '+%Y-%m-%d %H:%M:%S')

    echo "[$DISK_NAME] Pesquisando ${#RUN_TERMS[@]} termo(s) em uma única leitura..."

    if [ "$SEARCH_ENGINE" = "rg" ]; then
        # Existe exatamente um rg por disco. THREADS controla apenas o
        # paralelismo interno dessa leitura.
        rg --ignore-case --text --no-line-number --no-filename \
            --hidden --no-ignore --no-heading --color never \
            --threads "$THREADS" --regexp "$COMBINED_PATTERN" "$DISK_PATH" \
            | classify_matches "$DISK_NAME"
        PIPELINE_STATUS=("${PIPESTATUS[@]}")
    else
        grep -Eriha --binary-files=text -- "$COMBINED_PATTERN" "$DISK_PATH" \
            | classify_matches "$DISK_NAME"
        PIPELINE_STATUS=("${PIPESTATUS[@]}")
    fi

    SEARCH_STATUS=${PIPELINE_STATUS[0]:-2}
    CLASSIFIER_STATUS=${PIPELINE_STATUS[1]:-2}
    FINAL_STATUS=0
    if [ "$SEARCH_STATUS" -gt 1 ]; then
        FINAL_STATUS=$SEARCH_STATUS
    elif [ "$CLASSIFIER_STATUS" -ne 0 ]; then
        FINAL_STATUS=$CLASSIFIER_STATUS
    fi

    END_TIME=$(date +%s)
    END_DATE=$(date '+%Y-%m-%d %H:%M:%S')
    DURATION=$((END_TIME - START_TIME))
    MINUTES=$((DURATION / 60))
    SECONDS=$((DURATION % 60))

    # Mantém um histórico por termo/disco, sempre em modo de acréscimo.
    for TERM_INDEX in "${!RUN_TERMS[@]}"; do
        TIME_FILE="${RUN_OUTPUT_DIRS[$TERM_INDEX]}/TIME-${RUN_LABELS[$TERM_INDEX]}-${DISK_NAME}.log"
        {
            echo "============================================================"
            echo "Início: $START_DATE"
            echo "Fim: $END_DATE"
            echo "Duração: $MINUTES min $SECONDS seg"
            echo "Mecanismo: $SEARCH_ENGINE"
            echo "Threads do rg: $THREADS"
            echo "Termo: ${RUN_TERMS[$TERM_INDEX]}"
            echo "Disco: $DISK_NAME"
            echo "Status da busca: $SEARCH_STATUS"
            echo "Status da classificação: $CLASSIFIER_STATUS"
        } >> "$TIME_FILE"
    done

    if [ "$FINAL_STATUS" -eq 0 ]; then
        if ! mark_disk_complete "$DISK_PATH"; then
            echo "[$DISK_NAME] A busca terminou, mas não foi possível salvar o estado de conclusão." >&2
            return 3
        fi
        echo "[$DISK_NAME] Finalizado em $MINUTES min $SECONDS seg."
        return 0
    fi

    echo "[$DISK_NAME] ERRO na busca/classificação (código $FINAL_STATUS)." >&2
    return "$FINAL_STATUS"
}

TERM_COUNT=${#RUN_TERMS[@]}
DISK_COUNT=${#DISKS[@]}
PENDING_DISKS=()
COMPLETED_DISKS=()

for DISK in "${DISKS[@]}"; do
    if [ "$FORCE_RESCAN" -eq 0 ] && disk_is_complete "$DISK"; then
        COMPLETED_DISKS+=("$DISK")
        echo "[$(basename "$DISK")] Já concluído; busca ignorada."
    else
        PENDING_DISKS+=("$DISK")
    fi
done

PENDING_COUNT=${#PENDING_DISKS[@]}
COMPLETED_COUNT=${#COMPLETED_DISKS[@]}
TOTAL_SEARCHES=$PENDING_COUNT

echo ""
echo "Iniciando uma busca por disco, todas simultaneamente:"
echo "  Discos encontrados: $DISK_COUNT"
echo "  Discos já concluídos: $COMPLETED_COUNT"
echo "  Discos pendentes/processos de busca: $PENDING_COUNT"
echo "  Termos avaliados por processo: $TERM_COUNT"
if [ "$SEARCH_ENGINE" = "rg" ]; then
    echo "  Threads internas por processo rg: $THREADS"
fi

if [ "$PENDING_COUNT" -eq 0 ]; then
    echo "Todos os discos já haviam sido concluídos. Nenhuma nova leitura foi necessária."
    exit 0
fi

# Todos os discos são iniciados antes do primeiro wait. A quantidade de termos
# não altera a quantidade de processos rg.
SEARCH_PIDS=()
for DISK in "${PENDING_DISKS[@]}"; do
    search_in_disk "$DISK" &
    SEARCH_PIDS+=("$!")
done

echo "Todos os $TOTAL_SEARCHES discos pendentes foram iniciados. Aguardando conclusão..."

TOTAL_ERRORS=0
for SEARCH_PID in "${SEARCH_PIDS[@]}"; do
    if ! wait "$SEARCH_PID"; then
        TOTAL_ERRORS=$((TOTAL_ERRORS + 1))
    fi
done

if [ "$SEARCH_ENGINE" = "rg" ]; then
    echo "Busca concluída com ripgrep."
else
    echo "Busca concluída com grep. Para maior velocidade, instale: apt install ripgrep"
fi

if [ "$TOTAL_ERRORS" -gt 0 ]; then
    echo "Busca concluída com $TOTAL_ERRORS erro(s). Consulte as mensagens acima." >&2
    exit 1
fi

echo "Todas as pesquisas foram concluídas com sucesso."
