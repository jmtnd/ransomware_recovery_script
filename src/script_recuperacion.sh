#!/bin/bash
# Ransomware Recovery Script - Versión Final Mejorada

########################################
# Configuración de seguridad y colores #
########################################
set -o errexit
set -o nounset
set -o pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

# Variables globales seguras
declare -r TIMESTAMP=$(date +%Y%m%d_%H%M%S)
declare -r MAX_PARALLEL_JOBS=4
declare -r MIN_BACKUP_SIZE=$((10*1024*1024*1024)) # 10GB
declare -r DISCO_FUENTE="/dev/sda2"
declare -r MOUNT_POINT="/mnt/sda2"
declare -r BACKUP_DIR="/mnt/sda2/BMS/RespaldosBMS"
declare -r WORK_DIR="/mnt/usb_recuperacion/recuperados_${TIMESTAMP}"
declare -r LOG_DIR="${WORK_DIR}/logs"
declare -r SCAN_LOG="${LOG_DIR}/scan_${TIMESTAMP}.log"
declare -r RECOVERY_LOG="${LOG_DIR}/recovery_${TIMESTAMP}.log"
declare -r PATTERNS_FOUND="${LOG_DIR}/patterns_${TIMESTAMP}.txt"
declare -r EMAIL_TO="jaime911@gmail.com"
declare -r EMAIL_FROM="recovery_script@localhost"
declare RAW_BLOCK_SIZE=$((128*1024*1024))  # 128MB, sin -r para poder modificarlo

# Patrones específicos de backup encontrados
BACKUP_PATTERNS=(
    "BMS_backup_[0-9]{4}_[0-9]{2}_[0-9]{2}_[0-9]{6}_[0-9]+\.bak"
    "BMSJoseDiego_backup_[0-9]{4}_[0-9]{2}_[0-9]{2}_[0-9]{6}_[0-9]+\.bak"
    "BMSsa_backup_[0-9]{4}_[0-9]{2}_[0-9]{2}_[0-9]{6}_[0-9]+\.bak"
)

# Tamaños esperados por tipo (en bytes)
declare -A TAMANOS_ESPERADOS=(
    ["BMSsa"]=22305395720
)

# Buscar secuencias de bytes comunes en backups
BACKUP_SIGNATURES=(
    "424D537361"      # "BMSsa" en hex
    "424D5373615F4241434B5550"  # "BMSsa_BACKUP" en hex
)

########################################
# Sistema de IA y Análisis Predictivo  #
########################################

# Configuración del sistema de IA
declare -r MIN_CLUSTER_SIZE=3
declare -r PATTERN_SCORE_THRESHOLD=10
declare -r PREDICTION_CONFIDENCE=0.7

######################################
# Funciones auxiliares y de logging  #
######################################

# Función de limpieza mejorada
cleanup() {
    local exit_code=$1
    echo "Limpiando recursos..."
    sync
    if [ $exit_code -ne 0 ]; then
        echo -e "${RED}Error durante la ejecución. Código: $exit_code${NC}"
    fi
    exit $exit_code
}
trap 'cleanup $?' EXIT

# Función para manejo uniforme de errores
handle_error() {
    local error_msg="$1"
    echo -e "${RED}ERROR: $error_msg${NC}" >&2
    
    # Enviar notificación de error
    local email_subject="[Recovery] ERROR CRÍTICO"
    local email_message="Se ha producido un error en el proceso:
- Error: $error_msg
- Fecha: $(date)
- Ubicación: $DISCO_FUENTE
- Último comando: $BASH_COMMAND"
    
    send_email_notification "$email_subject" "$email_message"
    
    cleanup 1
}

# Verificación mejorada de entropía
check_entropy() {
    local file="$1"
    local sample_size=$((1024*1024)) # 1MB
    local entropy
    
    entropy=$(dd if="$file" bs=1M count=1 2>/dev/null | ent | awk '/Entropy/ {print $3}')
    if [[ -z "$entropy" ]]; then
        return 1
    fi
    
    # Entropía mayor a 7.8 indica posible cifrado
    awk "BEGIN {exit !($entropy > 7.8)}"
}

# Función para verificar montaje del disco
mount_disk_safely() {
    if ! mountpoint -q "$MOUNT_POINT"; then
        echo "Montando $DISCO_FUENTE en modo solo lectura..."
        mount -t ntfs-3g -o ro "$DISCO_FUENTE" "$MOUNT_POINT" || handle_error "No se pudo montar el disco"
    else
        # Para NTFS, verificamos los permisos reales
        if ! mount | grep "$MOUNT_POINT" | grep -q "ro\|read-only"; then
            echo "Desmontando para remontar en modo solo lectura..."
            umount "$MOUNT_POINT"
            mount -t ntfs-3g -o ro "$DISCO_FUENTE" "$MOUNT_POINT" || handle_error "No se pudo montar el disco en modo lectura"
        else
            echo -e "${GREEN}✓ Disco montado correctamente en modo lectura${NC}"
        fi
    fi
}

# Función para crear imagen forense mejorada
create_forensic_image() {
    local source_device="$1"
    local output_dir="$2"
    local image_file="${output_dir}/disk_image_${TIMESTAMP}.dd"
    local log_file="${output_dir}/ddrescue_${TIMESTAMP}.log"
    
    echo -e "${YELLOW}Creando imagen forense...${NC}"
    
    # Usar dcfldd para mejor evidencia forense
    dcfldd if="$source_device" \
           of="$image_file" \
           hash=sha256,md5 \
           hashlog="${image_file}.hash" \
           hashwindow=1G \
           log="$log_file" \
           bs=4M

    # Verificar creación exitosa
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}Imagen forense creada exitosamente${NC}"
        echo "$image_file"
    else
        handle_error "Error creando imagen forense"
    fi
}

# Añadir esta función para logging
log_message() {
    local level="$1"
    local message="$2"
    local log_file="$3"
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [$level] $message" | tee -a "$log_file"
}

# Modificar la función de búsqueda para ser más flexible
find_backup_patterns() {
    local block="$1"
    local output_dir="$2"
    
    log_message "INFO" "Analizando bloque $block por patrones" "$SCAN_LOG"
    
    # Buscar patrones con barra de progreso
    echo -e "${CYAN}Analizando bloque $block...${NC}"
    dd if="$DISCO_FUENTE" bs=1M skip=$((block*1024)) count=1024 2>/dev/null | \
    pv -s 1024M | \
    strings -n 10 | \
    grep -i -E 'backup|\.bak|BMS|respaldo|copia' >> "$PATTERNS_FOUND"
    
    # Buscar cabeceras conocidas
    dd if="$DISCO_FUENTE" bs=1M skip=$((block*1024)) count=1024 2>/dev/null | \
    hexdump -C | grep -E '424D535F|4241434B|524553504C' >> "${PATTERNS_FOUND}.hex"
    
    # Registrar tamaños de archivos encontrados
    find "$output_dir" -type f -size +5G -exec ls -lh {} \; >> "$SCAN_LOG"
}

# Modificar recover_original_backup para una búsqueda más precisa
recover_original_backup() {
    local nigra_file="$1"
    local output_dir="$2"
    local tipo="$3"
    
    log_message "INFO" "Iniciando recuperación de: $nigra_file" "$RECOVERY_LOG"
    
    local original_name=$(basename "$nigra_file" | sed 's/\.\[.*\]\.nigra$//')
    local tamano_esperado="${TAMANOS_ESPERADOS[$tipo]}"
    
    echo -e "\n${YELLOW}=== Procesando: $original_name ===${NC}"
    echo -e "Tipo: $tipo"
    echo -e "Tamaño esperado: $(numfmt --to=iec-i --suffix=B "$tamano_esperado")"
    
    # Usar bloques más pequeños pero buscar en más bloques
    local block_size="512M"
    local total_blocks=100
    
    echo -e "\n${CYAN}Buscando en bloques del disco...${NC}"
    for block in $(seq $((total_blocks-1)) -1 0); do
        echo -ne "${YELLOW}Bloque ${block}/${total_blocks} - "
        
        # Buscar múltiples patrones incluyendo el nombre original
        if dd if="$DISCO_FUENTE" bs="$block_size" skip="$block" count=1 2>/dev/null | \
           (grep -a "BMS_BACKUP_HEADER" || \
            grep -a "BACKUP_START" || \
            grep -a "$original_name"); then
            
            echo -e "\n${GREEN}✓ Patrón encontrado en bloque $block${NC}"
            local output_file="${output_dir}/recovered_${block}_${original_name}"
            
            # Extraer un bloque más grande
            echo -e "${CYAN}Extrayendo datos (4GB)...${NC}"
            dd if="$DISCO_FUENTE" bs="$block_size" skip="$block" count=8 2>/dev/null | \
            pv -s $((4*1024*1024*1024)) > "$output_file"
            
            if validate_backup_integrity "$output_file" "$tamano_esperado"; then
                echo -e "${GREEN}✓ Backup recuperado exitosamente${NC}"
                return 0
            else
                echo -e "${YELLOW}× Backup no válido, continuando búsqueda...${NC}"
                rm -f "$output_file"
            fi
        fi
        echo -ne "Buscando...\r"
        sleep 0.1  # Pequeña pausa para no saturar el disco
    done
    
    echo -e "${RED}× No se encontró backup válido${NC}"
    return 1
}

# Función mejorada para validar integridad
validate_backup_integrity() {
    local file="$1"
    local expected_size="$2"
    local actual_size=$(stat -c%s "$file")
    
    # Verificar tamaño con margen de error de ±1GB
    if [ "$actual_size" -lt "$((expected_size-1024*1024*1024))" ] || \
       [ "$actual_size" -gt "$((expected_size+1024*1024*1024))" ]; then
        return 1
    fi
    
    # Verificar si está cifrado
    if check_entropy "$file"; then
        echo -e "${YELLOW}Advertencia: Posible archivo cifrado${NC}"
        return 1
    fi
    
    # Verificar cabecera
    if ! head -c 512 "$file" | grep -q "BMS_BACKUP_HEADER"; then
        return 1
    fi
    
    # Si pasa todas las validaciones, notificar
    local email_subject="Backup Válido Encontrado"
    local email_message="Se ha validado un backup:
- Archivo: $(basename "$file")
- Tamaño: $(numfmt --to=iec-i --suffix=B $actual_size)
- Fecha: $(date)
- Ubicación: $file"
    
    send_email_notification "$email_subject" "$email_message"
    return 0
}

# Modificar process_nigra_file para detectar archivos cifrados
process_nigra_file() {
    local nigra_file="$1"
    local work_dir="$2"
    
    # Primero verificar si el archivo está cifrado
    if [[ "$nigra_file" =~ \[.*\]\.\[.*@.*\]\.nigra$ ]]; then
        log_message "WARN" "Archivo cifrado detectado, saltando: $(basename "$nigra_file")" "$RECOVERY_LOG"
        return 0
    fi

    # Solo procesar archivos no cifrados
    local tipo_backup
    if [[ "$nigra_file" =~ BMS_backup_ ]]; then
        tipo_backup="BMS"
    elif [[ "$nigra_file" =~ BMSJoseDiego_backup_ ]]; then
        tipo_backup="BMSJoseDiego"
    elif [[ "$nigra_file" =~ BMSsa_backup_ ]]; then
        tipo_backup="BMSsa"
    else
        return 0
    fi

    log_message "INFO" "Procesando backup no cifrado tipo: $tipo_backup" "$RECOVERY_LOG"
    recover_original_backup "$nigra_file" "${work_dir}/${tipo_backup}/originales" "$tipo_backup"
}

# Modificar la función recover_all_backups para buscar en sectores raw
recover_all_backups() {
    echo -e "${BLUE}=== Iniciando búsqueda profunda de backups originales ===${NC}"
    echo -e "${YELLOW}Analizando sectores del disco. Esto puede tomar varias horas.${NC}"
    
    # Crear directorios para recuperación
    mkdir -p "${WORK_DIR}"/{BMS,BMSJoseDiego,BMSsa}/originales
    
    # Obtener tamaño total del disco en bloques de 512MB
    local disk_size=$(blockdev --getsize64 "$DISCO_FUENTE")
    local block_size=$((512*1024*1024))  # 512MB
    local total_blocks=$((disk_size / block_size))
    
    echo -e "${BLUE}Tamaño del disco: $(numfmt --to=iec-i --suffix=B $disk_size)${NC}"
    echo -e "${BLUE}Total de bloques a analizar: $total_blocks${NC}"
    echo
    
    # Buscar en cada bloque
    for block in $(seq 0 $total_blocks); do
        echo -ne "${YELLOW}Analizando bloque ${block}/${total_blocks}${NC}"
        
        # Buscar firmas en hex
        if dd if="$DISCO_FUENTE" bs="$block_size" skip="$block" count=1 2>/dev/null | \
           hexdump -C | grep -E "$(printf '|%s' "${BACKUP_SIGNATURES[@]}")"; then
            
            echo -e "\n${GREEN}✓ Firma de backup encontrada en bloque $block${NC}"
            # Extraer y analizar...
        fi
    done
}

# Función para analizar estructura de backups existentes
analyze_backup_structure() {
    local backup_dir="/mnt/sda2/BMS/RespaldosBMS"
    
    echo -e "${BLUE}=== Análisis de Estructura de Backups ===${NC}"
    echo -e "${YELLOW}Directorio: $backup_dir${NC}"
    echo
    
    # Listar archivos grandes con detalles
    echo "Archivos .bak mayores a 10GB:"
    echo "----------------------------------------"
    find "$backup_dir" -type f -name "*.bak" -size +10G -exec ls -lh {} \; | \
        while read -r line; do
            echo -e "${GREEN}$line${NC}"
        done
    
    # Analizar patrones de nombres
    echo -e "\nPatrones de nombres encontrados:"
    echo "----------------------------------------"
    find "$backup_dir" -type f -name "*.bak" -printf "%f\n" | \
        sort | uniq -c | sort -nr
    
    # Mostrar estructura temporal
    echo -e "\nDistribución temporal:"
    echo "----------------------------------------"
    find "$backup_dir" -type f -name "*.bak" -printf "%TY-%Tm-%Td %TH:%TM %s %p\n" | \
        sort -n
    
    # Calcular espacio total
    echo -e "\nEspacio total usado:"
    echo "----------------------------------------"
    du -sh "$backup_dir"
}

# Función para análisis de clusters
analyze_clusters() {
    local CLUSTER_LOG="${LOG_DIR}/clusters_${TIMESTAMP}.log"
    
    echo -e "\n${BLUE}=== Análisis de Clusters ===${NC}" | tee -a "$CLUSTER_LOG"
    log_message "INFO" "Iniciando análisis de clusters" "$CLUSTER_LOG"
    
    # Verificar directorio de trabajo
    if [ ! -d "$WORK_DIR" ]; then
        log_message "ERROR" "Directorio de trabajo no existe: $WORK_DIR" "$CLUSTER_LOG"
        return 1
    fi
    
    # Crear archivo de bloques exitosos si no existe
    touch "${WORK_DIR}/successful_blocks.txt"
    
    if [ ! -s "${WORK_DIR}/successful_blocks.txt" ]; then
        log_message "INFO" "No hay bloques exitosos para analizar aún" "$CLUSTER_LOG"
        return 0
    fi
    
    local prev_block=0
    local cluster_size=0
    local cluster_start=0
    
    while read -r block; do
        if [ $((block - prev_block)) -lt 10 ]; then
            cluster_size=$((cluster_size + 1))
            [ $cluster_size -eq 1 ] && cluster_start=$prev_block
        else
            if [ $cluster_size -gt $MIN_CLUSTER_SIZE ]; then
                echo "Cluster encontrado: Inicio=$cluster_start, Tamaño=$cluster_size" | tee -a "$CLUSTER_LOG"
                echo "$cluster_start $((cluster_start + cluster_size))" >> "${WORK_DIR}/priority_ranges.txt"
            fi
            cluster_size=0
        fi
        prev_block=$block
    done < <(sort -n "${WORK_DIR}/successful_blocks.txt")
    
    log_message "INFO" "Análisis de clusters completado" "$CLUSTER_LOG"
    return 0
}

# Sistema de puntuación para patrones
score_pattern() {
    local pattern="$1"
    local score=0
    
    # Puntuar basado en características conocidas
    [[ $pattern =~ BMS ]] && ((score+=5))
    [[ $pattern =~ backup ]] && ((score+=3))
    [[ $pattern =~ [0-9]{4}_[0-9]{2}_[0-9]{2} ]] && ((score+=4))
    [[ $pattern =~ \.bak$ ]] && ((score+=3))
    
    # Puntuar basado en el histórico de éxitos
    local success_count=$(grep -c "$pattern" "${WORK_DIR}/successful_patterns.txt" 2>/dev/null || echo 0)
    score=$((score + success_count * 2))
    
    echo $score
}

# Predicción de regiones prometedoras
predict_next_regions() {
    local PREDICTION_LOG="${LOG_DIR}/predictions_${TIMESTAMP}.log"
    
    echo -e "\n${BLUE}=== Predicción de Regiones ===${NC}" | tee -a "$PREDICTION_LOG"
    
    if [ -f "${WORK_DIR}/successful_blocks.txt" ]; then
        # Calcular diferencias entre bloques exitosos
        local differences=()
        local prev_block=0
        
        while read -r block; do
            if [ $prev_block -ne 0 ]; then
                differences+=($((block - prev_block)))
            fi
            prev_block=$block
        done < <(sort -n "${WORK_DIR}/successful_blocks.txt")
        
        # Encontrar patrones comunes
        local common_diff=$(printf '%d\n' "${differences[@]}" | sort -n | uniq -c | sort -nr | head -n1 | awk '{print $2}')
        
        # Predecir próximas ubicaciones
        local last_block=$(tail -n1 "${WORK_DIR}/successful_blocks.txt")
        local next_predicted=$((last_block + common_diff))
        
        echo "Análisis de patrones:" | tee -a "$PREDICTION_LOG"
        echo "- Diferencia más común: $common_diff bloques" | tee -a "$PREDICTION_LOG"
        echo "- Último bloque exitoso: $last_block" | tee -a "$PREDICTION_LOG"
        echo "- Próxima región predicha: $next_predicted" | tee -a "$PREDICTION_LOG"
        
        # Guardar predicción con nivel de confianza
        echo "$next_predicted $PREDICTION_CONFIDENCE" >> "${WORK_DIR}/predicted_blocks.txt"
    fi
}

# Modificar la función recover_from_raw_sectors para usar el sistema de IA
recover_from_raw_sectors() {
    echo -e "${BLUE}=== Iniciando búsqueda profunda de backups ===${NC}"
    log_message "INFO" "Iniciando búsqueda profunda" "$RECOVERY_LOG"
    
    # Crear directorios necesarios
    mkdir -p "${WORK_DIR}/learning"
    mkdir -p "${WORK_DIR}"/{BMS,BMSJoseDiego,BMSsa}/originales
    
    # Archivo de checkpoint
    local CHECKPOINT_FILE="${WORK_DIR}/checkpoint.dat"
    local start_block=0
    
    # Verificar si existe checkpoint
    if [ -f "$CHECKPOINT_FILE" ]; then
        start_block=$(cat "$CHECKPOINT_FILE")
        echo -e "${GREEN}Reanudando desde bloque $start_block${NC}"
        log_message "INFO" "Reanudando desde bloque $start_block" "$RECOVERY_LOG"
    fi
    
    # Obtener tamaño del disco
    local disk_size=$(blockdev --getsize64 "$DISCO_FUENTE")
    local total_blocks=$((disk_size / RAW_BLOCK_SIZE))
    
    log_message "INFO" "Configuración inicial:" "$RECOVERY_LOG"
    log_message "INFO" "- Disco: $DISCO_FUENTE" "$RECOVERY_LOG"
    log_message "INFO" "- Tamaño: $(numfmt --to=iec-i --suffix=B $disk_size)" "$RECOVERY_LOG"
    log_message "INFO" "- Bloques: $total_blocks" "$RECOVERY_LOG"
    log_message "INFO" "- Iniciando desde: $start_block" "$RECOVERY_LOG"
    
    echo -e "\n${BLUE}Iniciando escaneo de bloques...${NC}"
    echo -e "${YELLOW}Presiona Ctrl+C para interrumpir de forma segura${NC}"
    
    # Escanear bloques con checkpoint cada 100 bloques
    for block in $(seq $start_block $total_blocks); do
        process_block "$block" "$total_blocks" || break
        
        # Guardar checkpoint cada 100 bloques
        if [ $((block % 100)) -eq 0 ]; then
            echo "$block" > "$CHECKPOINT_FILE"
            sync  # Forzar escritura a disco
        fi
    done
    
    return 0
}

# Función de aprendizaje para ajustar patrones
learn_from_success() {
    local successful_block="$1"
    local successful_pattern="$2"
    local LEARNING_LOG="${LOG_DIR}/learning_${TIMESTAMP}.log"
    
    echo -e "\n${BLUE}=== Analizando patrón exitoso ===${NC}" | tee -a "$LEARNING_LOG"
    echo "Bloque: $successful_block" | tee -a "$LEARNING_LOG"
    echo "Patrón: $successful_pattern" | tee -a "$LEARNING_LOG"
    
    # Extraer contexto alrededor del patrón exitoso
    dd if="$DISCO_FUENTE" bs=1M skip=$((successful_block*128-1)) count=2 2>/dev/null | \
    hexdump -C > "${WORK_DIR}/context_${successful_block}.hex"
    
    # Analizar patrones comunes antes y después
    {
        echo "Contexto encontrado:"
        head -n 20 "${WORK_DIR}/context_${successful_block}.hex"
        echo "Analizando patrones..."
    } | tee -a "$LEARNING_LOG"
    
    # Ajustar prioridades de búsqueda
    if ! grep -q "$successful_pattern" "${WORK_DIR}/successful_patterns.txt" 2>/dev/null; then
        echo "$successful_pattern" >> "${WORK_DIR}/successful_patterns.txt"
        echo "Nuevo patrón añadido a la base de conocimiento" | tee -a "$LEARNING_LOG"
    fi
}

# Función para ajustar estrategia de búsqueda
adjust_search_strategy() {
    local LEARNING_LOG="${LOG_DIR}/learning_${TIMESTAMP}.log"
    local success_rate=0
    
    # Verificar que existan patrones antes de calcular
    if [ -f "${WORK_DIR}/successful_patterns.txt" ] && [ -f "$PATTERNS_FOUND" ]; then
        local total_patterns=$(wc -l < "$PATTERNS_FOUND")
        if [ "$total_patterns" -gt 0 ]; then
            local successful_patterns=$(wc -l < "${WORK_DIR}/successful_patterns.txt")
            success_rate=$(( (successful_patterns * 100) / total_patterns ))
        fi
    fi
    
    echo -e "\n${BLUE}=== Ajustando estrategia de búsqueda ===${NC}" | tee -a "$LEARNING_LOG"
    echo "Tasa de éxito actual: ${success_rate}%" | tee -a "$LEARNING_LOG"
    
    # Ajustar tamaño de bloque basado en el éxito
    if [ $success_rate -lt 20 ]; then
        RAW_BLOCK_SIZE=$((RAW_BLOCK_SIZE / 2))
        echo "Reduciendo tamaño de bloque a: $RAW_BLOCK_SIZE" | tee -a "$LEARNING_LOG"
    elif [ $success_rate -gt 80 ]; then
        RAW_BLOCK_SIZE=$((RAW_BLOCK_SIZE * 2))
        echo "Aumentando tamaño de bloque a: $RAW_BLOCK_SIZE" | tee -a "$LEARNING_LOG"
    fi
    
    # Notificar cambios significativos
    if [ $success_rate -lt 10 ]; then
        send_email_notification "Ajuste de Estrategia" "Tasa de éxito muy baja ($success_rate%). Ajustando parámetros de búsqueda."
    fi
}

analyze_results() {
    local ANALYSIS_LOG="${LOG_DIR}/analysis_${TIMESTAMP}.log"
    
    echo -e "\n${BLUE}=== Análisis de Resultados ===${NC}" | tee -a "$ANALYSIS_LOG"
    
    # Analizar patrones exitosos
    if [ -f "${WORK_DIR}/successful_patterns.txt" ]; then
        echo "Patrones más efectivos:" | tee -a "$ANALYSIS_LOG"
        sort "${WORK_DIR}/successful_patterns.txt" | uniq -c | sort -nr | head -n 5 | tee -a "$ANALYSIS_LOG"
    fi
    
    # Analizar distribución de hallazgos
    if [ -f "${WORK_DIR}/successful_blocks.txt" ]; then
        echo -e "\nDistribución de hallazgos:" | tee -a "$ANALYSIS_LOG"
        awk '{print int($1/100)*100}' "${WORK_DIR}/successful_blocks.txt" | 
        sort -n | uniq -c | 
        awk '{printf "Región %8d MB: %d hallazgos\n", $2, $1}' | tee -a "$ANALYSIS_LOG"
    fi
}

# Modificar la función send_email_notification
send_email_notification() {
    local subject="$1"
    local message="$2"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    
    # Usar mailx en lugar de sendmail para mejor manejo de SMTP
    (
    echo "$message"
    echo "----------------------------------------"
    echo "Fecha: $timestamp"
    echo "Host: $(hostname)"
    echo "Disco: $DISCO_FUENTE"
    echo "----------------------------------------"
    ) | mailx -v -s "[Recuperacion] $subject" \
              -S smtp=smtp.gmail.com:587 \
              -S smtp-use-starttls \
              -S smtp-auth=login \
              -S smtp-auth-user=jaime911@gmail.com \
              -S smtp-auth-password=bbxxvzdasmctqdnn \
              -S ssl-verify=ignore \
              jaime911@gmail.com
    
    echo "[${timestamp}] Email enviado: $subject" >> "${LOG_DIR}/email_${TIMESTAMP}.log"
}

######################################
# Función principal y arranque       #
######################################

# Función principal
main() {
    # Verificar privilegios root
    if [ "$EUID" -ne 0 ]; then 
        echo -e "${RED}Se requieren privilegios root${NC}"
        exec sudo "$0" "$@"
    fi
    
    # Verificar herramientas necesarias
    check_tools
    
    # Configurar correo antes de iniciar
    setup_email
    
    # Verificar montaje seguro del disco
    mount_disk_safely
    
    # Crear directorio de trabajo
    mkdir -p "$WORK_DIR"
    
    # Crear directorios de logs
    mkdir -p "$LOG_DIR"
    
    log_message "INFO" "Iniciando proceso de recuperación" "$RECOVERY_LOG"
    
    # Análisis inicial del disco
    log_message "INFO" "Realizando análisis inicial del disco" "$SCAN_LOG"
    {
        echo "=== Análisis inicial del disco ==="
        echo "Fecha: $(date)"
        echo "Disco: $DISCO_FUENTE"
        echo "Tamaño: $(blockdev --getsize64 $DISCO_FUENTE | numfmt --to=iec-i --suffix=B)"
        echo "Sistema de archivos: $(blkid $DISCO_FUENTE)"
        echo "==================================="
    } >> "$SCAN_LOG"
    
    # Iniciar recuperación
    recover_from_raw_sectors
    
    # Mostrar resumen
    echo -e "\n${BLUE}=== Resumen de Recuperación ===${NC}"
    for tipo in BMS BMSJoseDiego BMSsa; do
        echo -e "\nBackups tipo $tipo recuperados:"
        find "${WORK_DIR}/${tipo}/originales" -type f -ls || true
    done
    
    # Generar reporte final
    {
        echo "=== Reporte Final de Recuperación ==="
        echo "Fecha finalización: $(date)"
        echo "Total archivos procesados: $(find "$WORK_DIR" -type f | wc -l)"
        echo "Patrones únicos encontrados: $(sort -u "$PATTERNS_FOUND" | wc -l)"
        echo "Espacio total recuperado: $(du -sh "$WORK_DIR")"
        echo "==================================="
    } >> "$RECOVERY_LOG"
    
    # Analizar resultados
    analyze_results
}

# Verificar herramientas necesarias
check_tools() {
    local missing_tools=()
    local tools=(
        "dd" 
        "grep" 
        "pv" 
        "parallel" 
        "strings" 
        "hexdump" 
        "mailx"     # Añadido mailx
        "awk"
        "sort"
        "uniq"
    )
    
    echo -e "${YELLOW}Verificando herramientas necesarias...${NC}"
    
    for tool in "${tools[@]}"; do
        if ! command -v "$tool" &>/dev/null; then
            missing_tools+=("$tool")
        fi
    done
    
    if [ ${#missing_tools[@]} -ne 0 ]; then
        echo -e "${RED}Faltan las siguientes herramientas: ${missing_tools[*]}${NC}"
        echo "Instalando herramientas faltantes..."
        # En Arch Linux (SystemRescue)
        pacman -Sy --noconfirm "${missing_tools[@]}"
        
        # Verificar instalación
        for tool in "${missing_tools[@]}"; do
            if ! command -v "$tool" &>/dev/null; then
                echo -e "${RED}Error: No se pudo instalar $tool${NC}"
                exit 1
            fi
        done
    fi
    
    echo -e "${GREEN}✓ Todas las herramientas necesarias están instaladas${NC}"
}

# Función para procesar cada bloque
process_block() {
    local block="$1"
    local total_blocks="$2"
    local output_file="${WORK_DIR}/raw_block_${block}.dat"
    
    # Actualizar variable global de bloque actual
    current_block=$block
    
    # Mostrar progreso cada bloque
    echo -ne "\r${YELLOW}Progreso: Bloque $block de $total_blocks ($(( (block * 100) / total_blocks ))%) - Buscando BMSsa${NC}"
    
    # Verificar límites
    local disk_size=$(blockdev --getsize64 "$DISCO_FUENTE")
    if [ $((block * RAW_BLOCK_SIZE)) -ge "$disk_size" ]; then
        return 0
    fi
    
    # Buscar firmas específicas de BMSsa
    timeout 30s dd if="$DISCO_FUENTE" bs="$RAW_BLOCK_SIZE" skip="$block" count=1 2>/dev/null | \
    hexdump -C | grep -q -E "$(printf '|%s' "${BACKUP_SIGNATURES[@]}")" && {
        echo -e "\n${GREEN}✓ Firma de BMSsa encontrada en bloque $block${NC}"
        echo "$block" >> "${WORK_DIR}/successful_blocks.txt"
        
        # Extraer y validar con timeout
        timeout 60s dd if="$DISCO_FUENTE" bs="$RAW_BLOCK_SIZE" skip="$block" count=2 2>/dev/null > "$output_file"
        
        if validate_backup_integrity "$output_file" "${TAMANOS_ESPERADOS[BMSsa]}"; then
            mv "$output_file" "${WORK_DIR}/BMSsa/originales/recovered_block_${block}_${TIMESTAMP}.bak"
            send_email_notification "BMSsa Backup Encontrado" "Se ha recuperado un backup BMSsa válido del bloque $block"
            return 0
        fi
        rm -f "$output_file"
    }
    
    # Verificar si debemos pausar o detener
    if [ "$STOP_SCAN" -eq 1 ]; then
        echo -e "\n${RED}Deteniendo escaneo...${NC}"
        return 1
    fi
    
    if [ "$PAUSE_SCAN" -eq 1 ]; then
        echo -e "\n${YELLOW}Proceso pausado. Presiona ENTER para continuar o Ctrl+\ para detener${NC}"
        read -r
        PAUSE_SCAN=0
    fi
    
    return 0
}

# Actualizar la función setup_email
setup_email() {
    echo "=== Configurando mailx para Gmail ==="
    # Configurar mailx
    sudo tee /etc/mail.rc << 'EOF'
set smtp=smtp.gmail.com:587
set smtp-use-starttls
set smtp-auth=login
set smtp-auth-user=jaime911@gmail.com
set smtp-auth-password=bbxxvzdasmctqdnn
set ssl-verify=ignore
set nss-config-dir=/etc/pki/nssdb/
EOF

    # Enviar correo de prueba
    echo "=== Enviando correo de prueba ==="
    echo "Iniciando proceso de recuperación
----------------------------------------
Fecha: $(date)
Host: $(hostname)
Disco: $DISCO_FUENTE
Tamaño: $(blockdev --getsize64 $DISCO_FUENTE | numfmt --to=iec-i --suffix=B)
----------------------------------------" | \
    mailx -v -s "[Recuperacion] Inicio del Proceso" jaime911@gmail.com
}

# Añadir variable global al inicio del script
declare -g current_block=0

# Al inicio del script, después de las variables
declare -g PAUSE_SCAN=0
declare -g STOP_SCAN=0

# Función para manejar señales
handle_signals() {
    echo -e "\n${YELLOW}Manejando señal $1...${NC}"
    case "$1" in
        SIGINT)  # Ctrl+C
            echo -e "${YELLOW}Presiona Ctrl+C otra vez para detener, o SPACE para pausar${NC}"
            PAUSE_SCAN=1
            ;;
        SIGQUIT)  # Ctrl+\
            echo -e "${RED}Deteniendo proceso...${NC}"
            STOP_SCAN=1
            ;;
        SIGTERM)  # kill -15
            echo -e "${RED}Recibida señal de terminación${NC}"
            STOP_SCAN=1
            ;;
    esac

    # Guardar progreso actual
    if [ -n "$current_block" ]; then
        echo "$current_block" > "${WORK_DIR}/checkpoint.dat"
        sync
        echo -e "${GREEN}Progreso guardado en bloque $current_block${NC}"
    fi
}

# Registrar manejadores de señales
trap 'handle_signals SIGINT' SIGINT
trap 'handle_signals SIGQUIT' SIGQUIT
trap 'handle_signals SIGTERM' SIGTERM

# Iniciar proceso
main "$@" 