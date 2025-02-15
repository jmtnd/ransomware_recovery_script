#!/bin/bash

# Configuración de seguridad
set -o errexit
set -o nounset
set -o pipefail

# Colores y configuración
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
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

# Patrones específicos de backup encontrados
BACKUP_PATTERNS=(
    "BMS_backup_[0-9]{4}_[0-9]{2}_[0-9]{2}_[0-9]{6}_[0-9]+\.bak"
    "BMSJoseDiego_backup_[0-9]{4}_[0-9]{2}_[0-9]{2}_[0-9]{6}_[0-9]+\.bak"
    "BMSsa_backup_[0-9]{4}_[0-9]{2}_[0-9]{2}_[0-9]{6}_[0-9]+\.bak"
)

# Tamaños esperados por tipo (en bytes)
declare -A TAMANOS_ESPERADOS=(
    ["BMS"]=17992074248
    ["BMSJoseDiego"]=16564105224
    ["BMSsa"]=22305395720
)

# Buscar secuencias de bytes comunes en backups
BACKUP_SIGNATURES=(
    "\x42\x4D\x53"          # "BMS" en hex
    "\x42\x41\x43\x4B\x55\x50"  # "BACKUP" en hex
    "\x42\x4D\x53\x5F\x42\x41\x43\x4B\x55\x50"  # "BMS_BACKUP" en hex
)

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
    echo -e "${RED}ERROR: $1${NC}" >&2
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
    
    # Permitir un margen de error de ±1GB
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

# Modificar la función recover_from_raw_sectors para ser más efectiva
recover_from_raw_sectors() {
    echo -e "${BLUE}=== Iniciando búsqueda profunda de backups ===${NC}"
    
    # Obtener tamaño del disco
    local disk_size=$(blockdev --getsize64 "$DISCO_FUENTE")
    local block_size=$((128*1024*1024))  # 128MB
    local total_blocks=$((disk_size / block_size))
    
    # Crear archivo de log específico para la búsqueda
    local SEARCH_LOG="${LOG_DIR}/search_${TIMESTAMP}.log"
    
    {
        echo "=== Configuración de Búsqueda ==="
        echo "Fecha inicio: $(date)"
        echo "Disco: $DISCO_FUENTE"
        echo "Tamaño total: $(numfmt --to=iec-i --suffix=B $disk_size)"
        echo "Tamaño de bloque: $(numfmt --to=iec-i --suffix=B $block_size)"
        echo "Total de bloques: $total_blocks"
        echo "============================"
        echo
        echo "=== Registro de Búsqueda ==="
    } | tee -a "$SEARCH_LOG"
    
    # Buscar en paralelo usando bloques más pequeños
    seq 0 $total_blocks | parallel --bar --eta --jobs $MAX_PARALLEL_JOBS \
    "dd if=$DISCO_FUENTE bs=$block_size skip={} count=1 2>/dev/null | \
     (hexdump -C | grep -E '424D535F|4241434B|524553504C' && \
      echo 'BLOQUE_{}_$(date +%H:%M:%S)' >> $PATTERNS_FOUND.blocks) 2>&1 | \
      tee -a $SEARCH_LOG"
    
    # Procesar bloques donde se encontraron patrones
    if [ -f "$PATTERNS_FOUND.blocks" ]; then
        echo -e "\n${GREEN}Procesando bloques con patrones encontrados...${NC}" | tee -a "$SEARCH_LOG"
        while read -r line; do
            local block=$(echo "$line" | cut -d'_' -f2)
            local time=$(echo "$line" | cut -d'_' -f3)
            
            echo -e "\n=== Análisis de Bloque $block (Encontrado: $time) ===" | tee -a "$SEARCH_LOG"
            echo -e "Posición: $((block * block_size)) bytes" | tee -a "$SEARCH_LOG"
            echo -e "Rango: $((block * 128))MB - $(((block + 1) * 128))MB" | tee -a "$SEARCH_LOG"
            
            # Extraer segmento
            echo -e "Extrayendo datos..." | tee -a "$SEARCH_LOG"
            local start_block=$((block > 8 ? block - 8 : 0))
            dd if="$DISCO_FUENTE" bs=$block_size skip=$start_block count=16 2>/dev/null | \
            pv -s $((16*block_size)) > "${WORK_DIR}/raw_block_${block}.dat" 2>&1 | tee -a "$SEARCH_LOG"
            
            # Analizar contenido
            echo -e "Analizando contenido..." | tee -a "$SEARCH_LOG"
            strings "${WORK_DIR}/raw_block_${block}.dat" | \
            grep -E "BMS.*backup|BACKUP_HEADER" > "${WORK_DIR}/raw_block_${block}.txt"
            
            if [ -s "${WORK_DIR}/raw_block_${block}.txt" ]; then
                echo -e "Contenido encontrado:" | tee -a "$SEARCH_LOG"
                cat "${WORK_DIR}/raw_block_${block}.txt" | tee -a "$SEARCH_LOG"
                
                # Intentar recuperar
                for tipo in BMS BMSJoseDiego BMSsa; do
                    echo -e "\nVerificando si es backup tipo $tipo..." | tee -a "$SEARCH_LOG"
                    if validate_backup_integrity "${WORK_DIR}/raw_block_${block}.dat" "${TAMANOS_ESPERADOS[$tipo]}"; then
                        echo -e "${GREEN}✓ Backup válido tipo $tipo encontrado${NC}" | tee -a "$SEARCH_LOG"
                        mv "${WORK_DIR}/raw_block_${block}.dat" \
                           "${WORK_DIR}/${tipo}/originales/recovered_block_${block}_${TIMESTAMP}.bak"
                        break
                    else
                        echo -e "No es un backup válido tipo $tipo" | tee -a "$SEARCH_LOG"
                    fi
                done
            else
                echo -e "No se encontró contenido relevante" | tee -a "$SEARCH_LOG"
                rm "${WORK_DIR}/raw_block_${block}.dat"
            fi
            echo -e "=== Fin Análisis Bloque $block ===\n" | tee -a "$SEARCH_LOG"
        done < "$PATTERNS_FOUND.blocks"
    fi
    
    # Resumen final
    {
        echo -e "\n=== Resumen de Búsqueda ==="
        echo "Fecha fin: $(date)"
        echo "Bloques analizados: $total_blocks"
        echo "Patrones encontrados: $(wc -l < "$PATTERNS_FOUND.blocks")"
        echo "============================"
    } | tee -a "$SEARCH_LOG"
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
}

# Verificar herramientas necesarias
check_tools() {
    local missing_tools=()
    local tools=("dd" "grep" "pv" "parallel" "strings" "hexdump")
    
    echo -e "${YELLOW}Verificando herramientas necesarias...${NC}"
    
    for tool in "${tools[@]}"; do
        if ! command -v "$tool" &>/dev/null; then
            missing_tools+=("$tool")
        fi
    done
    
    if [ ${#missing_tools[@]} -ne 0 ]; then
        echo -e "${RED}Faltan las siguientes herramientas: ${missing_tools[*]}${NC}"
        echo "Intente instalarlas manualmente con:"
        echo "pacman -Sy ${missing_tools[*]}"
        exit 1
    fi
    
    echo -e "${GREEN}✓ Todas las herramientas necesarias están instaladas${NC}"
}

# Iniciar proceso
main "$@" 