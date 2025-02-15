#!/bin/bash
# Script para mejorar el proceso en vivo sin interrumpir

# Configuración
CURRENT_WORKDIR=$(ls -td /mnt/usb_recuperacion/recuperados_* | head -n1)
MAIN_PID=$(pgrep -f "script_recuperacion.sh")

# Colores
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
NC='\033[0m'

# Función para implementar checkpointing
implement_checkpointing() {
    echo -e "${YELLOW}Implementando checkpointing sin interrumpir proceso...${NC}"
    
    # Crear archivo de checkpoint si no existe
    CHECKPOINT_FILE="${CURRENT_WORKDIR}/checkpoint.dat"
    touch "$CHECKPOINT_FILE"
    
    # Guardar último bloque procesado cada 100 bloques
    while true; do
        last_block=$(tail -n1 "${CURRENT_WORKDIR}/successful_blocks.txt" 2>/dev/null || echo "0")
        echo "$last_block" > "$CHECKPOINT_FILE"
        echo -e "${GREEN}Checkpoint guardado: Bloque $last_block${NC}"
        sleep 300  # Actualizar cada 5 minutos
    done
}

# Función para optimizar parámetros
optimize_parameters() {
    echo -e "${YELLOW}Optimizando parámetros de búsqueda...${NC}"
    
    # Analizar patrones de éxito
    if [ -f "${CURRENT_WORKDIR}/successful_blocks.txt" ]; then
        # Calcular distancia promedio entre hallazgos
        local avg_distance=$(awk 'NR>1{sum+=$1-prev;count++}END{print int(sum/count)}' "${CURRENT_WORKDIR}/successful_blocks.txt")
        
        if [ ! -z "$avg_distance" ] && [ "$avg_distance" -gt 0 ]; then
            echo -e "${GREEN}Distancia promedio entre hallazgos: $avg_distance bloques${NC}"
            echo "Sugerencia: Ajustar RAW_BLOCK_SIZE a $((avg_distance * 1024 * 1024))B"
        fi
    fi
}

# Menú principal
while true; do
    echo -e "\n${GREEN}=== Mejoras en Vivo ===${NC}"
    echo "1. Implementar checkpointing (permite reanudar)"
    echo "2. Optimizar parámetros de búsqueda"
    echo "3. Ver progreso y estadísticas"
    echo "4. Salir"
    
    read -p "Seleccione una opción: " option
    
    case $option in
        1) implement_checkpointing & ;;  # Ejecutar en background
        2) optimize_parameters ;;
        3) 
            echo -e "\n${YELLOW}=== Estadísticas ===${NC}"
            echo "Bloques procesados: $(wc -l < "${CURRENT_WORKDIR}/successful_blocks.txt" 2>/dev/null || echo 0)"
            echo "Último bloque: $(tail -n1 "${CURRENT_WORKDIR}/successful_blocks.txt" 2>/dev/null || echo 0)"
            tail -f "${CURRENT_WORKDIR}/logs/recovery_"*.log
            ;;
        4) exit 0 ;;
        *) echo -e "${RED}Opción inválida${NC}" ;;
    esac
done 