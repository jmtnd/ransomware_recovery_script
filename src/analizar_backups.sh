#!/bin/bash

# Colores para mejor visualización
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Verificar que el disco esté montado
if ! mountpoint -q /mnt/sda2; then
    echo -e "${RED}El disco no está montado en /mnt/sda2${NC}"
    exit 1
fi

BACKUP_DIR="/mnt/sda2/BMS/RespaldosBMS"
REPORT_FILE="analisis_backups.txt"

echo "=== Análisis de Backups ===" | tee "$REPORT_FILE"
echo "Fecha: $(date)" | tee -a "$REPORT_FILE"
echo "" | tee -a "$REPORT_FILE"

# Analizar archivos cifrados
echo "Archivos cifrados encontrados:" | tee -a "$REPORT_FILE"
echo "--------------------------------" | tee -a "$REPORT_FILE"
find "$BACKUP_DIR" -type f -name "*\[*@*\]\.nigra" | while read -r file; do
    nombre=$(basename "$file")
    fecha_original=$(echo "$nombre" | grep -oP '\d{4}_\d{2}_\d{2}_\d{6}')
    email=$(echo "$nombre" | grep -oP '\[.*@.*\]' | tr -d '[]')
    echo -e "${RED}Archivo: $nombre${NC}" | tee -a "$REPORT_FILE"
    echo "  Fecha original: $fecha_original" | tee -a "$REPORT_FILE"
    echo "  Email atacante: $email" | tee -a "$REPORT_FILE"
    echo "" | tee -a "$REPORT_FILE"
done

# Analizar archivos no cifrados
echo "Archivos no cifrados:" | tee -a "$REPORT_FILE"
echo "--------------------------------" | tee -a "$REPORT_FILE"
find "$BACKUP_DIR" -type f -name "*.bak" ! -name "*\[*@*\]*" | while read -r file; do
    echo -e "${GREEN}$(basename "$file")${NC}" | tee -a "$REPORT_FILE"
done

# Análisis profundo
echo -e "${BLUE}=== Análisis Profundo de Directorio ===${NC}"
echo -e "${YELLOW}Directorio: $BACKUP_DIR${NC}"
echo

# Listar archivos grandes
echo "Archivos grandes (>10GB):"
echo "----------------------------------------"
find "$BACKUP_DIR" -type f -size +10G -exec ls -lh {} \; | \
    while read -r line; do
        echo -e "${GREEN}$line${NC}"
    done

# Mostrar extensiones
echo -e "\nExtensiones encontradas:"
echo "----------------------------------------"
find "$BACKUP_DIR" -type f -name "*.*" | sed 's/.*\.//' | sort | uniq -c | sort -nr

# Estructura de directorios
echo -e "\nEstructura de directorios:"
echo "----------------------------------------"
tree -L 3 "$BACKUP_DIR" | head -n 20

# Buscar archivos NIGRA
echo -e "\nArchivos posiblemente cifrados (NIGRA):"
echo "----------------------------------------"
find "$BACKUP_DIR" -type f -name "*.NIGRA" -exec ls -lh {} \;

# Top archivos más grandes
echo -e "\nTop 10 archivos más grandes:"
echo "----------------------------------------"
find "$BACKUP_DIR" -type f -exec ls -lh {} \; | sort -rh -k5 | head -n 10

# Estadísticas
echo -e "\nEstadísticas generales:"
echo "----------------------------------------"
echo "Espacio total usado: $(du -sh "$BACKUP_DIR" | cut -f1)"
echo "Número total de archivos: $(find "$BACKUP_DIR" -type f | wc -l)"
echo "Número de archivos >10GB: $(find "$BACKUP_DIR" -type f -size +10G | wc -l)" 