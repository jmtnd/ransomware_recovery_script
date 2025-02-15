# Ransomware Recovery Script

## Descripción
Herramienta forense avanzada con IA para recuperación de backups BMS afectados por ransomware.

## Características Principales
- Sistema de IA para análisis predictivo
- Detección de clusters y patrones
- Puntuación inteligente de hallazgos
- Predicción de regiones prometedoras
- Optimización automática de la búsqueda
- Búsqueda profunda en sectores raw del disco
- Detección de firmas hexadecimales específicas
- Validación de integridad de backups
- Logging detallado del proceso
- Manejo robusto de errores

## Requisitos
- dd
- grep
- pv
- parallel
- strings
- hexdump
- ent

## Uso

1. Ejecutar el script principal:
```bash
sudo ./src/script_recuperacion.sh
```

2. Monitorear los logs en tiempo real:
```bash
tail -f /mnt/usb_recuperacion/recuperados_*/logs/search_*.log
tail -f /mnt/usb_recuperacion/recuperados_*/logs/patterns_*.txt
tail -f /mnt/usb_recuperacion/recuperados_*/logs/recovery_*.log
```

## Logs Generados
- search_[timestamp].log: Registro detallado de la búsqueda
- patterns_[timestamp].txt: Patrones encontrados
- recovery_[timestamp].log: Proceso de recuperación
