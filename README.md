# Ransomware Recovery Script

Herramienta para recuperación de backups BMS afectados por ransomware mediante análisis de sectores raw.

## Características
- Búsqueda profunda en sectores raw del disco
- Detección de backups cifrados vs originales
- Análisis de patrones y firmas hexadecimales
- Logging detallado del proceso
- Validación de integridad de backups

## Requisitos
- dd
- grep
- pv
- parallel
- strings
- hexdump
- ent

## Estructura
```
.
├── src/
│   ├── script_recuperacion.sh
│   └── analizar_backups.sh
├── docs/
├── tests/
└── logs/
```

## Uso

1. Análisis inicial:
```bash
sudo ./src/analizar_backups.sh
```

2. Recuperación:
```bash
sudo ./src/script_recuperacion.sh
```
