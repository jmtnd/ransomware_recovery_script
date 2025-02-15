# Ransomware Recovery Script

## Descripción
Ransomware Recovery Script es un conjunto de herramientas en Bash diseñadas para analizar, recuperar y reportar backups afectados por ataques de ransomware. Estas utilidades permiten crear imágenes forenses, examinar sectores del disco en busca de respaldos originales y validar la integridad de archivos, facilitando la identificación de aquellos que han sido cifrados.

**Importante:**  
- Está orientado a sistemas Linux y requiere privilegios de superusuario (root) para montar dispositivos y acceder directamente a discos.
- Antes de ejecutar cualquiera de estos scripts, realiza siempre una copia de seguridad completa de tus datos.
- Utiliza este conjunto de herramientas en entornos controlados y de prueba para evitar la pérdida de información.

## Características
- **Recuperación de Backups:**  
  Escanea el disco en busca de respaldos originales y procede a recuperarlos.
  
- **Análisis de Integridad:**  
  Verifica la integridad de los archivos recuperados mediante la comparación de tamaños y analiza la entropía para detectar posibles archivos cifrados.

- **Creación de Imágenes Forenses:**  
  Emplea herramientas como dcfldd para generar imágenes forenses, asegurando que la evidencia no sea alterada durante el proceso.

- **Análisis y Reporte de Backups:**  
  Detecta y lista tanto archivos cifrados (por ejemplo, con extensión `.nigra`) como respaldos no cifrados, generando informes detallados con información relevante (fecha original, email del atacante, estadísticas y estructura de directorios).

- **Búsqueda en Sectores y Bloques:**  
  Realiza un escaneo profundo sobre el disco, analizando bloques específicos en busca de patrones y firmas conocidos de backups.

## Requisitos
- **Sistema Operativo:** Linux (con soporte para NTFS-3G cuando se accede a particiones NTFS)
- **Herramientas y Utilidades:**  
  - Bash
  - dd
  - grep
  - pv
  - parallel
  - strings
  - hexdump
  - dcfldd (para la creación de imágenes forenses)
  - tree (opcional, para visualizar la estructura de directorios)
  
- **Privilegios:**  
  Se requieren permisos de root para ejecutar operaciones de montaje y lecturas directas del disco.

## Instalación
1. Clona el repositorio:
   ```bash
   git clone https://github.com/jmtnd/ransomware_recovery_script.git
   ```
2. Entra en el directorio del proyecto:
   ```bash
   cd ransomware_recovery_script
   ```
3. Instala (o verifica) que las herramientas necesarias estén instaladas. Por ejemplo, en distribuciones basadas en Arch Linux:
   ```bash
   sudo pacman -Sy dd grep pv parallel strings dcfldd hexdump tree
   ```
   Ajusta este comando según el gestor de paquetes de tu distribución.

4. Revisa el archivo `.gitignore` para confirmar que se ignoran archivos y directorios temporales (logs, datos recuperados, etc.).

## Uso
El proyecto proporciona dos scripts principales:

### 1. Recuperación de Backups
Ejecuta el script principal de recuperación para analizar y extraer backups desde el disco:
   ```bash
   sudo bash script_recuperacion.sh
   ```
Este script se encarga de:
- Montar el disco de forma segura en modo solo lectura.
- Escanear en bloques y sectores buscando patrones y firmas de respaldo.
- Extraer datos y validar la integridad de los archivos recuperados.
- Registrar detalladamente el proceso en distintos archivos de log.

### 2. Análisis de Backups
Para generar un informe detallado de los respaldos presentes en el sistema, utiliza:
   ```bash
   sudo bash analizar_backups.sh
   ```
Este script realiza lo siguiente:
- Verifica que el disco esté montado correctamente.
- Identifica y lista archivos cifrados (con extensión `.nigra`) y archivos no cifrados (extensión `.bak`).
- Genera un reporte en el archivo `analisis_backups.txt` que incluye información detallada (e.g., fecha original, email del atacante) y estadísticas del uso del disco.

## Advertencias y Recomendaciones
- **Precaución:** Debido a que estos scripts acceden a nivel de hardware y directamente a la estructura del disco, una configuración incorrecta puede ocasionar pérdida de datos.  
- **Copia de Seguridad:** Realiza siempre una copia completa de tus datos antes de cualquier operación de recuperación.
- **Configuración:** Revisa las variables de configuración en los scripts (como rutas de montado, dispositivos de origen y tamaños de bloques) y adáptalas según tu entorno.
- **Entorno Controlado:** Se recomienda probar primero en un entorno de laboratorio o con imágenes forenses antes de aplicarlo en producción.

## Contribución
¡Las contribuciones son bienvenidas! Si deseas aportar mejoras o reportar incidencias, sigue estos pasos:
1. Haz un fork del proyecto.
2. Crea una nueva rama para tu cambio:
   ```bash
   git checkout -b feature/tu-nueva-funcionalidad
   ```
3. Realiza tus modificaciones y realiza commits con mensajes descriptivos:
   ```bash
   git commit -m "Describe brevemente tu cambio"
   ```
4. Sube la rama a tu repositorio:
   ```bash
   git push origin feature/tu-nueva-funcionalidad
   ```
5. Abre un Pull Request en GitHub para revisión.

## Licencia
Este proyecto está licenciado bajo la Licencia MIT. Consulta el archivo `LICENSE` para más detalles.

## Contacto
Si tienes preguntas, sugerencias o encuentras algún problema, no dudes en contactarme:

- Jaime - jaime911@gmail.com

Enlace del proyecto:  
[https://github.com/jmtnd/ransomware_recovery_script](https://github.com/jmtnd/ransomware_recovery_script)
