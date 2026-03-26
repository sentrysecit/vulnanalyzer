# Guía de Uso - VulnAnalyzer

## Índice

1. [Instalación](#instalación)
2. [CLI - Uso desde Consola](#cli---uso-desde-consola)
3. [Interfaz Web](#interfaz-web)
4. [API REST](#api-rest)
5. [Base de Datos](#base-de-datos)

---

## Instalación

### Requisitos Previos

- Python 3.8+
- nmap instalado en el sistema

### Instalación de Dependencias

```bash
pip install -r requirements.txt
```

---

## CLI - Uso desde Consola

### Comandos Disponibles

#### 1. Descubrimiento de Hosts

Descubre hosts activos en una red.

```bash
python main.py discover <rango_red> [opciones]
```

**Ejemplo:**
```bash
python main.py discover 192.168.1.0/24
python main.py discover 10.0.0.0/24 -o hosts.json
```

**Opciones:**
- `-o, --output <archivo>` - Guardar resultados en JSON

---

#### 2. Escaneo de Vulnerabilidades

Escanea un objetivo en busca de vulnerabilidades.

```bash
python main.py scan <objetivo> [opciones]
```

**Ejemplo:**
```bash
python main.py scan 192.168.1.10
python main.py scan 192.168.1.10 --type quick
python main.py scan 192.168.1.10 --type full -o resultados.json
python main.py scan 192.168.1.10 -o resultados.json --report reporte.html
```

**Opciones:**
- `--type {quick|full|stealth}` - Tipo de escaneo
  - `quick`: Puertos comunes
  - `full`: Todos los puertos + detección de SO
  - `stealth`: Escaneo lento y sigiloso
- `-o, --output <archivo>` - Guardar resultados en JSON
- `--report <archivo.html>` - Generar reporte HTML

---

#### 3. Explotación

Ejecuta exploits basados en vulnerabilidades detectadas.

```bash
python main.py exploit [opciones]
```

**Ejemplo:**
```bash
python main.py exploit --list
python main.py exploit --scan-file resultados.json
python main.py exploit --scan-file resultados.json --target 192.168.1.10 --exploit nombre_exploit
```

**Opciones:**
- `--scan-file <archivo>` - Archivo con resultados de escaneo previo
- `--target <objetivo>` - Objetivo específico
- `--exploit <nombre>` - Exploit específico a ejecutar
- `--list` - Listar exploits disponibles

---

#### 4. Integración MITRE Caldera

Interactúa con MITRE Caldera para emulación de adversarios.

```bash
python main.py caldera [opciones]
```

**Ejemplo:**
```bash
python main.py caldera --deploy --platform linux
python main.py caldera --run --adversary "APT29"
```

**Opciones:**
- `--deploy` - Desplegar agente en el objetivo
- `--platform {windows|linux|darwin}` - Plataforma del agente
- `--run` - Ejecutar evaluación con Caldera
- `--adversary <nombre>` - Perfil de adversario a usar

---

#### 5. Interfaz Web

Inicia el servidor web para acceder a la interfaz gráfica.

```bash
python main.py web [opciones]
```

**Ejemplo:**
```bash
python main.py web
python main.py web --port 8080
python main.py web --host 127.0.0.1 --port 3000
```

**Opciones:**
- `--host <direccion>` - Host donde bindear (default: 0.0.0.0)
- `--port <puerto>` - Puerto donde bindear (default: 8000)
- `--reload` - Habilitar auto-reload para desarrollo

---

## Interfaz Web

La interfaz web proporciona una forma visual de gestionar análisis y generar reportes.

### Acceder

1. Inicia el servidor web:
   ```bash
   python main.py web
   ```

2. Abre tu navegador en:
   - **Dashboard:** http://localhost:8000/web/dashboard
   - **Lista de Análisis:** http://localhost:8000/web/scans
   - **Nuevo Análisis:** http://localhost:8000/web/scan/new

### Funcionalidades

#### Dashboard

Muestra un resumen con:
- Total de análisis realizados
- Targets analizados
- Total de vulnerabilidades encontradas
- Distribución por severidad (gráfico)
- Top 5 targets más vulnerables
- Análisis recientes

#### Lista de Análisis

Permite:
- Ver todos los análisis realizados
- Filtrar por target, tipo y estado
- Buscar por nombre de objetivo
- Ver detalles de cada análisis
- Eliminar análisis

#### Detalle de Análisis

Muestra:
- Información del scan (target, tipo, estado, fecha)
- Puertos y servicios detectados
- Vulnerabilidades encontradas con severidad
- Recomendaciones de remediación
- Enlaces para descargar reportes

#### Generar Nuevo Análisis

Formulario para:
- Ingresar objetivo (IP, dominio o rango CIDR)
- Seleccionar tipo de escaneo
- Iniciar análisis

---

## API REST

La API REST permite integrar VulnAnalyzer con otras herramientas o automatizar procesos.

### Endpoints

| Método | Endpoint | Descripción |
|--------|----------|-------------|
| GET | `/api/scans` | Lista de análisis |
| POST | `/api/scans` | Crear nuevo análisis |
| GET | `/api/scans/{id}` | Detalle de un análisis |
| DELETE | `/api/scans/{id}` | Eliminar análisis |
| GET | `/api/scans/stats` | Estadísticas globales |
| GET | `/api/reports/{id}` | Datos del reporte |
| GET | `/api/reports/{id}/html` | Reporte en HTML |
| GET | `/api/reports/{id}/download/{format}` | Descargar reporte |

### Documentación Interactiva

Accede a la documentación Swagger en: http://localhost:8000/docs

### Ejemplos con curl

**Listar análisis:**
```bash
curl http://localhost:8000/api/scans
```

**Crear análisis:**
```bash
curl -X POST http://localhost:8000/api/scans \
  -H "Content-Type: application/json" \
  -d '{"target": "192.168.1.10", "scan_type": "quick"}'
```

**Ver análisis específico:**
```bash
curl http://localhost:8000/api/scans/1
```

**Descargar reporte JSON:**
```bash
curl -O http://localhost:8000/api/reports/1/download/json
```

**Ver estadísticas:**
```bash
curl http://localhost:8000/api/scans/stats
```

---

## Base de Datos

VulnAnalyzer utiliza SQLite para almacenar análisis de forma persistente.

### Ubicación

La base de datos se encuentra en:
```
data/vulnanalyzer.db
```

### Estructura

**Tabla: scans**

| Campo | Tipo | Descripción |
|-------|------|-------------|
| id | INTEGER | ID único del análisis |
| target | VARCHAR | Objetivo escaneado |
| scan_type | VARCHAR | Tipo de escaneo (quick/full/stealth) |
| status | VARCHAR | Estado (pending/running/completed/failed) |
| created_at | DATETIME | Fecha de creación |
| completed_at | DATETIME | Fecha de finalización |
| results_json | TEXT | Resultados en JSON |
| error_message | TEXT | Mensaje de error si falló |
| total_vulnerabilities | INTEGER | Total de vulnerabilidades |
| critical_count | INTEGER | Vulnerabilidades críticas |
| high_count | INTEGER | Vulnerabilidades altas |
| medium_count | INTEGER | Vulnerabilidades medias |
| low_count | INTEGER | Vulnerabilidades bajas |
| info_count | INTEGER | Informativas |

### Acceso Directo

Puedes consultar la base de datos directamente con sqlite3:

```bash
sqlite3 data/vulnanalyzer.db
```

**Consultas útiles:**

```sql
-- Ver todas las tablas
.schema

-- Listar análisis recientes
SELECT * FROM scans ORDER BY created_at DESC LIMIT 10;

-- Análisis con más vulnerabilidades críticas
SELECT target, critical_count FROM scans ORDER BY critical_count DESC;

-- Estadísticas generales
SELECT 
  COUNT(*) as total,
  SUM(total_vulnerabilities) as total_vulns,
  SUM(critical_count) as total_critical
FROM scans;
```

---

## Flujo de Trabajo Típico

### Opción 1: Solo CLI

```bash
# 1. Descubrir hosts
python main.py discover 192.168.1.0/24 -o hosts.json

# 2. Escanear objetivo
python main.py scan 192.168.1.10 --type full -o resultados.json

# 3. Generar reporte
python main.py scan 192.168.1.10 --type full --report reporte.html

# 4. Listar exploits disponibles
python main.py exploit --list

# 5. Ejecutar exploits
python main.py exploit --scan-file resultados.json
```

### Opción 2: CLI + Web

```bash
# 1. Iniciar interfaz web
python main.py web --port 8000

# 2. En el navegador, ir a Nuevo Análisis
# 3. Ingresar target y tipo de scan
# 4. El análisis se guardará automáticamente en la BD
# 5. Ver resultados, reportes y estadísticas desde la web
```

### Opción 3: API + Herramientas Externas

```bash
# 1. Iniciar servidor
python main.py web

# 2. Integrar con otras herramientas usando la API REST
curl -X POST http://localhost:8000/api/scans \
  -H "Content-Type: application/json" \
  -d '{"target": "example.com", "scan_type": "quick"}'
```

---

## Configuración

### Variables de Entorno (.env)

```env
CALDERA_BASE_URL=http://localhost:8888
CALDERA_API_KEY=your-api-key
```

### Configuración General (config/settings.py)

```python
DEBUG = True
VERSION = "1.0.0"
DEFAULT_SCAN_TYPE = "full"
DEFAULT_THREADS = 10
DEFAULT_TIMEOUT = 30
```

---

## Solución de Problemas

### Error: nmap no encontrado

```bash
# Linux
sudo apt install nmap

# macOS
brew install nmap

# Windows
# Descargar desde https://nmap.org/download.html
```

### Puerto en uso

```bash
# Usar otro puerto
python main.py web --port 8080
```

### Error de permisos en base de datos

```bash
chmod 755 data/
chmod 644 data/vulnanalyzer.db
```
