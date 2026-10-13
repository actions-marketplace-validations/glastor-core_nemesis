# 🛡️ Nemesis — Auditor de Seguridad y Limpieza Universal para Repositorios

> **GitHub Action y motor CLI de DevSecOps & Repo Hygiene construido con Deno y TypeScript.**  
> Audita automáticamente secretos expuestos, vulnerabilidades de código (SAST), dependencias vulnerables (SCA) y **limpieza/higiene del repositorio** (archivos tóxicos, blobs pesados y estándares de salud), reportando los hallazgos directamente en el Pull Request y en la pestaña de Seguridad de GitHub.

---

## 🚀 Capacidades Principales

* 🔑 **Secret Scanning (Gitleaks):** Detecta claves de API, tokens privados, certificados y contraseñas filtradas en el código e historial de commits.
* 🛡️ **SAST - Análisis Estático de Código (Semgrep):** Encuentra vulnerabilidades comunes (inyecciones SQL, XSS, RCE, criptografía insegura) en más de 30 lenguajes sin necesidad de compilar.
* 📦 **SCA - Análisis de Dependencias (Trivy):** Detecta CVEs conocidos en tus gestores de paquetes (`package.json`, `requirements.txt`, `go.mod`, `pom.xml`, `Cargo.lock`, etc.) y malas configuraciones de Dockerfile/K8s.
* 🧹 **Higiene y Limpieza del Repositorio (Nativo Deno):**
  * **Archivos Tóxicos/Basura:** Detecta archivos `.env`, `.DS_Store`, `Thumbs.db`, `*.log`, temporales `*.bak` o dumps `*.dump`.
  * **Carpetas Indebidas:** Alerta si se suben directorios de dependencias o compilación (`node_modules/`, `vendor/`, `__pycache__/`).
  * **Archivos Pesados (Blob Bloat):** Identifica archivos mayores a 10 MB (o el límite que configures) que deberían usar Git LFS.
  * **Salud y Gobernanza:** Valida la presencia de `.gitignore`, `README.md` y `LICENSE`.
  * **Inconsistencias de Git:** Detecta archivos que están siendo rastreados por Git a pesar de figurar en el `.gitignore`.
* 💬 **Feedback Inteligente en Pull Requests:** Publica un comentario resumido en Markdown tipo "semáforo" (con actualización automática *in-place* para evitar spam).
* 📑 **Integración SARIF Nativa:** Exporta reportes compatibles con GitHub Advanced Security para ver las alertas directamente en la pestaña **Security -> Code Scanning**.
* ⚡ **Impulsado por Deno & TypeScript:**
  * Cero configuración de empaquetadores (sin Babel, esbuild ni Webpack).
  * Sin carpeta `node_modules` pesada en tu repositorio.
  * Capaz de compilarse en un binario autónomo único con `deno compile`.

---

## 📦 Uso Rápido: Integrar en cualquier Repositorio

Para auditar cualquier repositorio automáticamente en cada *push* o *pull request*, solo crea el archivo `.github/workflows/security-audit.yml`:

```yaml
name: Security & Hygiene Audit

on:
  push:
    branches: [ main, master ]
  pull_request:
    branches: [ main, master ]

permissions:
  contents: read
  pull-requests: write
  security-events: write

jobs:
  audit:
    name: Nemesis Audit
    runs-on: ubuntu-latest
    steps:
      - name: Checkout del repositorio
        uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - name: Ejecutar Auditor Nemesis
        uses: tu-usuario/nemesis@main # o @v1
        with:
          fail-on-critical: false # Cambia a 'true' si quieres bloquear merges ante fallos críticos
          scan-hygiene: true      # Habilita chequeos de repositorio limpio
          max-file-size-mb: '10'  # Límite máximo para alertar archivos pesados
          post-pr-comment: true
          upload-sarif: true
```

---

## ⚙️ Parámetros de Configuración (`inputs`)

| Parámetro | Tipo | Por Defecto | Descripción |
| :--- | :---: | :---: | :--- |
| `target-path` | string | `.` | Directorio del proyecto a auditar. |
| `scan-secrets` | boolean | `true` | Habilita el escaneo de secretos (Gitleaks). |
| `scan-sast` | boolean | `true` | Habilita el escaneo estático de código (Semgrep). |
| `scan-sca` | boolean | `true` | Habilita el escaneo de dependencias (Trivy). |
| `scan-hygiene` | boolean | `true` | Habilita la verificación de limpieza e higiene del repo. |
| `max-file-size-mb`| string | `'10'` | Tamaño máximo de archivo en MB antes de alertar por sobrepeso. |
| `require-license` | boolean | `false` | Exige la presencia obligatoria de un archivo LICENSE en la raíz. |
| `fail-on-critical` | boolean | `false` | Falla el paso del pipeline si hay vulnerabilidades `CRITICAL`. |
| `fail-on-high` | boolean | `false` | Falla el paso si hay vulnerabilidades `HIGH` o `CRITICAL`. |
| `post-pr-comment` | boolean | `true` | Publica/actualiza un comentario resumen en el PR. |
| `create-annotations`| boolean | `true` | Marca las líneas de código afectadas directamente en el diff del PR. |
| `upload-sarif` | boolean | `true` | Sube el reporte SARIF a la pestaña Security de GitHub. |
| `output-dir` | string | `.nemesis-reports` | Carpeta local donde se guardan los reportes (`.json`, `.md`, `.sarif`). |
| `github-token` | string | `${{ github.token }}` | Token para autenticación en la API de GitHub. |

---

## 💻 Uso Local (CLI con Deno)

También puedes correr Nemesis directamente en tu máquina local o en tu servidor de integración continua sin GitHub:

### Requisitos locales:
* [Deno](https://deno.land/) (v2.x o superior)

### 1. Ejecutar auditoría:
```bash
# Auditar el directorio actual con todos los módulos (Seguridad + Higiene)
deno task start --path .

# Auditar únicamente limpieza e higiene del repositorio
deno task start --path . --hygiene

# Ajustar límite de tamaño de archivos a 5 MB
deno task start --path . --hygiene --max-file-size 5

# Auditar solo secretos
deno task start --path . --secrets

# Auditar solo dependencias y fallar si hay vulnerabilidades críticas
deno task start --path . --sca --fail-on-critical
```

### 2. Compilar un binario autónomo (sin dependencias):
Puedes compilar el CLI completo a un archivo binario independiente:

```bash
# Compilar binario nativo (nemesis o nemesis.exe en bin/)
deno task compile

# Ejecutar el binario generado
./bin/nemesis --help
./bin/nemesis --path .
```

---

## 📁 Estructura del Proyecto

```text
nemesis/
├── .github/
│   └── workflows/
│       ├── ci.yml                 # Pipeline CI y prueba de compilación de Nemesis
│       └── audit.yml              # Reusable Workflow para invocar desde otros repos
├── src/
│   ├── types.ts                   # Interfaces y tipos del dominio de seguridad e higiene
│   ├── config.ts                  # Parser unificado de inputs de GitHub y CLI
│   ├── main.ts                    # Punto de entrada principal y orquestador
│   ├── scanners/
│   │   ├── base.ts                # Interfaz base de escáneres
│   │   ├── gitleaks.ts            # Escáner de secretos
│   │   ├── semgrep.ts             # Escáner SAST
│   │   ├── trivy.ts               # Escáner SCA y dependencias
│   │   └── hygiene.ts             # Escáner nativo de limpieza e higiene del repo
│   ├── reporters/
│   │   ├── console.ts             # Salida formateada con colores para consola
│   │   ├── markdown.ts            # Generador de reportes en Markdown para PRs
│   │   └── sarif.ts               # Generador de reportes estándar SARIF 2.1.0
│   ├── github/
│   │   ├── pr-commenter.ts        # Comentador idempotente en PRs (sin spam)
│   │   └── annotator.ts           # Anotador de líneas en el diff de GitHub
│   └── utils/
│       ├── exec.ts                # Ejecutor seguro de subprocesos con timeout
│       └── tool-checker.ts        # Comprobador y fallback de herramientas
├── action.yml                     # Definición de la GitHub Composite Action
├── deno.json                      # Configuración, dependencias e imports de Deno
└── README.md                      # Documentación completa
```

---

## 📄 Licencia
Distribuido bajo la licencia MIT.
