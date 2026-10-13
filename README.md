# 🛡️ Nemesis — Auditor Universal de Seguridad, Higiene y Cumplimiento para Repositorios

> **GitHub Action y motor CLI de DevSecOps, Repo Hygiene & Compliance construido con Deno y TypeScript.**  
> Audita automáticamente secretos expuestos, vulnerabilidades de código (SAST), dependencias vulnerables (SCA), licencias open source (Copyleft), generación de SBOM (CycloneDX), limpieza e higiene del repositorio y supresión de falsos positivos con `.nemesis.yml`.

---

## 🚀 Capacidades Principales

* 🔑 **Secret Scanning (Gitleaks):** Detecta claves de API, tokens privados, certificados y contraseñas filtradas en el código e historial de commits.
* 🛡️ **SAST - Análisis Estático de Código (Semgrep):** Encuentra vulnerabilidades comunes (inyecciones SQL, XSS, RCE, criptografía insegura) en más de 30 lenguajes sin compilar.
* 📦 **SCA - Análisis de Dependencias (Trivy):** Detecta CVEs conocidos en gestores de paquetes (`npm`, `pip`, `go`, `cargo`, `maven`) y fallos de infraestructura (Dockerfile, K8s).
* 📜 **Auditoría de Licencias & SBOM (CycloneDX):**
  * Detecta licencias copyleft de alto riesgo (`GPL-3.0`, `AGPL-3.0`, `SSPL`) que comprometan código propietario.
  * Genera automáticamente el inventario de software **SBOM en estándar CycloneDX** (`sbom.cyclonedx.json`) para auditorías regulatorias (NIST, ISO 27001).
* 🧹 **Higiene y Limpieza del Repositorio (Nativo Deno):**
  * **Archivos Tóxicos/Basura:** Detecta archivos `.env`, `.DS_Store`, `Thumbs.db`, `*.log`, temporales `*.bak` o dumps `*.dump`.
  * **Carpetas Indebidas:** Alerta si se suben directorios de dependencias o compilación (`node_modules/`, `vendor/`, `__pycache__/`).
  * **Archivos Pesados (Blob Bloat):** Identifica archivos mayores a 10 MB (o el límite que configures) que deberían usar Git LFS.
  * **Salud y Gobernanza:** Valida la presencia de `.gitignore`, `README.md` y `LICENSE`.
* ⚡ **Escaneo Diferencial (`--diff`):**
  * En Pull Requests, audita **únicamente los archivos modificados**, reduciendo el tiempo de ejecución en repositorios grandes de minutos a pocos segundos.
* 🎯 **Manejo de Falsos Positivos con `.nemesis.yml`:**
  * Permite suprimir alertas justificadas indicando ID de regla, CVE o ruta, exigiendo obligatoriamente un motivo (`reason`) y fecha de caducidad opcional (`expires`).
* 📢 **Alertas Webhook (Slack & Discord):**
  * Despacha tarjetas resumen formateadas a canales de Slack o Discord cuando termina la auditoría.
* 💬 **Feedback Inteligente en Pull Requests:**
  * Comentario Markdown tipo semáforo con actualización *in-place* (sin spam) y anotaciones directas en el diff del PR.
* 📑 **Integración SARIF Nativa:**
  * Alertas visibles en la pestaña **Security -> Code Scanning** de GitHub.
* 🚀 **Caché Automático:**
  * Preserva la base de datos de vulnerabilidades entre ejecuciones mediante `actions/cache@v4`.

---

## 📦 Uso Rápido: Integrar en cualquier Repositorio

Para auditar cualquier repositorio automáticamente en cada *push* o *pull request*, crea el archivo `.github/workflows/security-audit.yml`:

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
        uses: glastor-dev/nemesis@master
        with:
          fail-on-critical: false     # Ponlo en 'true' para bloquear merges con fallos críticos
          diff-mode: true             # Escanea únicamente lo modificado en el PR
          scan-hygiene: true          # Revisa limpieza y archivos no deseados
          scan-licenses: true         # Revisa licencias restrictivas
          generate-sbom: true         # Genera reporte CycloneDX SBOM
          slack-webhook-url: ${{ secrets.SLACK_WEBHOOK }} # Opcional
          upload-sarif: true
```

---

## 🎯 Configuración de Exclusiones y Falsos Positivos (`.nemesis.yml`)

Para suprimir alertas justificadas (por ejemplo, credenciales mockeadas en un test o un CVE mitigado por infraestructura), añade `.nemesis.yml` en la raíz de tu repositorio:

```yaml
version: "1"

ignore:
  - id: "SECRET-aws-access-token-1"
    path: "tests/mocks/**"
    reason: "Credencial falsa para pruebas unitarias"

  - cve: "CVE-2023-12345"
    reason: "Mitigado por reglas de firewall WAF en producción"
    expires: "2026-12-31" # Expira para forzar re-evaluación

settings:
  maxFileSizeMb: 15
  requireLicense: true
```

---

## ⚙️ Parámetros de Configuración (`inputs`)

| Parámetro | Tipo | Por Defecto | Descripción |
| :--- | :---: | :---: | :--- |
| `target-path` | string | `.` | Directorio del proyecto a auditar. |
| `diff-mode` | boolean | `false` | Escanea solo archivos modificados en el PR/commit actual. |
| `diff-base-ref` | string | `'origin/main'` | Rama base para la comparación diferencial. |
| `scan-secrets` | boolean | `true` | Habilita el escaneo de secretos (Gitleaks). |
| `scan-sast` | boolean | `true` | Habilita el escaneo estático de código (Semgrep). |
| `scan-sca` | boolean | `true` | Habilita el escaneo de dependencias (Trivy). |
| `scan-hygiene` | boolean | `true` | Habilita la verificación de limpieza e higiene del repo. |
| `scan-licenses` | boolean | `true` | Audita licencias copyleft restrictivas. |
| `generate-sbom` | boolean | `true` | Genera archivo CycloneDX SBOM (`sbom.cyclonedx.json`). |
| `max-file-size-mb`| string | `'10'` | Tamaño máximo de archivo en MB antes de alertar. |
| `require-license` | boolean | `false` | Exige la presencia obligatoria de un archivo LICENSE en la raíz. |
| `fail-on-critical` | boolean | `false` | Falla el paso del pipeline si hay vulnerabilidades `CRITICAL`. |
| `fail-on-high` | boolean | `false` | Falla el paso si hay vulnerabilidades `HIGH` o `CRITICAL`. |
| `post-pr-comment` | boolean | `true` | Publica/actualiza un comentario resumen en el PR. |
| `create-annotations`| boolean | `true` | Marca las líneas afectadas en el diff del PR. |
| `upload-sarif` | boolean | `true` | Sube el reporte SARIF a la pestaña Security de GitHub. |
| `slack-webhook-url`| string | `''` | URL de Webhook para alertas en Slack. |
| `discord-webhook-url`| string| `''` | URL de Webhook para alertas en Discord. |
| `config-file` | string | `''` | Ruta personalizada a `.nemesis.yml`. |

---

## 💻 Uso Local (CLI con Deno)

```bash
# Auditar todo el repositorio (Seguridad + Higiene + Licencias)
deno task start --path .

# Modo diferencial: auditar solo archivos modificados frente a main
deno task start --path . --diff

# Usar archivo de exclusiones personalizado
deno task start --path . --config ./mi-config.yml

# Auditar solo higiene y limpieza
deno task start --path . --hygiene --max-file-size 5

# Enviar alerta a Discord/Slack al finalizar
deno task start --path . --discord-webhook https://discord.com/api/webhooks/...

# Compilar binario autónomo para Windows/Linux/macOS
deno task compile
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
│   ├── config/
│   │   └── schema.ts              # Validador Zod y motor de exclusiones (.nemesis.yml)
│   ├── main.ts                    # Punto de entrada principal y orquestador
│   ├── scanners/
│   │   ├── base.ts                # Interfaz base de escáneres
│   │   ├── gitleaks.ts            # Escáner de secretos
│   │   ├── semgrep.ts             # Escáner SAST
│   │   ├── trivy.ts               # Escáner SCA y dependencias
│   │   ├── hygiene.ts             # Escáner nativo de limpieza e higiene del repo
│   │   └── license.ts             # Escáner de licencias y generador de SBOM
│   ├── reporters/
│   │   ├── console.ts             # Salida formateada con colores para consola
│   │   ├── markdown.ts            # Generador de reportes en Markdown para PRs
│   │   ├── sarif.ts               # Generador de reportes estándar SARIF 2.1.0
│   │   └── webhook.ts             # Notificador para Slack y Discord
│   ├── github/
│   │   ├── pr-commenter.ts        # Comentador idempotente en PRs (sin spam)
│   │   └── annotator.ts           # Anotador de líneas en el diff de GitHub
│   └── utils/
│       ├── diff.ts                # Motor de escaneo diferencial por Git
│       ├── exec.ts                # Ejecutor seguro de subprocesos con timeout
│       └── tool-checker.ts        # Comprobador y fallback de herramientas
├── .nemesis.yml                   # Plantilla de configuración de falsos positivos
├── action.yml                     # Definición de la GitHub Composite Action con caché
├── deno.json                      # Configuración, tareas y dependencias de Deno
└── README.md                      # Documentación completa
```

---

## 📄 Licencia
Distribuido bajo la licencia MIT.
