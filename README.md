# 🛡️ Nemesis — Auditor Universal & Bot de Auto-Remediación DevSecOps

<p align="center">
  <a href="https://github.com/marketplace/actions/nemesis-universal-security-hygiene-compliance-auditor"><img src="https://img.shields.io/badge/GitHub_Marketplace-Nemesis-purple.svg?logo=github&style=for-the-badge" alt="GitHub Marketplace" /></a>
  <a href="https://github.com/glastor-core/nemesis/actions"><img src="https://img.shields.io/github/actions/workflow/status/glastor-core/nemesis/ci.yml?branch=main&label=CI%20Audit&style=for-the-badge" alt="CI Status" /></a>
  <a href="https://deno.com"><img src="https://img.shields.io/badge/Deno-v2.x-000000.svg?logo=deno&style=for-the-badge" alt="Deno Runtime" /></a>
  <a href="https://cyclonedx.org"><img src="https://img.shields.io/badge/SBOM-CycloneDX%201.5-blueviolet?style=for-the-badge" alt="CycloneDX SBOM" /></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-MIT-blue.svg?style=for-the-badge" alt="MIT License" /></a>
</p>

> **Acción oficial de GitHub y motor CLI de DevSecOps, Repo Hygiene, Auto-Fix &
> Compliance construido con Deno y TypeScript.**\
> Audita automáticamente secretos expuestos (Gitleaks + motor nativo),
> vulnerabilidades de código (SAST Semgrep), dependencias vulnerables (SCA
> Trivy), licencias open source (Copyleft), genera inventario de software SBOM
> (CycloneDX 1.5), realiza **commits automáticos de limpieza (Auto-Fix)** y
> genera **sugerencias interactivas de 1-clic en Pull Requests**.

---

## 🚀 Capacidades Principales

- 🤖 **Commits Automáticos de Limpieza (Auto-Fix):**
  - Elimina automáticamente archivos tóxicos o temporales (`.DS_Store`,
    `Thumbs.db`, `.env.local`, logs) que se hayan colado en el repositorio.
  - Añade automáticamente las reglas correspondientes a `.gitignore`.
  - Realiza un commit automático del bot
    (`chore(nemesis): auto-clean toxic files [skip ci]`) y lo sube a la rama del
    Pull Request.
- 💡 **Sugerencias Interactivas de 1-Clic en PRs (GitHub Review Suggestions):**
  - Para dependencias vulnerables o credenciales expuestas, genera comentarios
    de revisión en el código con bloques de sugerencia interactiva.
  - El desarrollador solo hace clic en **"Commit suggestion"** en GitHub para
    aplicar la corrección de inmediato sin abrir su editor.
- 🔑 **Secret Scanning Híbrido (Gitleaks + Motor Nativo):**
  - Detecta claves de API (AWS, OpenAI, GitHub PAT, Google Cloud, Slack, JWT,
    Private Keys) tanto en el código actual como en el historial.
  - Si Gitleaks no está instalado en el entorno local, se activa un motor de
    regex de alta fidelidad nativo en Deno con cero dependencias.
- 🛡️ **SAST - Análisis Estático de Código (Semgrep):**
  - Encuentra vulnerabilidades comunes (inyecciones SQL, XSS, RCE,
    deserialización insegura, criptografía rota) en más de 30 lenguajes sin
    compilar.
- 📦 **SCA - Análisis de Dependencias (Trivy):**
  - Detecta CVEs conocidos en gestores de paquetes (`npm`, `pip`, `go`, `cargo`,
    `maven`, `nuget`) y fallos de infraestructura (Dockerfile, Kubernetes).
- 📜 **Auditoría de Licencias & SBOM (CycloneDX 1.5):**
  - Detecta licencias copyleft de alto riesgo (`GPL-3.0`, `AGPL-3.0`, `SSPL`)
    que comprometan código propietario o comercial cerrado.
  - Genera automáticamente el inventario de software **SBOM en estándar
    CycloneDX 1.5** (`sbom.cyclonedx.json`) para auditorías regulatorias (NIST,
    ISO 27001, Executive Order 14028).
- 🧹 **Higiene y Limpieza del Repositorio (Nativo Deno):**
  - **Archivos Tóxicos/Basura:** Detecta archivos `.env`, `.DS_Store`,
    `Thumbs.db`, `*.log`, temporales `*.bak` o dumps `*.dump`.
  - **Carpetas Indebidas:** Alerta si se suben directorios de dependencias o
    compilación (`node_modules/`, `vendor/`, `__pycache__/`).
  - **Archivos Pesados (Blob Bloat):** Identifica archivos mayores a 10 MB (o el
    límite que configures) que deberían usar Git LFS.
  - **Salud y Gobernanza:** Valida la presencia de `.gitignore`, `README.md` y
    `LICENSE`.
- ⚡ **Escaneo Diferencial (`diff-mode`):**
  - En Pull Requests, audita **únicamente los archivos modificados**, reduciendo
    el tiempo de ejecución en repositorios grandes de minutos a pocos segundos.
- 🎯 **Manejo de Falsos Positivos con `.nemesis.yml`:**
  - Permite suprimir alertas justificadas indicando ID de regla, CVE o ruta,
    exigiendo obligatoriamente un motivo (`reason`) y fecha de caducidad
    opcional (`expires`).
- 📢 **Alertas Webhook (Slack & Discord):**
  - Despacha tarjetas resumen formateadas a canales de Slack o Discord cuando
    termina la auditoría.
- 💬 **Feedback Inteligente en Pull Requests:**
  - Comentario Markdown tipo semáforo con actualización _in-place_ (sin spam) y
    anotaciones directas en el diff del PR.
- 📑 **Integración SARIF Nativa:**
  - Alertas visibles en la pestaña **Security -> Code Scanning** de GitHub.

---

## 📦 Uso Rápido: Integrar en cualquier Repositorio

Para auditar y **resolver automáticamente** en cualquier repositorio, crea el
archivo `.github/workflows/security-audit.yml`:

```yaml
name: Security & Hygiene Audit

on:
  push:
    branches: [main, master]
  pull_request:
    branches: [main, master]

permissions:
  contents: write # Requerido para auto-commits de limpieza (Auto-Fix)
  pull-requests: write # Requerido para comentarios y sugerencias de 1-clic
  security-events: write # Requerido para alertas SARIF en la pestaña Security

jobs:
  audit:
    name: Nemesis Audit
    runs-on: ubuntu-latest
    steps:
      - name: Checkout del repositorio
        uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - name: Ejecutar Nemesis Auditor & Remediation Bot
        uses: glastor-core/nemesis@v1
        with:
          auto-fix: true # Limpia archivos basura y comitea automáticamente
          pr-suggestions: true # Genera sugerencias de 1-clic para dependencias
          diff-mode: true # Escanea únicamente lo modificado en el PR
          scan-hygiene: true # Revisa limpieza y archivos no deseados
          scan-licenses: true # Revisa licencias restrictivas
          generate-sbom: true # Genera reporte CycloneDX SBOM
          upload-sarif: true # Muestra alertas en la pestaña de Seguridad
```

### ⚡ Ejemplo Mínimo (Zero-Config)

Si solo deseas auditar tu repositorio con los valores por defecto:

```yaml
- name: Nemesis Security Audit
  uses: glastor-core/nemesis@v1
```

---

## 🔐 Permisos Requeridos de GitHub (`permissions`)

Dependiendo de las funciones que actives, tu workflow necesita los siguientes
permisos en GitHub Actions:

| Permiso                  |            Requerido por            | Motivo                                                                                     |
| :----------------------- | :---------------------------------: | :----------------------------------------------------------------------------------------- |
| `contents: write`        |          `auto-fix: true`           | Permite al bot comitear y pushear la eliminación de archivos basura y reglas `.gitignore`. |
| `pull-requests: write`   | `post-pr-comment`, `pr-suggestions` | Publica/actualiza comentarios y genera revisiones interactivas en el PR.                   |
| `security-events: write` |        `upload-sarif: true`         | Permite subir el informe SARIF a la pestaña **Security -> Code Scanning**.                 |
| `contents: read`         |      Auditoría de solo lectura      | Permite clonar y analizar el repositorio.                                                  |

---

## 🎯 Configuración de Exclusiones y Falsos Positivos (`.nemesis.yml`)

Para suprimir alertas justificadas (por ejemplo, credenciales mockeadas en un
test o un CVE mitigado por infraestructura), añade `.nemesis.yml` en la raíz de
tu repositorio:

```yaml
version: "1"

ignore:
  - id: "SECRET-aws-access-token-1"
    path: "tests/mocks/**"
    reason: "Credencial falsa para pruebas unitarias"

  - cve: "CVE-2023-12345"
    reason: "Mitigado por reglas de firewall WAF en producción"
    expires: "2026-12-31" # Expira para forzar re-evaluación periódica

settings:
  maxFileSizeMb: 15
  requireLicense: true
```

---

## ⚙️ Parámetros de Entrada (`inputs`)

Todos los parámetros son opcionales y cuentan con valores por defecto
optimizados para DevSecOps:

| Parámetro             |  Tipo   |             Por Defecto              | Descripción                                                                       |
| :-------------------- | :-----: | :----------------------------------: | :-------------------------------------------------------------------------------- |
| `target-path`         | string  |                 `.`                  | Directorio o repositorio a auditar.                                               |
| `scan-secrets`        | boolean |                `true`                | Habilita el escaneo de secretos expuestos (Gitleaks + nativo).                    |
| `scan-sast`           | boolean |                `true`                | Habilita el escaneo estático de código (Semgrep).                                 |
| `scan-sca`            | boolean |                `true`                | Habilita el escaneo de dependencias vulnerables (Trivy).                          |
| `scan-hygiene`        | boolean |                `true`                | Habilita la verificación de limpieza e higiene del repo.                          |
| `scan-licenses`       | boolean |                `true`                | Audita licencias copyleft restrictivas (GPL, AGPL, SSPL).                         |
| `generate-sbom`       | boolean |                `true`                | Genera archivo CycloneDX SBOM (`sbom.cyclonedx.json`).                            |
| `diff-mode`           | boolean |               `false`                | Escanea solo archivos modificados en el PR/commit actual.                         |
| `diff-base-ref`       | string  |           `'origin/main'`            | Rama base para la comparación diferencial.                                        |
| `auto-fix`            | boolean |               `false`                | Elimina archivos basura y hace auto-commit de limpieza.                           |
| `pr-suggestions`      | boolean |                `true`                | Publica sugerencias de 1-clic en el PR para arreglar dependencias o credenciales. |
| `max-file-size-mb`    | string  |                `'10'`                | Tamaño máximo de archivo en MB antes de alertar por blob bloat.                   |
| `require-license`     | boolean |               `false`                | Exige la presencia obligatoria de un archivo LICENSE en la raíz.                  |
| `fail-on-critical`    | boolean |               `false`                | Falla el paso del pipeline si hay vulnerabilidades `CRITICAL`.                    |
| `fail-on-high`        | boolean |               `false`                | Falla el paso si hay vulnerabilidades `HIGH` o `CRITICAL`.                        |
| `fail-on-medium`      | boolean |               `false`                | Falla el paso si hay vulnerabilidades `MEDIUM` o superiores.                      |
| `post-pr-comment`     | boolean |                `true`                | Publica/actualiza un comentario Markdown tipo semáforo en el PR.                  |
| `create-annotations`  | boolean |                `true`                | Marca las líneas afectadas directamente en el diff del PR.                        |
| `upload-sarif`        | boolean |                `true`                | Sube el reporte SARIF a la pestaña Security de GitHub.                            |
| `output-dir`          | string  |         `'.nemesis-reports'`         | Directorio donde se guardan los reportes generados.                               |
| `config-file`         | string  |                 `''`                 | Ruta personalizada al archivo `.nemesis.yml`.                                     |
| `slack-webhook-url`   | string  |                 `''`                 | URL de Webhook para alertas en Slack.                                             |
| `discord-webhook-url` | string  |                 `''`                 | URL de Webhook para alertas en Discord.                                           |
| `github-token`        | string  |        `${{ github.token }}`         | Token de GitHub para comentarios en PRs y subida SARIF.                           |
| `semgrep-rules`       | string  |         `'p/security-audit'`         | Regla o conjunto de reglas Semgrep a utilizar.                                    |
| `trivy-severity`      | string  | `'UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL'` | Severidades de vulnerabilidad a capturar con Trivy.                               |

---

## 📤 Parámetros de Salida (`outputs`)

Nemesis expone las siguientes salidas utilizables por pasos posteriores en el
workflow:

| Salida             |          Tipo           | Descripción                                                       |
| :----------------- | :---------------------: | :---------------------------------------------------------------- |
| `passed`           | string (`true`/`false`) | Indica si la auditoría superó los umbrales configurados.          |
| `total-findings`   |     string (número)     | Cantidad total de hallazgos activos encontrados.                  |
| `critical-count`   |     string (número)     | Cantidad de vulnerabilidades con severidad `CRITICAL`.            |
| `high-count`       |     string (número)     | Cantidad de vulnerabilidades con severidad `HIGH`.                |
| `ignored-count`    |     string (número)     | Cantidad de alertas suprimidas mediante `.nemesis.yml`.           |
| `auto-fixed-count` |     string (número)     | Cantidad de problemas resueltos automáticamente por Auto-Fix.     |
| `report-json`      |      string (ruta)      | Ruta al reporte completo en formato JSON (`nemesis-report.json`). |
| `report-md`        |      string (ruta)      | Ruta al reporte formateado en Markdown (`nemesis-report.md`).     |
| `report-sarif`     |      string (ruta)      | Ruta al reporte estándar SARIF 2.1.0 (`nemesis-report.sarif`).    |
| `sbom-file`        |      string (ruta)      | Ruta al archivo CycloneDX SBOM generado (`sbom.cyclonedx.json`).  |

---

## 📁 Archivos de Reporte Generados

Nemesis genera de forma automática los siguientes artefactos en el directorio
especificado por `output-dir` (por defecto `.nemesis-reports`):

| Archivo                |    Formato    | Propósito                                                                    |
| :--------------------- | :-----------: | :--------------------------------------------------------------------------- |
| `nemesis-report.json`  |     JSON      | Estructura completa de auditoría para ingesta en herramientas SIEM/SecOps.   |
| `nemesis-report.md`    |   Markdown    | Resumen visual con tablas e indicadores semáforo para PRs y resúmenes de CI. |
| `nemesis-report.sarif` |  SARIF 2.1.0  | Estándar de la industria para integración con GitHub Code Scanning.          |
| `sbom.cyclonedx.json`  | CycloneDX 1.5 | Inventario de software para cumplimiento NIST, ISO 27001 y auditorías.       |

---

## 💻 Uso Local (CLI con Deno)

Nemesis puede ejecutarse localmente sin depender de GitHub Actions:

```bash
# Auditar todo el repositorio (Seguridad + Higiene + Licencias + SBOM)
deno task start --path .

# Auditar y limpiar archivos basura automáticamente
deno task start --path . --hygiene --auto-fix

# Modo diferencial: auditar solo archivos modificados frente a master
deno task start --path . --diff

# Ejecutar suite de pruebas unitarias
deno task test

# Compilar binario autónomo para Windows/Linux/macOS
deno task compile
```

---

## 🪝 Git Hooks Nativos & Push Protection (Zero-Dependency Shift-Left)

Nemesis incluye hooks de Git nativos sin necesidad de Node.js, npm ni
`node_modules`. Para activarlos en tu copia local:

```bash
deno task setup
```

Esto configura automáticamente el estándar de **Push Protection**:

1. **`pre-commit`**: Ejecuta `deno fmt --check`, `deno lint`, `deno check`,
   `deno test` y una auditoría diferencial de Nemesis
   (`--diff --fail-on-critical`) para impedir comitear secretos o archivos
   basura.
2. **`pre-push`**: Activa la **protección nativa contra push accidental** (_Push
   Protection_), auditando el delta de código antes de enviar datos al
   repositorio remoto.
3. **`commit-msg`**: Valida que el mensaje cumpla estrictamente con
   [Conventional Commits](.github/COMMIT_CONVENTION.md) antes de guardarlo.

---

## 🏛️ Arquitectura Glastor Core

Nemesis es el componente de seguridad fundamental del ecosistema **Glastor
Core**:

- 🛡️ **DevSecOps & Security Gateways:** Implementa _Continuous Audit & Push
  Protection_ en pipelines de CI/CD y en la máquina del desarrollador.
- 📦 **High-Performance Libraries & CLI:** Provee herramientas _Zero-Dependency_
  compiladas para múltiples arquitecturas (Linux, Windows, macOS x86 y ARM64) y
  motores de escaneo nativos en TypeScript.
- ⚡ **Edge Engine & Microservices:** Protege y asegura repositorios de
  microservicios y motores Edge de alto rendimiento (como Glastor Medusa y
  Hyper-Flow).

---

## 📄 Licencia

Distribuido bajo la [Licencia MIT](LICENSE).
