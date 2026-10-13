# 🛡️ Nemesis — Auditor & Bot de Auto-Remediación para Repositorios

> **GitHub Action y motor CLI de DevSecOps, Repo Hygiene, Auto-Fix & Compliance
> construido con Deno y TypeScript.**\
> Audita automáticamente secretos expuestos, vulnerabilidades de código (SAST),
> dependencias vulnerables (SCA), licencias open source (Copyleft), generación
> de SBOM (CycloneDX), limpieza e higiene del repositorio, **commits automáticos
> de limpieza (Auto-Fix)** y **sugerencias interactivas de 1-clic en Pull
> Requests**.

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
- 🔑 **Secret Scanning (Gitleaks):** Detecta claves de API, tokens privados,
  certificados y contraseñas filtradas en el código e historial de commits.
- 🛡️ **SAST - Análisis Estático de Código (Semgrep):** Encuentra
  vulnerabilidades comunes (inyecciones SQL, XSS, RCE, criptografía insegura) en
  más de 30 lenguajes sin compilar.
- 📦 **SCA - Análisis de Dependencias (Trivy):** Detecta CVEs conocidos en
  gestores de paquetes (`npm`, `pip`, `go`, `cargo`, `maven`) y fallos de
  infraestructura (Dockerfile, K8s).
- 📜 **Auditoría de Licencias & SBOM (CycloneDX):**
  - Detecta licencias copyleft de alto riesgo (`GPL-3.0`, `AGPL-3.0`, `SSPL`)
    que comprometan código propietario.
  - Genera automáticamente el inventario de software **SBOM en estándar
    CycloneDX** (`sbom.cyclonedx.json`) para auditorías regulatorias (NIST, ISO
    27001).
- 🧹 **Higiene y Limpieza del Repositorio (Nativo Deno):**
  - **Archivos Tóxicos/Basura:** Detecta archivos `.env`, `.DS_Store`,
    `Thumbs.db`, `*.log`, temporales `*.bak` o dumps `*.dump`.
  - **Carpetas Indebidas:** Alerta si se suben directorios de dependencias o
    compilación (`node_modules/`, `vendor/`, `__pycache__/`).
  - **Archivos Pesados (Blob Bloat):** Identifica archivos mayores a 10 MB (o el
    límite que configures) que deberían usar Git LFS.
  - **Salud y Gobernanza:** Valida la presencia de `.gitignore`, `README.md` y
    `LICENSE`.
- ⚡ **Escaneo Diferencial (`--diff`):**
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
  contents: write # Requerido para auto-commits de limpieza
  pull-requests: write # Requerido para comentarios y sugerencias de 1-click
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

      - name: Ejecutar Auditor & Remediation Bot
        uses: glastor-dev/nemesis@master
        with:
          auto-fix: true # Limpia archivos basura y comitea automáticamente
          pr-suggestions: true # Genera sugerencias de 1-clic para dependencias
          diff-mode: true # Escanea únicamente lo modificado en el PR
          scan-hygiene: true # Revisa limpieza y archivos no deseados
          scan-licenses: true # Revisa licencias restrictivas
          generate-sbom: true # Genera reporte CycloneDX SBOM
          upload-sarif: true # Muestra alertas en la pestaña de Seguridad
```

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
    expires: "2026-12-31" # Expira para forzar re-evaluación

settings:
  maxFileSizeMb: 15
  requireLicense: true
```

---

## ⚙️ Parámetros de Configuración (`inputs`)

| Parámetro             |  Tipo   |   Por Defecto   | Descripción                                                            |
| :-------------------- | :-----: | :-------------: | :--------------------------------------------------------------------- |
| `target-path`         | string  |       `.`       | Directorio del proyecto a auditar.                                     |
| `auto-fix`            | boolean |     `false`     | Elimina archivos basura y hace auto-commit de limpieza.                |
| `pr-suggestions`      | boolean |     `true`      | Publica sugerencias de 1-clic en el PR para arreglar vulnerabilidades. |
| `diff-mode`           | boolean |     `false`     | Escanea solo archivos modificados en el PR/commit actual.              |
| `diff-base-ref`       | string  | `'origin/main'` | Rama base para la comparación diferencial.                             |
| `scan-secrets`        | boolean |     `true`      | Habilita el escaneo de secretos (Gitleaks).                            |
| `scan-sast`           | boolean |     `true`      | Habilita el escaneo estático de código (Semgrep).                      |
| `scan-sca`            | boolean |     `true`      | Habilita el escaneo de dependencias (Trivy).                           |
| `scan-hygiene`        | boolean |     `true`      | Habilita la verificación de limpieza e higiene del repo.               |
| `scan-licenses`       | boolean |     `true`      | Audita licencias copyleft restrictivas.                                |
| `generate-sbom`       | boolean |     `true`      | Genera archivo CycloneDX SBOM (`sbom.cyclonedx.json`).                 |
| `max-file-size-mb`    | string  |     `'10'`      | Tamaño máximo de archivo en MB antes de alertar.                       |
| `require-license`     | boolean |     `false`     | Exige la presencia obligatoria de un archivo LICENSE en la raíz.       |
| `fail-on-critical`    | boolean |     `false`     | Falla el paso del pipeline si hay vulnerabilidades `CRITICAL`.         |
| `fail-on-high`        | boolean |     `false`     | Falla el paso si hay vulnerabilidades `HIGH` o `CRITICAL`.             |
| `post-pr-comment`     | boolean |     `true`      | Publica/actualiza un comentario resumen en el PR.                      |
| `create-annotations`  | boolean |     `true`      | Marca las líneas afectadas en el diff del PR.                          |
| `upload-sarif`        | boolean |     `true`      | Sube el reporte SARIF a la pestaña Security de GitHub.                 |
| `slack-webhook-url`   | string  |      `''`       | URL de Webhook para alertas en Slack.                                  |
| `discord-webhook-url` | string  |      `''`       | URL de Webhook para alertas en Discord.                                |
| `config-file`         | string  |      `''`       | Ruta personalizada a `.nemesis.yml`.                                   |

---

## 💻 Uso Local (CLI con Deno)

```bash
# Auditar todo el repositorio (Seguridad + Higiene + Licencias)
deno task start --path .

# Auditar y limpiar archivos basura automáticamente
deno task start --path . --hygiene --auto-fix

# Modo diferencial: auditar solo archivos modificados frente a master
deno task start --path . --diff

# Compilar binario autónomo para Windows/Linux/macOS
deno task compile
```

---

## 🪝 Git Hooks Nativos (Zero-Dependency Shift-Left)

Nemesis incluye hooks de Git nativos sin necesidad de Node.js, npm ni
`node_modules`. Para activarlos en tu copia local:

```bash
deno task setup
```

Esto configura automáticamente:

1. **`pre-commit`**: Ejecuta `deno fmt --check`, `deno lint`, `deno check`,
   `deno test` y una auditoría diferencial de Nemesis
   (`--diff --fail-on-critical`) para impedir comitear secretos o archivos
   basura.
2. **`commit-msg`**: Valida que el mensaje cumpla estrictamente con
   [Conventional Commits](.github/COMMIT_CONVENTION.md) antes de guardarlo.

---

## 📄 Licencia

Distribuido bajo la [Licencia MIT](LICENSE).
