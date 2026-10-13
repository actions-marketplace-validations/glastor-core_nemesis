# Changelog

<p align="center">
  <img src="https://img.shields.io/badge/Format-Keep%20a%20Changelog-blue.svg" alt="Keep a Changelog">
  <img src="https://img.shields.io/badge/Versioning-SemVer%202.0.0-green.svg" alt="Semantic Versioning">
  <img src="https://img.shields.io/badge/License-MIT-purple.svg" alt="License MIT">
</p>

---

## Acerca de este Changelog

Todos los cambios notables en **Nemesis (Universal Security, Hygiene & Compliance Auditor)** son documentados en este archivo.

Este proyecto se adhiere a:
- **Formato:** [Keep a Changelog](https://keepachangelog.com/es-ES/1.0.0/)
- **Versionado:** [Semantic Versioning](https://semver.org/spec/v2.0.0.html)

### Categorías de Cambios
- **Added** ✨ - Nuevas características o funcionalidades
- **Changed** 🔄 - Cambios en funcionalidades existentes
- **Fixed** 🐛 - Correcciones de errores
- **Security** 🔒 - Mejoras de seguridad y protección

---

## [Unreleased]

### 💡 Planned
- Integración con modelos LLM para auto-generación de parches de código en vulnerabilidades complejas.
- Soporte para reglas de Conventional Commits en el módulo de higiene.

---

## [1.1.0] - 2026-10-13

**Nombre del Release:** "Auto-Remediation & Enterprise Compliance"  
**Tipo de Release:** Minor Feature Release  

### ✨ Added

#### Auto-Remediación & Bot Activo
- **Commits Automáticos de Limpieza (`auto-fix`):** Motor de remediación que elimina automáticamente archivos basura (`.DS_Store`, `Thumbs.db`, `.env.local`, logs) y actualiza `.gitignore` mediante un commit automático del bot con etiqueta `[skip ci]`.
- **Sugerencias de 1-Clic en PRs (`pr-suggestions`):** Integración con la API de GitHub Reviews para publicar bloques interactivos ````suggestion en dependencias vulnerables (SCA) y credenciales expuestas (Secret Scanning).

#### Gobernanza & Supresión de Falsos Positivos
- **Motor de Exclusiones con Zod (`.nemesis.yml`):** Soporte para reglas de ignorado con justificación obligatoria (`reason`), ruta de archivo, regla/CVE y fecha de caducidad opcional (`expires`).
- **Escaneo Diferencial (`--diff`):** Modo de alta velocidad para auditar únicamente archivos modificados o agregados en el Pull Request frente a la rama base (`git diff --name-only`).

#### Cumplimiento Normativo & Notificaciones
- **Auditoría de Licencias Open Source:** Detección de licencias *copyleft* de alto riesgo (`GPL-3.0`, `AGPL-3.0`, `SSPL`).
- **Generación de SBOM (CycloneDX):** Exportación automática del inventario de software `sbom.cyclonedx.json` para auditorías NIST / ISO 27001.
- **Webhooks de Alerta:** Notificador de tarjetas informativas para canales de **Slack** y **Discord**.
- **Soporte de Variables de Entorno Seguras:** Carga automática mediante `--env`, creación de [.env.example](.env.example) y exclusión obligatoria de `.env` en [.gitignore](.gitignore).

#### Infraestructura CI/CD
- **Caché de Vulnerabilidades:** Integración de `actions/cache@v4` en [action.yml](action.yml) para acelerar descargas repetidas de bases de datos de Trivy.

---

## [1.0.0] - 2026-10-12

**Nombre del Release:** "Initial Universal DevSecOps Core"  
**Tipo de Release:** Major Initial Release  

### ✨ Added
- **Núcleo Deno & TypeScript:** Arquitectura modular de escaneo de alto rendimiento sin `node_modules` ni pasos de empaquetado.
- **Módulos de Auditoría Integrados:**
  - **Secret Scanning:** Integración con Gitleaks para auditar claves de API, tokens privados e historial de Git.
  - **SAST:** Integración con Semgrep para análisis sintáctico de código en más de 30 lenguajes.
  - **SCA:** Integración con Trivy para detectar CVEs en gestores de dependencias y malas configuraciones de IaC.
  - **Repository Hygiene (`HygieneScanner`):** Detección nativa de archivos basura, toxic directories y archivos con sobrepeso (>10 MB).
- **Reporters Multi-formato:**
  - Consola con colores y tablas resumen (`reporters/console.ts`).
  - Markdown interactivo tipo semáforo con actualización *in-place* en Pull Requests (`reporters/markdown.ts`).
  - Estandarización a **SARIF 2.1.0** para integración con la pestaña *Security / Code scanning* de GitHub.
- **Empaquetado Binario:** Tareas de compilación a ejecutables nativos independientes mediante `deno compile`.
- **Licencia:** Adopción formal de la Licencia MIT.

---

## Enlaces & Recursos

- 📖 [README.md](README.md) - Documentación General
- 🏛️ [CONTRIBUTORS.md](CONTRIBUTORS.md) - Gobernanza y Contribuciones
- 📜 [LICENSE](LICENSE) - Términos de Licencia MIT
- 🏷️ [CITATION.cff](CITATION.cff) - Referencia Académica y Metadatos de Software
