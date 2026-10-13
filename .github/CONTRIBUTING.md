# 🌌 Ingeniería y Estándares de Contribución

Gracias por sumarte a la misión de construir y evolucionar **Nemesis** dentro
del ecosistema de `**GLASTOR-DEV** (división de desarrollo de GLASTOR®)`.
Nemesis es un motor universal de DevSecOps, auditoría de higiene de repositorios
y auto-remediación para GitHub Actions y CLI.

Valoramos la excelencia técnica, el rigor en seguridad y el compromiso con la
calidad del software. Esta guía establece las directrices operativas y de
ingeniería para colaborar con máxima eficiencia (DX).

---

## 🛠 Gestión Estratégica de Incidencias

### 🐛 Reportes de Errores (Fidelidad Técnica)

Cada _issue_ debe actuar como un documento técnico verificable:

- **Executive Summary:** Resumen conciso del impacto y el alcance.
- **Protocolo de Reproducción:** Pasos exactos y deterministas para replicar el
  problema.
- **Análisis de Desviación:** Contraste claro entre el resultado observado y el
  esperado.
- **Entorno de Ejecución:**
  - Versión de Deno (`deno --version`)
  - Sistema Operativo (Linux, macOS, Windows)
  - Modo de ejecución: CLI local o GitHub Action (`action.yml`)
- **Evidencia Técnica:** Logs de consola, trazas de error (`stack traces`) o
  reportes JSON/SARIF.

### 💡 Propuesta de Nuevas Reglas o Scanners

Para proponer nuevos módulos de detección, reglas de higiene o estrategias de
auto-remediación:

1. **Definición de Amenaza / Regla:** Qué vector de seguridad, patrón inseguro o
   desorden de repositorio se detecta.
2. **Estrategia de Detección:** Expresiones regulares seguras (sin riesgo de
   ReDoS), análisis AST o inspección de manifiestos.
3. **Propuesta de Remediación:** Si admite auto-fix automático (`--fix`) o
   sugerencias en PRs (`--pr-suggestions`).
4. **Falsos Positivos:** Identificar posibles excepciones o directivas de
   supresión (`@nemesis-ignore`).

---

## 💻 Setup del Entorno de Desarrollo

### Requisitos Previos

- **Deno:** 2.0+ instalado ([instrucciones de instalación](https://deno.land/)).
- **Git:** 2.30+.
- **GitHub Token (Opcional para pruebas de API):** Copia `.env.example` a `.env`
  y asigna `GITHUB_TOKEN`.

### 1. Clonación del Repositorio

```bash
git clone https://github.com/glastor-dev/nemesis.git
cd nemesis
```

### 2. Comandos y Tareas Disponibles

Nemesis gestiona sus scripts de desarrollo directamente a través de `deno.json`:

```bash
# Verificación de tipos TypeScript estricta
deno task check

# Formateo de código según los estándares del proyecto
deno task fmt

# Análisis estático y linter
deno task lint

# Ejecutar suite de pruebas automatizadas
deno task test

# Ejecutar auditoría sobre el propio repositorio (dogfooding)
deno task start --path .

# Ejecutar escaneo completo activando todos los scanners
deno task scan

# Compilar binario nativo standalone
deno task compile
```

---

## 🚀 Flujo de Integración y Pull Requests

Para preservar la estabilidad de la rama principal (`master`), seguimos un flujo
riguroso:

### 1. Rama de Trabajo

Crea una rama descriptiva partiendo de `master`:

```bash
git checkout -b feat/license-spdx-check
# o: git checkout -b fix/auto-fix-trailing-spaces
```

### 2. Estándares de Código

- **TypeScript Estricto:** Tipado exhaustivo; evitar el uso de `any` a menos que
  sea estrictamente necesario.
- **Arquitectura Modular:**
  - `/src/scanners/`: Motores de análisis (`secrets`, `hygiene`, `dependencies`,
    `sbom`, `permissions`, `license`).
  - `/src/remediation/`: Lógica de auto-remediación y generación de sugerencias.
  - `/src/reporters/`: Formateadores de salida (Consola, Markdown Summary,
    SARIF).
  - `/src/github/`: Integración con la API de GitHub y cliente Octokit.
  - `/src/utils/`: Funciones auxiliares independientes de plataforma.
- **Verificación Local Obligatoria:** Asegúrate de que pasen sin errores:
  ```bash
  deno task check && deno task lint && deno task fmt --check
  ```

### 3. Protocolo de Commits (Conventional Commits)

Implementamos la especificación de
[Conventional Commits](./COMMIT_CONVENTION.md):

```bash
git commit -m "feat(scanners): add strict spdx identifier validation"
git commit -m "fix(remediation): preserve crlf line endings on windows hosts"
```

Prefijos permitidos: `feat:`, `fix:`, `docs:`, `style:`, `refactor:`, `perf:`,
`test:`, `ci:`, `chore:`.

### 4. Publicación y PR

Envía tu rama al repositorio remoto y abre un Pull Request hacia la rama
`master`:

```bash
git push origin feat/license-spdx-check
```

Completa el formulario generado por el
[PULL_REQUEST_TEMPLATE.md](./PULL_REQUEST_TEMPLATE.md) asegurando que todos los
puntos del checklist estén marcados.

---

## 📧 Canales de Comunicación y Soporte

- **GitHub Discussions:**
  [glastor-dev/nemesis/discussions](https://github.com/glastor-dev/nemesis/discussions)
  (consultas de arquitectura y propuestas).
- **GitHub Issues:**
  [glastor-dev/nemesis/issues](https://github.com/glastor-dev/nemesis/issues)
  (bugs y tareas).
- **Soporte Corporativo:**
  [glastor.info@gmail.com](mailto:glastor.info@gmail.com)
- **Comunicación Directa (Telegram):** [@zerhocool](https://t.me/zerhocool)

---

## Código de Conducta

Este proyecto se rige bajo nuestro [Código de Conducta](./CODE_OF_CONDUCT.md).
Fomentamos un entorno de respeto mutuo, inclusión y rigor profesional.

© 2010-2026 Andrés Antonio Cardoso — Todos los derechos reservados
