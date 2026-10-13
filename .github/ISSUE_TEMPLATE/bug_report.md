---
name: 🐛 Reportar un bug (Markdown)
about: Reporta un error, fallo o comportamiento anómalo en Nemesis
title: "[Bug]: "
labels: ["bug"]
---

### 📝 Descripción del Problema
Una descripción clara y concisa del fallo observado en Nemesis.

### 🧩 Módulo o Scanner Afectado
Indica el componente involucrado (marca con `x`):
- [ ] Higiene de Repositorio / Archivos Tóxicos
- [ ] Escaneo de Secretos (Gitleaks)
- [ ] SAST / Análisis Estático (Semgrep)
- [ ] SCA / Dependencias Vulnerables (Trivy)
- [ ] Licencias y SBOM (CycloneDX)
- [ ] Auto-Fix y Commits de Limpieza
- [ ] GitHub PR Review Suggestions
- [ ] GitHub Action (`action.yml`)
- [ ] CLI / Orquestador Core

### 🔁 Pasos para Reproducir
1. Ejecutar el comando o pipeline: `...`
2. Configuración en `.nemesis.yml` o flags usados: `...`
3. Observar el error o fallo en la salida.

### 🎯 Comportamiento Esperado
Qué debería haber ocurrido (ej. detección correcta, supresión respetada, sugerencia en PR generada sin error).

### 🖥️ Entorno de Ejecución
- **Modo:** [GitHub Action / Deno CLI local / Binario standalone]
- **Versión de Nemesis:** [e.g. v1.1.0 / master / commit SHA]
- **Versión de Deno:** [salida de `deno --version`]
- **Sistema Operativo:** [Linux (Ubuntu 22.04), macOS, Windows 11]

### 📜 Salida de Consola / Logs de Error
```shell
# Pega aquí los logs de ejecución o fragmento de la salida
```

### 📌 Información Adicional
Contexto adicional, repositorios de prueba o capturas de pantalla.
