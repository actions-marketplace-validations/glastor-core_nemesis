import { AuditFinding, AuditReport } from "../types.ts";

export function generateMarkdownReport(report: AuditReport): string {
  const badgeStatus = report.passed ? "PASSED-brightgreen" : "FAILED-red";
  const badgeUrl = `https://img.shields.io/badge/Nemesis_Audit-${badgeStatus}?style=for-the-badge&logo=shield`;

  const sections: string[] = [];

  sections.push(`## 🛡️ Nemesis Security Audit Report`);
  sections.push(`![Status](${badgeUrl})`);
  sections.push("");
  sections.push(`> **Audit Target:** \`${report.targetPath}\` | **Date:** \`${report.timestamp}\``);
  if (report.commitSha) {
    sections.push(`> **Commit:** \`${report.commitSha.substring(0, 7)}\``);
  }
  sections.push("");

  // Severity summary table
  sections.push(`### 📊 Summary by Severity`);
  sections.push(`| Severity | Count | Indicator |`);
  sections.push(`| :--- | :---: | :---: |`);
  sections.push(`| **CRITICAL** | ${report.counts.CRITICAL} | ${report.counts.CRITICAL > 0 ? "🚨 Requiere atención inmediata" : "✅ Limpio"} |`);
  sections.push(`| **HIGH** | ${report.counts.HIGH} | ${report.counts.HIGH > 0 ? "⚠️ Alto riesgo" : "✅ Limpio"} |`);
  sections.push(`| **MEDIUM** | ${report.counts.MEDIUM} | ${report.counts.MEDIUM > 0 ? "🟡 Riesgo moderado" : "✅ Limpio"} |`);
  sections.push(`| **LOW / INFO** | ${report.counts.LOW + report.counts.INFO} | ℹ️ Información |`);
  sections.push(`| **TOTAL** | **${report.totalFindings}** | ${report.passed ? "🟢 APROBADO" : "🔴 REPROBADO"} |`);
  sections.push("");

  // Scanner status table
  sections.push(`### 🔍 Modulos de Escaneo`);
  sections.push(`| Scanner | Categoría | Estado | Tiempo | Hallazgos |`);
  sections.push(`| :--- | :--- | :---: | :---: | :---: |`);
  for (const s of report.scanners) {
    const totalFound = s.counts.CRITICAL + s.counts.HIGH + s.counts.MEDIUM + s.counts.LOW + s.counts.INFO;
    const statusIcon = s.status === "success" ? "✅ OK" : s.status === "skipped" ? "⏭️ Omitido" : "❌ Error";
    sections.push(`| **${s.tool.toUpperCase()}** | ${s.category} | ${statusIcon} | ${s.durationMs}ms | ${totalFound} |`);
  }
  sections.push("");

  // Categorized findings
  const secrets = report.findings.filter((f) => f.category === "SECRET");
  const sca = report.findings.filter((f) => f.category === "SCA");
  const sast = report.findings.filter((f) => f.category === "SAST");
  const misconfig = report.findings.filter((f) => f.category === "MISCONFIG");

  if (secrets.length > 0) {
    sections.push(`### 🚨 Secretos Expuestos (${secrets.length})`);
    sections.push(`> ⚠️ **Peligro:** Se encontraron posibles credenciales o claves de acceso en el código.`);
    sections.push("");
    sections.push(`| Regla | Archivo | Línea | Severidad |`);
    sections.push(`| :--- | :--- | :---: | :---: |`);
    for (const item of secrets) {
      sections.push(`| \`${item.ruleId ?? item.title}\` | \`${item.file ?? "N/A"}\` | ${item.line ?? "-"} | 🔴 ${item.severity} |`);
    }
    sections.push("");
  }

  if (sca.length > 0) {
    sections.push(`### 📦 Dependencias Vulnerables (SCA - ${sca.length})`);
    sections.push("");
    sections.push(`| Paquete | Versión Instalada | Versión Corregida | CVE | Severidad |`);
    sections.push(`| :--- | :---: | :---: | :--- | :---: |`);
    for (const item of sca) {
      const fix = item.fixedVersion ? `\`${item.fixedVersion}\`` : "*Sin parche aún*";
      const cveLink = item.cve ? `[\`${item.cve}\`](https://nvd.nist.gov/vuln/detail/${item.cve})` : "-";
      sections.push(`| **${item.package ?? item.title}** | \`${item.installedVersion ?? "N/A"}\` | ${fix} | ${cveLink} | **${item.severity}** |`);
    }
    sections.push("");
  }

  if (sast.length > 0) {
    sections.push(`<details><summary><b>🛡️ Hallazgos de Código (SAST - ${sast.length})</b> (Click para expandir)</summary>\n`);
    sections.push(`| Regla / Problema | Archivo:Línea | Severidad | Mensaje |`);
    sections.push(`| :--- | :--- | :---: | :--- |`);
    for (const item of sast) {
      const loc = `\`${item.file ?? ""}${item.line ? `:${item.line}` : ""}\``;
      sections.push(`| \`${item.ruleId ?? item.title}\` | ${loc} | **${item.severity}** | ${item.description.replace(/\|/g, "\\|").substring(0, 100)}... |`);
    }
    sections.push("\n</details>\n");
  }

  if (misconfig.length > 0) {
    sections.push(`<details><summary><b>⚙️ Configuraciones Inseguras (${misconfig.length})</b> (Click para expandir)</summary>\n`);
    sections.push(`| Archivo | ID Regla | Severidad | Descripción |`);
    sections.push(`| :--- | :--- | :---: | :--- |`);
    for (const item of misconfig) {
      sections.push(`| \`${item.file ?? "N/A"}\` | \`${item.ruleId ?? item.title}\` | **${item.severity}** | ${item.description.replace(/\|/g, "\\|").substring(0, 100)}... |`);
    }
    sections.push("\n</details>\n");
  }

  if (report.findings.length === 0) {
    sections.push(`### 🎉 ¡Excelente! No se encontraron vulnerabilidades en esta auditoría.`);
    sections.push("");
  }

  sections.push("---");
  sections.push(`*Generado automáticamente por [Nemesis Audit Engine](https://github.com) impulsado por Deno & TypeScript.*`);

  return sections.join("\n");
}
