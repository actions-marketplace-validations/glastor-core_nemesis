import * as core from "@actions/core";
import type { AuditFinding } from "../types.ts";

export function createWorkflowAnnotations(findings: AuditFinding[]): void {
  for (const f of findings) {
    if (!f.file) continue;

    const annotationProperties: core.AnnotationProperties = {
      file: f.file,
      startLine: f.line ?? 1,
      endLine: f.endLine ?? f.line ?? 1,
      startColumn: f.column ?? 1,
      title: `[Nemesis ${f.severity}] ${f.title}`,
    };

    const message = `[${f.category}] ${f.description}`;

    if (f.severity === "CRITICAL" || f.severity === "HIGH") {
      core.error(message, annotationProperties);
    } else if (f.severity === "MEDIUM") {
      core.warning(message, annotationProperties);
    } else {
      core.notice(message, annotationProperties);
    }
  }
}
