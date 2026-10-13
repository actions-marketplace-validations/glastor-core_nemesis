import type { AuditReport, Severity } from "../types.ts";

function mapSeverityToSarifLevel(
  severity: Severity,
): "error" | "warning" | "note" {
  switch (severity) {
    case "CRITICAL":
    case "HIGH":
      return "error";
    case "MEDIUM":
      return "warning";
    case "LOW":
    case "INFO":
    default:
      return "note";
  }
}

export function generateSarifReport(report: AuditReport): string {
  const rulesMap = new Map<
    string,
    { id: string; name: string; description: string }
  >();

  for (const f of report.findings) {
    const ruleKey = f.ruleId || f.title;
    if (!rulesMap.has(ruleKey)) {
      rulesMap.set(ruleKey, {
        id: ruleKey,
        name: f.title.replace(/[^a-zA-Z0-9_-]/g, "_").substring(0, 60),
        description: f.description,
      });
    }
  }

  const sarifRules = Array.from(rulesMap.values()).map((r) => ({
    id: r.id,
    name: r.name,
    shortDescription: {
      text: r.name,
    },
    fullDescription: {
      text: r.description,
    },
    defaultConfiguration: {
      level: "warning",
    },
  }));

  const sarifResults = report.findings.map((f) => {
    const resultObj: Record<string, unknown> = {
      ruleId: f.ruleId || f.title,
      level: mapSeverityToSarifLevel(f.severity),
      message: {
        text: `[${f.severity}] [${f.category}] ${f.title}: ${f.description}`,
      },
    };

    if (f.file) {
      resultObj.locations = [
        {
          physicalLocation: {
            artifactLocation: {
              uri: f.file.replace(/\\/g, "/"),
              uriBaseId: "%SRCROOT%",
            },
            region: {
              startLine: Math.max(1, f.line ?? 1),
              startColumn: Math.max(1, f.column ?? 1),
              endLine: Math.max(1, f.endLine ?? f.line ?? 1),
            },
          },
        },
      ];
    }

    return resultObj;
  });

  const sarifDocument = {
    $schema:
      "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
    version: "2.1.0",
    runs: [
      {
        tool: {
          driver: {
            name: "Nemesis Security Auditor",
            version: "1.0.0",
            informationUri: "https://github.com",
            rules: sarifRules,
          },
        },
        results: sarifResults,
      },
    ],
  };

  return JSON.stringify(sarifDocument, null, 2);
}
