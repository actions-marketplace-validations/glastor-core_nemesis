import { assertEquals } from "@std/assert";
import { generateSarifReport } from "../src/reporters/sarif.ts";
import type { AuditReport } from "../src/types.ts";

Deno.test("generateSarifReport produces valid SARIF 2.1.0 JSON document", () => {
  const dummyReport: AuditReport = {
    timestamp: new Date().toISOString(),
    targetPath: ".",
    diffMode: false,
    scanners: [],
    findings: [
      {
        id: "SECRET-1",
        tool: "gitleaks",
        category: "SECRET",
        severity: "CRITICAL",
        title: "AWS Access Key",
        description: "Hardcoded key found",
        file: "src/auth.ts",
        line: 10,
        ruleId: "aws-key",
      },
      {
        id: "HYGIENE-1",
        tool: "hygiene",
        category: "HYGIENE",
        severity: "LOW",
        title: "OS Junk File",
        description: "Thumbs.db file present",
        file: "Thumbs.db",
        ruleId: "repo-junk-file",
      },
    ],
    ignoredFindings: [],
    totalFindings: 2,
    counts: { CRITICAL: 1, HIGH: 0, MEDIUM: 0, LOW: 1, INFO: 0 },
    passed: false,
  };

  const sarifString = generateSarifReport(dummyReport);
  const parsed = JSON.parse(sarifString);

  assertEquals(parsed.version, "2.1.0");
  assertEquals(parsed.runs.length, 1);
  assertEquals(parsed.runs[0].tool.driver.name, "Nemesis Security Auditor");
  assertEquals(parsed.runs[0].results.length, 2);

  // Check critical maps to error level
  assertEquals(parsed.runs[0].results[0].level, "error");
  assertEquals(
    parsed.runs[0].results[0].locations[0].physicalLocation.artifactLocation
      .uri,
    "src/auth.ts",
  );

  // Check low maps to note level
  assertEquals(parsed.runs[0].results[1].level, "note");
});
