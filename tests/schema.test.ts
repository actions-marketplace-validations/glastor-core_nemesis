import { assertEquals } from "@std/assert";
import { filterIgnoredFindings, type IgnoreRule } from "../src/config/schema.ts";
import type { AuditFinding } from "../src/types.ts";

const sampleFindings: AuditFinding[] = [
  {
    id: "SECRET-1",
    tool: "gitleaks",
    category: "SECRET",
    severity: "CRITICAL",
    title: "AWS Secret Token",
    description: "AWS key leaked",
    file: "src/test.ts",
    ruleId: "aws-key",
  },
  {
    id: "HYGIENE-1",
    tool: "hygiene",
    category: "HYGIENE",
    severity: "LOW",
    title: "OS junk file",
    description: "Thumbs.db",
    file: "Thumbs.db",
    ruleId: "repo-junk-file",
  },
  {
    id: "SCA-1",
    tool: "trivy",
    category: "SCA",
    severity: "HIGH",
    title: "Vulnerable lodash",
    description: "Prototype pollution",
    file: "package.json",
    cve: "CVE-2021-23337",
    ruleId: "cve-rule",
  },
];

Deno.test("filterIgnoredFindings ignores by finding ID", () => {
  const rules: IgnoreRule[] = [
    { id: "SECRET-1", reason: "Falso positivo en mock" },
  ];

  const { active, ignored } = filterIgnoredFindings(sampleFindings, rules);
  assertEquals(active.length, 2);
  assertEquals(ignored.length, 1);
  assertEquals(ignored[0].id, "SECRET-1");
  assertEquals(ignored[0].ignoreReason, "Falso positivo en mock");
});

Deno.test("filterIgnoredFindings ignores by CVE", () => {
  const rules: IgnoreRule[] = [
    { cve: "CVE-2021-23337", reason: "Mitigado por control compensatorio" },
  ];

  const { active, ignored } = filterIgnoredFindings(sampleFindings, rules);
  assertEquals(active.length, 2);
  assertEquals(ignored.length, 1);
  assertEquals(ignored[0].cve, "CVE-2021-23337");
});

Deno.test("filterIgnoredFindings ignores by file path", () => {
  const rules: IgnoreRule[] = [
    { path: "Thumbs.db", reason: "Archivo temporal en staging" },
  ];

  const { active, ignored } = filterIgnoredFindings(sampleFindings, rules);
  assertEquals(active.length, 2);
  assertEquals(ignored.length, 1);
  assertEquals(ignored[0].file, "Thumbs.db");
});

Deno.test("filterIgnoredFindings does not ignore if rule is expired", () => {
  const rules: IgnoreRule[] = [
    { id: "SECRET-1", reason: "Expirado", expires: "2020-01-01" },
  ];

  const { active, ignored } = filterIgnoredFindings(sampleFindings, rules);
  assertEquals(active.length, 3);
  assertEquals(ignored.length, 0);
});
