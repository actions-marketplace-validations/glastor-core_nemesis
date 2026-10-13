import { join } from "@std/path";
import { ensureDir } from "@std/fs";
import * as core from "@actions/core";
import { loadConfig, showHelp } from "./config.ts";
import { AuditFinding, AuditReport, ScannerSummary, Severity } from "./types.ts";
import { GitleaksScanner } from "./scanners/gitleaks.ts";
import { SemgrepScanner } from "./scanners/semgrep.ts";
import { TrivyScanner } from "./scanners/trivy.ts";
import { HygieneScanner } from "./scanners/hygiene.ts";
import { Scanner } from "./scanners/base.ts";
import { printConsoleReport } from "./reporters/console.ts";
import { generateMarkdownReport } from "./reporters/markdown.ts";
import { generateSarifReport } from "./reporters/sarif.ts";
import { upsertPrComment } from "./github/pr-commenter.ts";
import { createWorkflowAnnotations } from "./github/annotator.ts";

async function main() {
  if (Deno.args.includes("-h") || Deno.args.includes("--help")) {
    showHelp();
    Deno.exit(0);
  }

  const config = loadConfig(Deno.args);
  await ensureDir(config.outputDir);

  const scanners: Scanner[] = [];

  if (config.scanSecrets) {
    scanners.push(new GitleaksScanner());
  }
  if (config.scanSast) {
    scanners.push(new SemgrepScanner());
  }
  if (config.scanSca) {
    scanners.push(new TrivyScanner());
  }
  if (config.scanHygiene) {
    scanners.push(new HygieneScanner());
  }

  if (scanners.length === 0) {
    console.error("No scanners enabled. Use --secrets, --sast, --sca, --hygiene or --all.");
    Deno.exit(1);
  }

  console.log(`[Nemesis] Starting audit on: ${config.targetPath}`);
  console.log(`[Nemesis] Enabled modules: ${scanners.map((s) => s.name).join(", ")}`);

  const scannerSummaries: ScannerSummary[] = [];
  const allFindings: AuditFinding[] = [];

  const totalCounts: Record<Severity, number> = {
    CRITICAL: 0,
    HIGH: 0,
    MEDIUM: 0,
    LOW: 0,
    INFO: 0,
  };

  // Run scanners sequentially or in parallel
  for (const scanner of scanners) {
    console.log(`[Nemesis] Running ${scanner.name}...`);
    try {
      const res = await scanner.run(config);
      scannerSummaries.push(res.summary);
      allFindings.push(...res.findings);

      totalCounts.CRITICAL += res.summary.counts.CRITICAL;
      totalCounts.HIGH += res.summary.counts.HIGH;
      totalCounts.MEDIUM += res.summary.counts.MEDIUM;
      totalCounts.LOW += res.summary.counts.LOW;
      totalCounts.INFO += res.summary.counts.INFO;
    } catch (err) {
      console.error(`[Nemesis] Error executing scanner ${scanner.name}:`, err);
      scannerSummaries.push({
        tool: scanner.name,
        category: scanner.category,
        status: "failed",
        durationMs: 0,
        error: err instanceof Error ? err.message : String(err),
        counts: { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 },
      });
    }
  }

  // Determine pass / fail
  let passed = true;
  let failureReason: string | undefined;

  if (config.failOnCritical && totalCounts.CRITICAL > 0) {
    passed = false;
    failureReason = `Found ${totalCounts.CRITICAL} CRITICAL vulnerabilities (fail-on-critical is enabled).`;
  } else if (config.failOnHigh && (totalCounts.CRITICAL + totalCounts.HIGH) > 0) {
    passed = false;
    failureReason = `Found ${totalCounts.CRITICAL + totalCounts.HIGH} HIGH/CRITICAL vulnerabilities (fail-on-high is enabled).`;
  } else if (config.failOnMedium && (totalCounts.CRITICAL + totalCounts.HIGH + totalCounts.MEDIUM) > 0) {
    passed = false;
    failureReason = `Found ${totalCounts.CRITICAL + totalCounts.HIGH + totalCounts.MEDIUM} MEDIUM or higher vulnerabilities.`;
  }

  const report: AuditReport = {
    timestamp: new Date().toISOString(),
    targetPath: config.targetPath,
    commitSha: Deno.env.get("GITHUB_SHA"),
    repository: Deno.env.get("GITHUB_REPOSITORY"),
    scanners: scannerSummaries,
    findings: allFindings,
    totalFindings: allFindings.length,
    counts: totalCounts,
    passed,
    failureReason,
  };

  // 1. Terminal report
  printConsoleReport(report);

  // 2. Write JSON report
  const jsonReportPath = join(config.outputDir, "nemesis-report.json");
  await Deno.writeTextFile(jsonReportPath, JSON.stringify(report, null, 2));

  // 3. Generate & Write Markdown report
  const markdownContent = generateMarkdownReport(report);
  const mdReportPath = join(config.outputDir, "nemesis-report.md");
  await Deno.writeTextFile(mdReportPath, markdownContent);

  // 4. Generate & Write SARIF report
  const sarifContent = generateSarifReport(report);
  const sarifReportPath = join(config.outputDir, "nemesis-report.sarif");
  await Deno.writeTextFile(sarifReportPath, sarifContent);

  // 5. GitHub Actions Specific Outputs & Annotations
  const isGitHubActions = !!Deno.env.get("GITHUB_ACTIONS");
  if (isGitHubActions) {
    // Write GitHub Step Summary
    try {
      await core.summary.addRaw(markdownContent).write();
    } catch {
      // Ignored if not in runner
    }

    // Set GitHub Action outputs
    core.setOutput("passed", String(report.passed));
    core.setOutput("total-findings", String(report.totalFindings));
    core.setOutput("critical-count", String(report.counts.CRITICAL));
    core.setOutput("high-count", String(report.counts.HIGH));
    core.setOutput("report-json", jsonReportPath);
    core.setOutput("report-md", mdReportPath);
    core.setOutput("report-sarif", sarifReportPath);

    // Annotations on PR files
    if (config.createAnnotations) {
      createWorkflowAnnotations(report.findings);
    }

    // PR Comment
    if (config.postPrComment && config.githubToken) {
      await upsertPrComment(config.githubToken, markdownContent);
    }

    if (!passed) {
      core.setFailed(failureReason ?? "Security audit failed threshold requirements.");
    }
  } else if (!passed) {
    Deno.exit(1);
  }
}

if (import.meta.main) {
  await main();
}
