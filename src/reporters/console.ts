import { bold, cyan, green, red, yellow, gray, magenta, blue } from "@std/fmt/colors";
import { AuditReport, Severity } from "../types.ts";

export function printConsoleReport(report: AuditReport): void {
  console.log("\n" + cyan(bold("==================================================")));
  console.log(cyan(bold("        N E M E S I S   S E C U R I T Y           ")));
  console.log(cyan(bold("==================================================")));
  console.log(gray(`Timestamp: ${report.timestamp}`));
  console.log(gray(`Target:    ${report.targetPath}\n`));

  console.log(bold("--- Modules Executed ---"));
  for (const s of report.scanners) {
    const statusText = s.status === "success"
      ? green("✔ SUCCESS")
      : s.status === "skipped"
      ? yellow("⚠ SKIPPED")
      : red("✖ FAILED");

    console.log(
      `  • ${bold(s.tool.toUpperCase().padEnd(10))} [${statusText}] (${s.durationMs}ms)` +
        (s.error ? gray(` - ${s.error}`) : ""),
    );
  }

  console.log("\n" + bold("--- Findings by Severity ---"));
  console.log(`  ${red("CRITICAL:")} ${report.counts.CRITICAL}`);
  console.log(`  ${magenta("HIGH:    ")} ${report.counts.HIGH}`);
  console.log(`  ${yellow("MEDIUM:  ")} ${report.counts.MEDIUM}`);
  console.log(`  ${blue("LOW:     ")} ${report.counts.LOW}`);
  console.log(`  ${gray("INFO:    ")} ${report.counts.INFO}`);
  console.log(`  ${bold("TOTAL:   ")} ${report.totalFindings}\n`);

  if (report.findings.length > 0) {
    console.log(bold("--- Top Findings ---"));
    const preview = report.findings.slice(0, 10);
    for (const f of preview) {
      const sevColor = f.severity === "CRITICAL"
        ? red
        : f.severity === "HIGH"
        ? magenta
        : f.severity === "MEDIUM"
        ? yellow
        : blue;

      const location = f.file ? gray(` (${f.file}${f.line ? `:${f.line}` : ""})`) : "";
      console.log(`  [${sevColor(f.severity)}] [${f.category}] ${bold(f.title)}${location}`);
      if (f.cve || f.package) {
        console.log(`    ${gray(`Pkg: ${f.package ?? "N/A"} | Fix: ${f.fixedVersion ?? "N/A"} | CVE: ${f.cve ?? "N/A"}`)}`);
      }
    }
    if (report.findings.length > 10) {
      console.log(gray(`  ... and ${report.findings.length - 10} more findings (see report file)`));
    }
    console.log();
  }

  console.log(cyan(bold("==================================================")));
  if (report.passed) {
    console.log(green(bold("✔ AUDIT PASSED - No threshold-violating vulnerabilities found")));
  } else {
    console.log(red(bold(`✖ AUDIT FAILED - ${report.failureReason}`)));
  }
  console.log(cyan(bold("==================================================\n")));
}
