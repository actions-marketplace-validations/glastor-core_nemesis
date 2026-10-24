import { join } from "@std/path";
import { ensureDir } from "@std/fs";
import type { AuditFinding, NemesisConfig, Severity } from "../types.ts";
import type { Scanner, ScannerResult } from "./base.ts";
import { runCommand } from "../utils/exec.ts";
import { checkTool } from "../utils/tool-checker.ts";

interface SemgrepResult {
  check_id: string;
  path: string;
  start: { line: number; col: number };
  end: { line: number; col: number };
  extra: {
    message: string;
    severity: string;
    metadata?: Record<string, unknown>;
  };
}

interface SemgrepOutput {
  results?: SemgrepResult[];
  errors?: unknown[];
}

export class SemgrepScanner implements Scanner {
  name = "semgrep";
  category = "SAST" as const;

  private mapSeverity(semgrepSeverity: string): Severity {
    switch (semgrepSeverity.toUpperCase()) {
      case "ERROR":
        return "HIGH";
      case "WARNING":
        return "MEDIUM";
      case "INFO":
        return "LOW";
      default:
        return "INFO";
    }
  }

  async run(config: NemesisConfig): Promise<ScannerResult> {
    const startTime = Date.now();
    const tool = await checkTool("semgrep");

    const counts: Record<Severity, number> = {
      CRITICAL: 0,
      HIGH: 0,
      MEDIUM: 0,
      LOW: 0,
      INFO: 0,
    };

    if (!tool.available) {
      return {
        summary: {
          tool: this.name,
          category: this.category,
          status: "skipped",
          durationMs: Date.now() - startTime,
          error: "Semgrep binary and Docker are not available in PATH",
          counts,
        },
        findings: [],
      };
    }

    await ensureDir(config.outputDir);
    const reportPath = join(config.outputDir, "semgrep-report.json");

    let cmd = "semgrep";
    let args: string[] = [];

    if (tool.useDocker) {
      cmd = "docker";
      args = [
        "run",
        "--rm",
        "-v",
        `${Deno.cwd()}:/src`,
        "semgrep/semgrep:1.98.0",
        "semgrep",
        "scan",
        "--config",
        config.semgrepRules,
        "--json",
        "--output",
        `/src/${reportPath}`,
        `/src/${config.targetPath}`,
      ];
    } else {
      args = [
        "scan",
        "--config",
        config.semgrepRules,
        "--json",
        "--output",
        reportPath,
        config.targetPath,
      ];
    }

    if (config.verbose) {
      console.log(`[Semgrep] Executing: ${cmd} ${args.join(" ")}`);
    }

    const execResult = await runCommand(cmd, args, {
      cwd: Deno.cwd(),
      timeoutMs: 600_000,
    });
    const durationMs = Date.now() - startTime;

    const findings: AuditFinding[] = [];

    try {
      const fileContent = await Deno.readTextFile(reportPath);
      const parsed: SemgrepOutput = JSON.parse(fileContent);
      const results = parsed.results ?? [];

      for (let i = 0; i < results.length; i++) {
        const item = results[i];
        const severity = this.mapSeverity(item.extra.severity);
        counts[severity]++;

        findings.push({
          id: `SAST-${i + 1}`,
          tool: this.name,
          category: this.category,
          severity,
          title: item.check_id,
          description: item.extra.message,
          file: item.path,
          line: item.start.line,
          endLine: item.end.line,
          column: item.start.col,
          ruleId: item.check_id,
          raw: item,
        });
      }
    } catch {
      if (execResult.code !== 0 && execResult.code !== 1) {
        return {
          summary: {
            tool: this.name,
            category: this.category,
            status: "failed",
            durationMs,
            error: execResult.stderr || execResult.stdout ||
              `Exit code ${execResult.code}`,
            counts,
          },
          findings: [],
        };
      }
    }

    return {
      summary: {
        tool: this.name,
        category: this.category,
        status: "success",
        durationMs,
        counts,
      },
      findings,
    };
  }
}
