import { join } from "@std/path";
import { ensureDir } from "@std/fs";
import { AuditFinding, NemesisConfig, ScannerSummary, Severity } from "../types.ts";
import { Scanner, ScannerResult } from "./base.ts";
import { runCommand } from "../utils/exec.ts";
import { checkTool } from "../utils/tool-checker.ts";

interface GitleaksFinding {
  Description?: string;
  StartLine?: number;
  EndLine?: number;
  StartColumn?: number;
  Match?: string;
  Secret?: string;
  File?: string;
  Commit?: string;
  Author?: string;
  RuleID?: string;
}

export class GitleaksScanner implements Scanner {
  name = "gitleaks";
  category = "SECRET" as const;

  async run(config: NemesisConfig): Promise<ScannerResult> {
    const startTime = Date.now();
    const tool = await checkTool("gitleaks");

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
          error: "Gitleaks binary and Docker are not available in PATH",
          counts,
        },
        findings: [],
      };
    }

    await ensureDir(config.outputDir);
    const reportPath = join(config.outputDir, "gitleaks-report.json");

    let cmd = "gitleaks";
    let args: string[] = [];

    // Check if target is inside a git repo
    const isGit = await runCommand("git", ["rev-parse", "--is-inside-work-tree"], {
      cwd: config.targetPath,
    });

    if (tool.useDocker) {
      cmd = "docker";
      args = [
        "run",
        "--rm",
        "-v",
        `${Deno.cwd()}:/work`,
        "zricethezav/gitleaks:latest",
        "detect",
        "--source",
        `/work/${config.targetPath}`,
        "--report-format",
        "json",
        "--report-path",
        `/work/${reportPath}`,
        "--no-banner",
      ];
      if (!isGit.success) {
        args.push("--no-git");
      }
    } else {
      args = [
        "detect",
        "--source",
        config.targetPath,
        "--report-format",
        "json",
        "--report-path",
        reportPath,
        "--no-banner",
      ];
      if (!isGit.success) {
        args.push("--no-git");
      }
    }

    if (config.verbose) {
      console.log(`[Gitleaks] Executing: ${cmd} ${args.join(" ")}`);
    }

    // Gitleaks returns 0 when no leaks found, 1 when leaks found, >1 on error
    const execResult = await runCommand(cmd, args, { cwd: Deno.cwd() });
    const durationMs = Date.now() - startTime;

    const findings: AuditFinding[] = [];

    try {
      const fileContent = await Deno.readTextFile(reportPath);
      const parsed: GitleaksFinding[] = JSON.parse(fileContent);

      for (let i = 0; i < parsed.length; i++) {
        const item = parsed[i];
        counts.CRITICAL++;

        findings.push({
          id: `SECRET-${item.RuleID || "LEAK"}-${i + 1}`,
          tool: this.name,
          category: this.category,
          severity: "CRITICAL",
          title: item.Description || `Exposed Secret (${item.RuleID || "Unknown"})`,
          description: `Hardcoded secret detected matching rule "${item.RuleID ?? "generic"}". Secrets must never be stored in source code.`,
          file: item.File,
          line: item.StartLine,
          endLine: item.EndLine,
          column: item.StartColumn,
          ruleId: item.RuleID,
          raw: item,
        });
      }
    } catch {
      // If report is empty or no leaks, Gitleaks might not create the file or it might be valid empty
      if (execResult.code > 1) {
        return {
          summary: {
            tool: this.name,
            category: this.category,
            status: "failed",
            durationMs,
            error: execResult.stderr || execResult.stdout || `Exit code ${execResult.code}`,
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
