import { join } from "@std/path";
import { ensureDir } from "@std/fs";
import { AuditFinding, NemesisConfig, ScannerSummary, Severity } from "../types.ts";
import { Scanner, ScannerResult } from "./base.ts";
import { runCommand } from "../utils/exec.ts";
import { checkTool } from "../utils/tool-checker.ts";

interface TrivyVulnerability {
  VulnerabilityID: string;
  PkgName: string;
  InstalledVersion: string;
  FixedVersion?: string;
  Severity: string;
  Title?: string;
  Description?: string;
}

interface TrivyMisconfig {
  ID: string;
  Title: string;
  Description: string;
  Severity: string;
  Message?: string;
  Resolution?: string;
}

interface TrivyTargetResult {
  Target: string;
  Class?: string;
  Type?: string;
  Vulnerabilities?: TrivyVulnerability[];
  Misconfigurations?: TrivyMisconfig[];
}

interface TrivyOutput {
  Results?: TrivyTargetResult[];
}

export class TrivyScanner implements Scanner {
  name = "trivy";
  category = "SCA" as const;

  private mapSeverity(trivySeverity: string): Severity {
    switch (trivySeverity.toUpperCase()) {
      case "CRITICAL":
        return "CRITICAL";
      case "HIGH":
        return "HIGH";
      case "MEDIUM":
        return "MEDIUM";
      case "LOW":
        return "LOW";
      default:
        return "INFO";
    }
  }

  async run(config: NemesisConfig): Promise<ScannerResult> {
    const startTime = Date.now();
    const tool = await checkTool("trivy");

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
          error: "Trivy binary and Docker are not available in PATH",
          counts,
        },
        findings: [],
      };
    }

    await ensureDir(config.outputDir);
    const reportPath = join(config.outputDir, "trivy-report.json");

    let cmd = "trivy";
    let args: string[] = [];

    if (tool.useDocker) {
      cmd = "docker";
      args = [
        "run",
        "--rm",
        "-v",
        `${Deno.cwd()}:/work`,
        "aquasec/trivy:latest",
        "fs",
        "--format",
        "json",
        "--output",
        `/work/${reportPath}`,
        "--severity",
        config.trivySeverity,
        `/work/${config.targetPath}`,
      ];
    } else {
      args = [
        "fs",
        "--format",
        "json",
        "--output",
        reportPath,
        "--severity",
        config.trivySeverity,
        config.targetPath,
      ];
    }

    if (config.verbose) {
      console.log(`[Trivy] Executing: ${cmd} ${args.join(" ")}`);
    }

    const execResult = await runCommand(cmd, args, { cwd: Deno.cwd(), timeoutMs: 600_000 });
    const durationMs = Date.now() - startTime;

    const findings: AuditFinding[] = [];

    try {
      const fileContent = await Deno.readTextFile(reportPath);
      const parsed: TrivyOutput = JSON.parse(fileContent);
      const targetResults = parsed.Results ?? [];

      let counter = 1;
      for (const target of targetResults) {
        // Process dependencies vulnerabilities (SCA)
        if (target.Vulnerabilities) {
          for (const vuln of target.Vulnerabilities) {
            const severity = this.mapSeverity(vuln.Severity);
            counts[severity]++;

            findings.push({
              id: `SCA-${counter++}`,
              tool: this.name,
              category: "SCA",
              severity,
              title: `${vuln.PkgName} (${vuln.VulnerabilityID})`,
              description: vuln.Title || vuln.Description || "Vulnerability in dependency",
              file: target.Target,
              package: vuln.PkgName,
              installedVersion: vuln.InstalledVersion,
              fixedVersion: vuln.FixedVersion,
              cve: vuln.VulnerabilityID,
              ruleId: vuln.VulnerabilityID,
              raw: vuln,
            });
          }
        }

        // Process misconfigurations (Dockerfile, Terraform, K8s, etc.)
        if (target.Misconfigurations) {
          for (const mis of target.Misconfigurations) {
            const severity = this.mapSeverity(mis.Severity);
            counts[severity]++;

            findings.push({
              id: `MISCONFIG-${counter++}`,
              tool: this.name,
              category: "MISCONFIG",
              severity,
              title: mis.Title || mis.ID,
              description: mis.Message || mis.Description || "Configuration security issue",
              file: target.Target,
              ruleId: mis.ID,
              raw: mis,
            });
          }
        }
      }
    } catch {
      if (execResult.code !== 0 && execResult.code !== 1) {
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
