import { join } from "@std/path";
import { ensureDir } from "@std/fs";
import { AuditFinding, NemesisConfig, ScannerSummary, Severity } from "../types.ts";
import { Scanner, ScannerResult } from "./base.ts";
import { runCommand } from "../utils/exec.ts";
import { checkTool } from "../utils/tool-checker.ts";

interface TrivyLicenseItem {
  Name?: string;
  Category?: string;
  Severity?: string;
  PkgName?: string;
  FilePath?: string;
}

interface TrivyLicenseTarget {
  Target: string;
  Licenses?: TrivyLicenseItem[];
}

interface TrivyLicenseOutput {
  Results?: TrivyLicenseTarget[];
}

export class LicenseScanner implements Scanner {
  name = "license";
  category = "LICENSE" as const;

  // High-risk copyleft licenses that may force source disclosure in proprietary environments
  private copyleftLicenses = [
    "GPL-1.0",
    "GPL-2.0",
    "GPL-3.0",
    "AGPL-1.0",
    "AGPL-3.0",
    "SSPL-1.0",
    "EUPL-1.1",
    "EUPL-1.2",
    "OSL-3.0",
  ];

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
          error: "Trivy binary is required for license and SBOM generation",
          counts,
        },
        findings: [],
      };
    }

    await ensureDir(config.outputDir);
    const reportPath = join(config.outputDir, "licenses-report.json");
    const sbomPath = join(config.outputDir, "sbom.cyclonedx.json");

    let cmd = "trivy";
    let args: string[] = [];

    // 1. Run License Scan
    if (tool.useDocker) {
      cmd = "docker";
      args = [
        "run",
        "--rm",
        "-v",
        `${Deno.cwd()}:/work`,
        "aquasec/trivy:latest",
        "fs",
        "--scanners",
        "license",
        "--format",
        "json",
        "--output",
        `/work/${reportPath}`,
        `/work/${config.targetPath}`,
      ];
    } else {
      args = [
        "fs",
        "--scanners",
        "license",
        "--format",
        "json",
        "--output",
        reportPath,
        config.targetPath,
      ];
    }

    if (config.verbose) {
      console.log(`[LicenseScanner] Executing: ${cmd} ${args.join(" ")}`);
    }

    const execResult = await runCommand(cmd, args, { cwd: Deno.cwd(), timeoutMs: 300_000 });

    // 2. Run SBOM Generation if enabled
    if (config.generateSbom) {
      let sbomArgs: string[] = [];
      if (tool.useDocker) {
        sbomArgs = [
          "run",
          "--rm",
          "-v",
          `${Deno.cwd()}:/work`,
          "aquasec/trivy:latest",
          "fs",
          "--format",
          "cyclonedx",
          "--output",
          `/work/${sbomPath}`,
          `/work/${config.targetPath}`,
        ];
      } else {
        sbomArgs = [
          "fs",
          "--format",
          "cyclonedx",
          "--output",
          sbomPath,
          config.targetPath,
        ];
      }
      if (config.verbose) {
        console.log(`[SBOM] Generating CycloneDX SBOM: ${cmd} ${sbomArgs.join(" ")}`);
      }
      await runCommand(cmd, sbomArgs, { cwd: Deno.cwd(), timeoutMs: 300_000 });
    }

    const durationMs = Date.now() - startTime;
    const findings: AuditFinding[] = [];

    try {
      const fileContent = await Deno.readTextFile(reportPath);
      const parsed: TrivyLicenseOutput = JSON.parse(fileContent);
      const targets = parsed.Results ?? [];

      let counter = 1;
      for (const target of targets) {
        if (!target.Licenses) continue;

        for (const lic of target.Licenses) {
          const licName = lic.Name ?? "Unknown";
          const isCopyleft = this.copyleftLicenses.some((cl) =>
            licName.toUpperCase().includes(cl.toUpperCase())
          );

          if (isCopyleft) {
            counts.HIGH++;
            findings.push({
              id: `LICENSE-COPYLEFT-${counter++}`,
              tool: this.name,
              category: this.category,
              severity: "HIGH",
              title: `Licencia Copyleft Restrictiva: ${licName}`,
              description: `El paquete "${lic.PkgName ?? "N/A"}" utiliza una licencia copyleft (${licName}). En software comercial cerrado, esto puede requerir la liberación del código fuente derivado.`,
              file: lic.FilePath || target.Target,
              package: lic.PkgName,
              license: licName,
              ruleId: "license-copyleft-risk",
              raw: lic,
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
