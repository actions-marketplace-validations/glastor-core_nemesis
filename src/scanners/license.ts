import { basename, join } from "@std/path";
import { ensureDir } from "@std/fs";
import { exists } from "@std/fs/exists";
import type { AuditFinding, NemesisConfig, Severity } from "../types.ts";
import type { Scanner, ScannerResult } from "./base.ts";
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
      if (config.verbose) {
        console.log(
          "[LicenseScanner] Trivy no detectado. Activando Nemesis Native License Scanner.",
        );
      }
      return await this.runNativeFallback(config, startTime, counts);
    }

    await ensureDir(config.outputDir);
    const reportPath = join(config.outputDir, "licenses-report.json");
    const sbomPath = join(config.outputDir, "sbom.cyclonedx.json");

    let cmd = "trivy";
    let args: string[] = [];

    // 1. Run License Scan via Trivy
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

    const _execResult = await runCommand(cmd, args, {
      cwd: Deno.cwd(),
      timeoutMs: 300_000,
    });

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
        console.log(
          `[SBOM] Generating CycloneDX SBOM: ${cmd} ${sbomArgs.join(" ")}`,
        );
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
              description: `El paquete "${
                lic.PkgName ?? "N/A"
              }" utiliza una licencia copyleft (${licName}). En software comercial cerrado, esto puede requerir la liberación del código fuente derivado.`,
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
      // Fall back to native scanner if trivy report was not produced or failed
      return await this.runNativeFallback(config, startTime, counts);
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

  /**
   * Native manifest and license scanner when Trivy is not installed
   */
  private async runNativeFallback(
    config: NemesisConfig,
    startTime: number,
    counts: Record<Severity, number>,
  ): Promise<ScannerResult> {
    const findings: AuditFinding[] = [];
    const targetDir = config.targetPath;
    let counter = 1;
    const components: Array<
      { name: string; version: string; license?: string }
    > = [];

    try {
      // 1. Inspect Root LICENSE File
      const licenseFiles = ["LICENSE", "LICENSE.md", "LICENSE.txt", "LICENCE"];
      let rootLicenseType = "Unknown";
      let hasRootLicense = false;

      for (const lf of licenseFiles) {
        const lfPath = join(targetDir, lf);
        if (await exists(lfPath)) {
          hasRootLicense = true;
          try {
            const content = await Deno.readTextFile(lfPath);
            rootLicenseType = this.detectLicenseFromText(content);
          } catch {
            // Ignore
          }
          break;
        }
      }

      if (!hasRootLicense && config.requireLicense) {
        counts.LOW++;
        findings.push({
          id: `LICENSE-NATIVE-${counter++}`,
          tool: `${this.name} (native)`,
          category: this.category,
          severity: "LOW",
          title: "Falta archivo LICENSE en la raíz del repositorio",
          description:
            "No se encontró ningún archivo LICENSE o LICENSE.md que declare los términos de uso del software.",
          file: "LICENSE",
          ruleId: "license-missing-file",
        });
      }

      // 2. Inspect Manifests: deno.json, package.json, Cargo.toml
      // deno.json
      const denoJsonPath = join(targetDir, "deno.json");
      if (await exists(denoJsonPath)) {
        try {
          const content = JSON.parse(await Deno.readTextFile(denoJsonPath));
          const lic = content.license;
          components.push({
            name: content.name ?? "deno-project",
            version: content.version ?? "1.0.0",
            license: lic ?? rootLicenseType,
          });

          if (lic && this.isCopyleft(lic)) {
            counts.HIGH++;
            findings.push({
              id: `LICENSE-NATIVE-${counter++}`,
              tool: `${this.name} (native)`,
              category: this.category,
              severity: "HIGH",
              title: `Licencia Copyleft declarada en deno.json: ${lic}`,
              description: `deno.json declara una licencia copyleft (${lic}).`,
              file: "deno.json",
              license: lic,
              ruleId: "license-copyleft-risk",
            });
          }
        } catch {
          // Ignore parse errors
        }
      }

      // package.json
      const pkgJsonPath = join(targetDir, "package.json");
      if (await exists(pkgJsonPath)) {
        try {
          const content = JSON.parse(await Deno.readTextFile(pkgJsonPath));
          const lic = content.license;
          components.push({
            name: content.name ?? "npm-project",
            version: content.version ?? "1.0.0",
            license: lic ?? rootLicenseType,
          });

          if (lic && this.isCopyleft(lic)) {
            counts.HIGH++;
            findings.push({
              id: `LICENSE-NATIVE-${counter++}`,
              tool: `${this.name} (native)`,
              category: this.category,
              severity: "HIGH",
              title: `Licencia Copyleft declarada en package.json: ${lic}`,
              description:
                `package.json declara una licencia copyleft (${lic}).`,
              file: "package.json",
              license: lic,
              ruleId: "license-copyleft-risk",
            });
          }
        } catch {
          // Ignore
        }
      }

      // Cargo.toml
      const cargoTomlPath = join(targetDir, "Cargo.toml");
      if (await exists(cargoTomlPath)) {
        try {
          const content = await Deno.readTextFile(cargoTomlPath);
          const licMatch = /license\s*=\s*["']([^"']+)["']/.exec(content);
          if (licMatch) {
            const lic = licMatch[1];
            components.push({
              name: "cargo-project",
              version: "1.0.0",
              license: lic,
            });
            if (this.isCopyleft(lic)) {
              counts.HIGH++;
              findings.push({
                id: `LICENSE-NATIVE-${counter++}`,
                tool: `${this.name} (native)`,
                category: this.category,
                severity: "HIGH",
                title: `Licencia Copyleft declarada en Cargo.toml: ${lic}`,
                description:
                  `Cargo.toml declara una licencia copyleft (${lic}).`,
                file: "Cargo.toml",
                license: lic,
                ruleId: "license-copyleft-risk",
              });
            }
          }
        } catch {
          // Ignore
        }
      }

      // 3. Generate Native SBOM CycloneDX if requested
      if (config.generateSbom) {
        await ensureDir(config.outputDir);
        const sbomPath = join(config.outputDir, "sbom.cyclonedx.json");
        const sbom = {
          bomFormat: "CycloneDX",
          specVersion: "1.5",
          serialNumber: `urn:uuid:${crypto.randomUUID()}`,
          version: 1,
          metadata: {
            timestamp: new Date().toISOString(),
            tools: [
              {
                vendor: "GLASTOR-DEV",
                name: "Nemesis Native SBOM Generator",
                version: "1.1.0",
              },
            ],
            component: {
              type: "application",
              name: basename(Deno.cwd()),
              version: "1.1.0",
              licenses: [{
                license: {
                  id: rootLicenseType !== "Unknown" ? rootLicenseType : "MIT",
                },
              }],
            },
          },
          components: components.map((c) => ({
            type: "library",
            name: c.name,
            version: c.version,
            licenses: c.license ? [{ license: { id: c.license } }] : undefined,
          })),
        };
        await Deno.writeTextFile(sbomPath, JSON.stringify(sbom, null, 2));
      }
    } catch (err) {
      return {
        summary: {
          tool: `${this.name} (native)`,
          category: this.category,
          status: "failed",
          durationMs: Date.now() - startTime,
          error: err instanceof Error ? err.message : String(err),
          counts,
        },
        findings,
      };
    }

    return {
      summary: {
        tool: `${this.name} (native)`,
        category: this.category,
        status: "success",
        durationMs: Date.now() - startTime,
        counts,
      },
      findings,
    };
  }

  private isCopyleft(licenseStr: string): boolean {
    return this.copyleftLicenses.some((cl) =>
      licenseStr.toUpperCase().includes(cl.toUpperCase())
    );
  }

  private detectLicenseFromText(text: string): string {
    const upper = text.toUpperCase();
    if (
      upper.includes("MIT LICENSE") ||
      upper.includes("PERMISSION IS HEREBY GRANTED, FREE OF CHARGE")
    ) {
      return "MIT";
    }
    if (upper.includes("APACHE LICENSE") && upper.includes("VERSION 2.0")) {
      return "Apache-2.0";
    }
    if (upper.includes("GNU AFFERO GENERAL PUBLIC LICENSE")) {
      return "AGPL-3.0";
    }
    if (
      upper.includes("GNU GENERAL PUBLIC LICENSE") &&
      upper.includes("VERSION 3")
    ) {
      return "GPL-3.0";
    }
    if (
      upper.includes("GNU GENERAL PUBLIC LICENSE") &&
      upper.includes("VERSION 2")
    ) {
      return "GPL-2.0";
    }
    if (
      upper.includes("BSD 3-CLAUSE") || upper.includes("NEITHER THE NAME OF")
    ) {
      return "BSD-3-Clause";
    }
    if (upper.includes("BSD 2-CLAUSE")) {
      return "BSD-2-Clause";
    }
    if (upper.includes("MOZILLA PUBLIC LICENSE")) {
      return "MPL-2.0";
    }
    if (upper.includes("ISC LICENSE")) {
      return "ISC";
    }
    return "Custom/Proprietary";
  }
}
