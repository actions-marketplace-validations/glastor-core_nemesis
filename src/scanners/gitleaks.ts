import { basename, join, relative } from "@std/path";
import { ensureDir } from "@std/fs";
import { walk } from "@std/fs/walk";
import type { AuditFinding, NemesisConfig, Severity } from "../types.ts";
import type { Scanner, ScannerResult } from "./base.ts";
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

interface SecretPattern {
  id: string;
  name: string;
  regex: RegExp;
  description: string;
}

export class GitleaksScanner implements Scanner {
  name = "gitleaks";
  category = "SECRET" as const;

  // High-fidelity native detection patterns when Gitleaks is not installed
  private nativeSecretPatterns: SecretPattern[] = [
    {
      id: "github-pat",
      name: "GitHub Personal Access Token",
      regex: /\b(ghp_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{82})\b/,
      description: "GitHub Personal Access Token expuesto en código fuente.",
    },
    {
      id: "github-oauth",
      name: "GitHub OAuth / Fine-Grained Token",
      regex:
        /\b(gho_[A-Za-z0-9]{36}|ghs_[A-Za-z0-9]{36}|ghr_[A-Za-z0-9]{36})\b/,
      description: "Token de autenticación de GitHub expuesto.",
    },
    {
      id: "aws-access-key",
      name: "AWS Access Key ID",
      regex: /\b(AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}\b/,
      description: "Identificador de clave de acceso de AWS expuesto.",
    },
    {
      id: "openai-api-key",
      name: "OpenAI API Key",
      regex: /\b(sk-[A-Za-z0-9]{32,}|sk-proj-[A-Za-z0-9_-]{40,})\b/,
      description: "Clave de API de OpenAI expuesta.",
    },
    {
      id: "anthropic-api-key",
      name: "Anthropic API Key",
      regex: /\bsk-ant-[A-Za-z0-9_-]{40,}\b/,
      description: "Clave de API de Anthropic expuesta.",
    },
    {
      id: "private-key",
      name: "Clave Privada Criptográfica (RSA/SSH/EC)",
      regex: /-----BEGIN (RSA|EC|DSA|OPENSSH|PGP|PRIVATE) KEY-----/,
      description:
        "Certificado o bloque de clave privada embebido en el código.",
    },
    {
      id: "slack-token",
      name: "Slack API Token",
      regex: /\bxox[baprs]-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*\b/,
      description: "Token de Bot o Usuario de Slack expuesto.",
    },
    {
      id: "google-api-key",
      name: "Google API Key",
      regex: /\bAIza[0-9A-Za-z\-_]{35}\b/,
      description: "Clave de API de Google Cloud/Maps expuesta.",
    },
    {
      id: "stripe-secret-key",
      name: "Stripe Secret Key",
      regex: /\bsk_live_[0-9a-zA-Z]{24,}\b/,
      description: "Clave secreta productiva de Stripe expuesta.",
    },
    {
      id: "sendgrid-api-key",
      name: "SendGrid API Key",
      regex: /\bSG\.[0-9A-Za-z\-_]{22}\.[0-9A-Za-z\-_]{43}\b/,
      description: "Token de API de SendGrid expuesto.",
    },
  ];

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

    // If Gitleaks binary or Docker is missing, execute Native Secret Scanner fallback
    if (!tool.available) {
      if (config.verbose) {
        console.log(
          "[Gitleaks] Binario y Docker no detectados. Activando Nemesis Native Secret Scanner.",
        );
      }
      return await this.runNativeFallback(config, startTime, counts);
    }

    await ensureDir(config.outputDir);
    const reportPath = join(config.outputDir, "gitleaks-report.json");

    let cmd = "gitleaks";
    let args: string[] = [];

    // Check if target is inside a git repo
    const isGit = await runCommand("git", [
      "rev-parse",
      "--is-inside-work-tree",
    ], {
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

    const _execResult = await runCommand(cmd, args, { cwd: Deno.cwd() });
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
          title: item.Description ||
            `Exposed Secret (${item.RuleID || "Unknown"})`,
          description: `Hardcoded secret detected matching rule "${
            item.RuleID ?? "generic"
          }". Secrets must never be stored in source code.`,
          file: item.File,
          line: item.StartLine,
          endLine: item.EndLine,
          column: item.StartColumn,
          ruleId: item.RuleID,
          raw: item,
        });
      }
    } catch {
      // Fall back to native scanner if gitleaks report was not produced or failed
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
   * High-speed native regular expression scanner when external binaries are unavailable
   */
  private async runNativeFallback(
    config: NemesisConfig,
    startTime: number,
    counts: Record<Severity, number>,
  ): Promise<ScannerResult> {
    const findings: AuditFinding[] = [];
    const targetDir = config.targetPath;
    let findingIndex = 1;

    const skipExtensions =
      /\.(png|jpe?g|gif|ico|pdf|zip|tar|gz|exe|dll|so|wasm|lock)$/i;

    try {
      for await (
        const entry of walk(targetDir, {
          includeFiles: true,
          includeDirs: false,
          skip: [/\.git[\\/]/, /\.nemesis-reports[\\/]/, /node_modules[\\/]/],
        })
      ) {
        const fileName = basename(entry.path);
        if (skipExtensions.test(fileName)) continue;

        try {
          const stat = await Deno.stat(entry.path);
          if (stat.size > 2 * 1024 * 1024) continue; // Skip large blobs

          const text = await Deno.readTextFile(entry.path);
          const lines = text.split("\n");
          const relPath = relative(targetDir, entry.path).replace(/\\/g, "/");

          for (let lineNum = 1; lineNum <= lines.length; lineNum++) {
            const line = lines[lineNum - 1];
            if (line.length > 2000) continue; // Skip minified lines

            for (const pat of this.nativeSecretPatterns) {
              const match = pat.regex.exec(line);
              if (match) {
                counts.CRITICAL++;
                const matchedSecret = match[0];
                const masked = matchedSecret.length > 8
                  ? `${matchedSecret.slice(0, 4)}...${matchedSecret.slice(-4)}`
                  : "****";

                findings.push({
                  id: `SECRET-NATIVE-${findingIndex++}`,
                  tool: `${this.name} (native)`,
                  category: this.category,
                  severity: "CRITICAL",
                  title: `${pat.name} Detectado: [${masked}]`,
                  description: pat.description,
                  file: relPath,
                  line: lineNum,
                  ruleId: pat.id,
                });
                break; // One match per line
              }
            }
          }
        } catch {
          // Skip unreadable files
        }
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
}
