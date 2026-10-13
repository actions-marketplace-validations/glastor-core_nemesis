import { basename, join, relative } from "@std/path";
import { walk } from "@std/fs/walk";
import { exists } from "@std/fs/exists";
import type {
  AuditFinding,
  NemesisConfig,
  Severity,
} from "../types.ts";
import type { Scanner, ScannerResult } from "./base.ts";
import { runCommand } from "../utils/exec.ts";

export class HygieneScanner implements Scanner {
  name = "hygiene";
  category = "HYGIENE" as const;

  // Patterns that should never be committed into a clean repository
  private toxicPatterns = [
    {
      regex: /^\.env(\.(local|development|staging|production|test))?$/i,
      except: /^\.env\.(example|sample|template|dist)$/i,
      severity: "HIGH" as Severity,
      title: "Archivo de entorno detectado (.env)",
      desc:
        "Los archivos .env contienen configuraciones locales o secretos. Usa archivos .env.example sin credenciales.",
    },
    {
      regex: /^(\.DS_Store|Thumbs\.db|desktop\.ini)$/i,
      severity: "LOW" as Severity,
      title: "Archivo basura del sistema operativo",
      desc:
        "Archivos generados por Windows/macOS que ensucian el repositorio. Añade a tu .gitignore global o del repo.",
    },
    {
      regex:
        /^(npm-debug\.log.*|yarn-error\.log.*|yarn-debug\.log.*|pnpm-debug\.log.*|debug\.log)$/i,
      severity: "LOW" as Severity,
      title: "Archivo de registro / log detectado",
      desc:
        "Los archivos de log no deben persistirse en el control de versiones.",
    },
    {
      regex: /\.(swp|swo|bak|old|orig|~)$/i,
      severity: "LOW" as Severity,
      title: "Archivo temporal o de respaldo de editor",
      desc:
        "Archivos temporales generados por editores (Vim, backup files) que ensucian el historial.",
    },
    {
      regex: /\.(pyc|pyo)$/i,
      severity: "LOW" as Severity,
      title: "Bytecode de Python compilado",
      desc: "Los archivos *.pyc deben ser ignorados en .gitignore.",
    },
    {
      regex: /\.(dump|dmp)$/i,
      severity: "MEDIUM" as Severity,
      title: "Dump de base de datos o memoria",
      desc:
        "Los dumps de datos pueden contener información sensible y ocupan espacio innecesario.",
    },
  ];

  private toxicDirectories = [
    "node_modules",
    "vendor",
    "__pycache__",
    ".pytest_cache",
    ".sass-cache",
    ".parcel-cache",
  ];

  // Conflict markers in git files
  private conflictMarkerRegex = /^(<{7} [^\n]+|={7}|>{7} [^\n]+)$/m;

  async run(config: NemesisConfig): Promise<ScannerResult> {
    const startTime = Date.now();
    const findings: AuditFinding[] = [];

    const counts: Record<Severity, number> = {
      CRITICAL: 0,
      HIGH: 0,
      MEDIUM: 0,
      LOW: 0,
      INFO: 0,
    };

    const targetDir = config.targetPath;
    const maxSizeBytes = config.maxFileSizeMb * 1024 * 1024;
    let findingIndex = 1;

    try {
      // 1. Check Repository Health Files at Root
      const hasGitignore = await exists(join(targetDir, ".gitignore"));
      if (!hasGitignore) {
        counts.MEDIUM++;
        findings.push({
          id: `HYGIENE-${findingIndex++}`,
          tool: this.name,
          category: this.category,
          severity: "MEDIUM",
          title: "Falta archivo .gitignore en la raíz",
          description:
            "Todo repositorio debe contar con un archivo .gitignore para prevenir la inclusión accidental de basura o secretos.",
          file: ".gitignore",
          ruleId: "repo-missing-gitignore",
        });
      }

      const hasReadme = (await exists(join(targetDir, "README.md"))) ||
        (await exists(join(targetDir, "README"))) ||
        (await exists(join(targetDir, "README.txt")));
      if (!hasReadme) {
        counts.LOW++;
        findings.push({
          id: `HYGIENE-${findingIndex++}`,
          tool: this.name,
          category: this.category,
          severity: "LOW",
          title: "Falta archivo README.md",
          description:
            "El repositorio no posee un README.md con la descripción y documentación inicial del proyecto.",
          file: "README.md",
          ruleId: "repo-missing-readme",
        });
      }

      if (config.requireLicense) {
        const hasLicense = (await exists(join(targetDir, "LICENSE"))) ||
          (await exists(join(targetDir, "LICENSE.md"))) ||
          (await exists(join(targetDir, "LICENSE.txt")));
        if (!hasLicense) {
          counts.LOW++;
          findings.push({
            id: `HYGIENE-${findingIndex++}`,
            tool: this.name,
            category: this.category,
            severity: "LOW",
            title: "Falta archivo LICENSE",
            description:
              "No se encontró un archivo de licencia que especifique los derechos y términos de uso del código.",
            file: "LICENSE",
            ruleId: "repo-missing-license",
          });
        }
      }

      // Check if we are inside a Git repository
      const gitCheck = await runCommand("git", [
        "rev-parse",
        "--is-inside-work-tree",
      ], {
        cwd: targetDir,
      });
      const isGitRepo = gitCheck.success;

      const isIgnoredByGit = async (relPath: string): Promise<boolean> => {
        if (!isGitRepo) return false;
        const res = await runCommand("git", ["check-ignore", "-q", relPath], {
          cwd: targetDir,
        });
        return res.code === 0;
      };

      // 2. Walk directory to find toxic files, oversized blobs and merge conflict markers
      for await (
        const entry of walk(targetDir, {
          includeDirs: true,
          includeFiles: true,
          skip: [/\.git[\\/]/, /\.nemesis-reports[\\/]/],
        })
      ) {
        const relPath = relative(targetDir, entry.path).replace(/\\/g, "/");
        if (!relPath || relPath === ".") continue;

        // If file or directory is properly ignored by .gitignore, skip unless tracked
        if (await isIgnoredByGit(relPath)) {
          continue;
        }

        const fileName = basename(entry.path);

        // Check toxic directories
        if (entry.isDirectory) {
          if (this.toxicDirectories.includes(fileName)) {
            counts.HIGH++;
            findings.push({
              id: `HYGIENE-${findingIndex++}`,
              tool: this.name,
              category: this.category,
              severity: "HIGH",
              title: `Directorio indebido comiteado: ${fileName}/`,
              description:
                `El directorio "${relPath}" contiene dependencias o artefactos de compilación. Debe estar ignorado en .gitignore.`,
              file: relPath,
              ruleId: "repo-toxic-directory",
            });
          }
          continue;
        }

        // Check toxic file patterns
        for (const pattern of this.toxicPatterns) {
          if (pattern.regex.test(fileName)) {
            if (pattern.except && pattern.except.test(fileName)) {
              continue; // Exemption (e.g. .env.example)
            }
            counts[pattern.severity]++;
            findings.push({
              id: `HYGIENE-${findingIndex++}`,
              tool: this.name,
              category: this.category,
              severity: pattern.severity,
              title: `${pattern.title}: ${fileName}`,
              description: pattern.desc,
              file: relPath,
              ruleId: "repo-junk-file",
            });
            break;
          }
        }

        // Check oversized files (Blob Bloat)
        try {
          const fileInfo = await Deno.stat(entry.path);
          if (fileInfo.size > maxSizeBytes) {
            const sizeMb = (fileInfo.size / (1024 * 1024)).toFixed(2);
            counts.MEDIUM++;
            findings.push({
              id: `HYGIENE-${findingIndex++}`,
              tool: this.name,
              category: this.category,
              severity: "MEDIUM",
              title: `Archivo excesivamente pesado (${sizeMb} MB)`,
              description:
                `El archivo supera el límite configurado de ${config.maxFileSizeMb} MB. Para mantener el repositorio ágil, considera usar Git LFS o almacenamiento en la nube.`,
              file: relPath,
              fileSizeBytes: fileInfo.size,
              ruleId: "repo-oversized-blob",
            });
          }

          // Check unresolved Git Merge Conflict markers (in files under 2MB)
          if (fileInfo.size < 2 * 1024 * 1024 && !fileName.endsWith(".lock")) {
            const isText =
              !/\.(png|jpe?g|gif|ico|pdf|zip|tar|gz|exe|dll|so|wasm)$/i.test(
                fileName,
              );
            if (isText) {
              const textContent = await Deno.readTextFile(entry.path);
              if (this.conflictMarkerRegex.test(textContent)) {
                counts.HIGH++;
                findings.push({
                  id: `HYGIENE-${findingIndex++}`,
                  tool: this.name,
                  category: this.category,
                  severity: "HIGH",
                  title:
                    `Marcadores de conflicto de merge Git sin resolver en ${fileName}`,
                  description:
                    `El archivo "${relPath}" contiene marcadores de conflicto de Git (<<<<<<< HEAD, =======, >>>>>>>). Deben resolverse antes de integrar.`,
                  file: relPath,
                  ruleId: "repo-merge-conflict-marker",
                });
              }
            }
          }
        } catch {
          // Skip if unable to stat/read
        }
      }

      // 3. Security Audit for GitHub Actions Workflows (.github/workflows)
      const workflowsDir = join(targetDir, ".github", "workflows");
      if (await exists(workflowsDir)) {
        for await (
          const wfEntry of walk(workflowsDir, {
            maxDepth: 1,
            includeFiles: true,
            includeDirs: false,
            exts: [".yml", ".yaml"],
          })
        ) {
          const wfRelPath = relative(targetDir, wfEntry.path).replace(
            /\\/g,
            "/",
          );
          try {
            const wfContent = await Deno.readTextFile(wfEntry.path);

            // Check for explicit permissions
            const hasPermissions = /^\s*permissions:\s*/m.test(wfContent);
            if (!hasPermissions) {
              counts.MEDIUM++;
              findings.push({
                id: `HYGIENE-${findingIndex++}`,
                tool: this.name,
                category: this.category,
                severity: "MEDIUM",
                title: `Workflow sin bloque de permisos explícito: ${
                  basename(wfEntry.path)
                }`,
                description:
                  `El workflow "${wfRelPath}" no define 'permissions:'. En GitHub Actions, la falta de permisos explícitos puede otorgar acceso de escritura por defecto a los jobs. Aplica el principio de mínimo privilegio declarando 'permissions: read-all' o permisos mínimos.`,
                file: wfRelPath,
                ruleId: "workflow-missing-permissions",
              });
            } else if (/^\s*permissions:\s*write-all\b/m.test(wfContent)) {
              counts.HIGH++;
              findings.push({
                id: `HYGIENE-${findingIndex++}`,
                tool: this.name,
                category: this.category,
                severity: "HIGH",
                title: `Permisos excesivos 'permissions: write-all' en ${
                  basename(wfEntry.path)
                }`,
                description:
                  `El workflow "${wfRelPath}" utiliza 'write-all'. Otorga capacidades completas sobre contenidos, pull requests y seguridad. Reduce los permisos a los estrictamente necesarios.`,
                file: wfRelPath,
                ruleId: "workflow-excessive-permissions",
              });
            }
          } catch {
            // Ignore if unreadable
          }
        }
      }

      // 4. Check git tracking inconsistencies (files tracked by git that match .gitignore)
      const gitInconsistentCheck = await runCommand("git", [
        "ls-files",
        "-i",
        "--exclude-standard",
      ], {
        cwd: targetDir,
        timeoutMs: 15_000,
      });

      if (
        gitInconsistentCheck.success &&
        gitInconsistentCheck.stdout.trim() !== ""
      ) {
        const trackedIgnored = gitInconsistentCheck.stdout.trim().split("\n");
        for (const item of trackedIgnored) {
          const cleanItem = item.trim();
          if (!cleanItem) continue;
          counts.LOW++;
          findings.push({
            id: `HYGIENE-${findingIndex++}`,
            tool: this.name,
            category: this.category,
            severity: "LOW",
            title:
              `Archivo rastreado por Git pero ignorado en .gitignore: ${cleanItem}`,
            description:
              `El archivo "${cleanItem}" sigue siendo rastreado por Git a pesar de coincidir con reglas de .gitignore. Ejecuta "git rm --cached ${cleanItem}" para desenrastrarlo.`,
            file: cleanItem,
            ruleId: "repo-tracked-ignored-file",
          });
        }
      }
    } catch (err) {
      return {
        summary: {
          tool: this.name,
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
        tool: this.name,
        category: this.category,
        status: "success",
        durationMs: Date.now() - startTime,
        counts,
      },
      findings,
    };
  }
}
