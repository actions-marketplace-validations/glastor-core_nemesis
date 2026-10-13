import { join } from "@std/path";
import { exists } from "@std/fs/exists";
import type { AuditFinding, AuditReport, NemesisConfig } from "../types.ts";
import { runCommand } from "../utils/exec.ts";

export interface AutoFixResult {
  fixedCount: number;
  commitSha?: string;
  filesRemoved: string[];
  gitignoreUpdated: boolean;
}

export async function applyAutoFix(
  report: AuditReport,
  config: NemesisConfig,
): Promise<AutoFixResult> {
  const result: AutoFixResult = {
    fixedCount: 0,
    filesRemoved: [],
    gitignoreUpdated: false,
  };

  const targetDir = config.targetPath;

  // 1. Check if git is available
  const gitCheck = await runCommand("git", [
    "rev-parse",
    "--is-inside-work-tree",
  ], {
    cwd: targetDir,
  });
  const isGit = gitCheck.success;

  // 2. Filter findings for auto-fixable hygiene items
  const fixableToxicFiles: AuditFinding[] = report.findings.filter(
    (f) =>
      f.category === "HYGIENE" &&
      f.ruleId === "repo-junk-file" &&
      f.file,
  );

  const missingGitignore = report.findings.some(
    (f) => f.category === "HYGIENE" && f.ruleId === "repo-missing-gitignore",
  );

  const gitignorePath = join(targetDir, ".gitignore");
  const gitignoreContent = (await exists(gitignorePath))
    ? await Deno.readTextFile(gitignorePath)
    : "";

  const standardIgnoreRules = [
    ".DS_Store",
    "Thumbs.db",
    "desktop.ini",
    "*.log",
    "npm-debug.log*",
    "yarn-error.log*",
    "*.bak",
    "*.swp",
    ".env.local",
    ".env.*.local",
  ];

  // 3. Remove toxic files
  for (const item of fixableToxicFiles) {
    if (!item.file) continue;
    const fullPath = join(targetDir, item.file);

    try {
      if (await exists(fullPath)) {
        await Deno.remove(fullPath);
        result.filesRemoved.push(item.file);
        result.fixedCount++;

        if (isGit) {
          await runCommand("git", ["rm", "-f", "--cached", item.file], {
            cwd: targetDir,
          });
        }
      }
    } catch (err) {
      console.warn(
        `[Nemesis Auto-Fix] Error eliminando archivo ${item.file}:`,
        err,
      );
    }
  }

  // 4. Update or create .gitignore
  let rulesToAdd: string[] = [];
  if (missingGitignore || !gitignoreContent) {
    rulesToAdd = standardIgnoreRules;
  } else {
    for (const rule of standardIgnoreRules) {
      if (!gitignoreContent.includes(rule)) {
        rulesToAdd.push(rule);
      }
    }
  }

  if (rulesToAdd.length > 0) {
    const header = gitignoreContent
      ? "\n# Nemesis Hygiene Auto-Clean\n"
      : "# Nemesis Hygiene .gitignore\n";
    const newContent = gitignoreContent + header + rulesToAdd.join("\n") + "\n";
    await Deno.writeTextFile(gitignorePath, newContent);
    result.gitignoreUpdated = true;
    result.fixedCount++;
  }

  // 5. Commit and Push if inside a Git repo and changes were made
  if (isGit && (result.filesRemoved.length > 0 || result.gitignoreUpdated)) {
    try {
      await runCommand("git", ["add", "-A"], { cwd: targetDir });
      const statusRes = await runCommand("git", ["status", "--porcelain"], {
        cwd: targetDir,
      });

      if (statusRes.stdout.trim() !== "") {
        console.log(
          "[Nemesis Auto-Fix] Realizando commit automático de limpieza...",
        );

        // Ensure git author identity
        await runCommand("git", ["config", "user.name", "Nemesis Bot"], {
          cwd: targetDir,
        });
        await runCommand("git", [
          "config",
          "user.email",
          "bot@nemesis.security",
        ], { cwd: targetDir });

        const commitMessage =
          "chore(nemesis): auto-clean toxic files and update .gitignore [skip ci]";
        const commitRes = await runCommand("git", [
          "commit",
          "-m",
          commitMessage,
        ], { cwd: targetDir });

        if (commitRes.success) {
          const shaRes = await runCommand("git", [
            "rev-parse",
            "--short",
            "HEAD",
          ], { cwd: targetDir });
          result.commitSha = shaRes.stdout.trim();
          console.log(`[Nemesis Auto-Fix] Commit creado: ${result.commitSha}`);

          // Push if in GitHub Actions environment
          if (Deno.env.get("GITHUB_ACTIONS")) {
            console.log(
              "[Nemesis Auto-Fix] Subiendo commit de limpieza a la rama remota...",
            );
            const pushRes = await runCommand("git", ["push"], {
              cwd: targetDir,
            });
            if (!pushRes.success) {
              console.warn(
                "[Nemesis Auto-Fix] Push automático falló (verificar permisos contents: write):",
                pushRes.stderr,
              );
            } else {
              console.log(
                "[Nemesis Auto-Fix] ✔ Cambios de limpieza subidos a GitHub exitosamente.",
              );
            }
          }
        }
      }
    } catch (err) {
      console.warn(
        "[Nemesis Auto-Fix] Error creando commit de auto-remediación:",
        err,
      );
    }
  }

  return result;
}
