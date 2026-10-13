import { runCommand } from "./exec.ts";

export async function getChangedFiles(
  targetDir: string,
  baseRef = "origin/main",
): Promise<string[] | null> {
  // Check if target is a git repository
  const isGit = await runCommand("git", ["rev-parse", "--is-inside-work-tree"], {
    cwd: targetDir,
  });
  if (!isGit.success) {
    return null;
  }

  // Check GITHUB_BASE_REF if running in GitHub Actions PR
  const prBase = Deno.env.get("GITHUB_BASE_REF");
  const compareRef = prBase ? `origin/${prBase}` : baseRef;

  // Try git diff with compareRef
  let diffRes = await runCommand("git", ["diff", "--name-only", `${compareRef}...HEAD`], {
    cwd: targetDir,
  });

  // If compareRef failed (e.g. shallow clone or origin/main not fetched), try HEAD~1
  if (!diffRes.success) {
    diffRes = await runCommand("git", ["diff", "--name-only", "HEAD~1"], {
      cwd: targetDir,
    });
  }

  // If still failed, try git status for staged/unstaged uncommitted files
  if (!diffRes.success) {
    diffRes = await runCommand("git", ["status", "--porcelain"], {
      cwd: targetDir,
    });
    if (diffRes.success) {
      const files = diffRes.stdout
        .split("\n")
        .map((l) => l.trim().substring(3).trim())
        .filter(Boolean);
      return files.length > 0 ? files : [];
    }
    return null;
  }

  const files = diffRes.stdout
    .split("\n")
    .map((l) => l.trim())
    .filter(Boolean);

  return files;
}
