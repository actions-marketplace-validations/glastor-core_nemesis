import * as github from "@actions/github";
import * as core from "@actions/core";
import type { AuditReport } from "../types.ts";

interface ReviewComment {
  path: string;
  line: number;
  side: "RIGHT";
  body: string;
}

export async function postPullRequestSuggestions(
  token: string,
  report: AuditReport,
): Promise<number> {
  const context = github.context;
  const prNumber = context.payload.pull_request?.number;
  const commitId = context.payload.pull_request?.head?.sha ||
    Deno.env.get("GITHUB_SHA");

  if (!prNumber || !commitId) {
    if (core.isDebug()) {
      core.debug(
        "[Nemesis Suggestions] No es un evento Pull Request con commit ID. Omitiendo.",
      );
    }
    return 0;
  }

  const octokit = github.getOctokit(token);
  const { owner, repo } = context.repo;

  const reviewComments: ReviewComment[] = [];

  for (const f of report.findings) {
    if (!f.file || !f.line) continue;

    // 1. Dependency vulnerability with fixed version (SCA)
    if (f.category === "SCA" && f.package && f.fixedVersion) {
      const suggestionBody = [
        `### 🛡️ Nemesis Auto-Remediation: Vulnerabilidad en Dependencia`,
        `> **${f.title}** (${f.severity})`,
        `\`${f.package}\` versión instalada: \`${
          f.installedVersion ?? "N/A"
        }\` -> Corregida en: \`${f.fixedVersion}\``,
        "",
        "```suggestion",
        `    "${f.package}": "^${f.fixedVersion}",`,
        "```",
        "",
        `*Haz clic en **"Commit suggestion"** para actualizar la dependencia a la versión segura.*`,
      ].join("\n");

      reviewComments.push({
        path: f.file.replace(/\\/g, "/"),
        line: f.line,
        side: "RIGHT",
        body: suggestionBody,
      });
      continue;
    }

    // 2. Secret Exposure (Gitleaks)
    if (f.category === "SECRET") {
      const suggestionBody = [
        `### 🚨 Nemesis Alerta de Secreto Expuesto`,
        `> Se detectó una credencial sensible hardcodeada. Nunca persistas credenciales en el código fuente.`,
        "",
        "```suggestion",
        `// TODO(seguridad): Cargar credencial desde variables de entorno o GitHub Secrets`,
        `const secret = Deno.env.get("API_KEY") || process.env.API_KEY || "";`,
        "```",
        "",
        `*Aplica esta sugerencia para reemplazar la credencial expuesta.*`,
      ].join("\n");

      reviewComments.push({
        path: f.file.replace(/\\/g, "/"),
        line: f.line,
        side: "RIGHT",
        body: suggestionBody,
      });
      continue;
    }

    // 3. Custom suggested replacement if available
    if (f.suggestedReplacement) {
      const suggestionBody = [
        `### 💡 Nemesis Corrección Sugerida (${f.severity})`,
        `> ${f.description}`,
        "",
        "```suggestion",
        f.suggestedReplacement,
        "```",
      ].join("\n");

      reviewComments.push({
        path: f.file.replace(/\\/g, "/"),
        line: f.line,
        side: "RIGHT",
        body: suggestionBody,
      });
    }
  }

  if (reviewComments.length === 0) {
    return 0;
  }

  // Cap suggestions at 10 to avoid hitting GitHub API rate limits
  const topSuggestions = reviewComments.slice(0, 10);

  try {
    await octokit.rest.pulls.createReview({
      owner,
      repo,
      pull_number: prNumber,
      commit_id: commitId,
      event: "COMMENT",
      body:
        `### 🛡️ Nemesis: Sugerencias Interactivas de Corrección (${topSuggestions.length})\nSe generaron sugerencias de 1-clic para corregir las vulnerabilidades detectadas en este Pull Request.`,
      comments: topSuggestions,
    });

    core.info(
      `[Nemesis] Publicadas ${topSuggestions.length} sugerencias interactivas en el PR #${prNumber}`,
    );
    return topSuggestions.length;
  } catch (err) {
    core.warning(
      `[Nemesis] No se pudieron publicar sugerencias de review en el PR: ${
        err instanceof Error ? err.message : String(err)
      }`,
    );
    return 0;
  }
}
