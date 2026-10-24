// scripts/bump-version.ts
// Motor Nativo de Versionado Semántico Continuo (SemVer) para Nemesis y Glastor Core.
// Analiza Conventional Commits desde el último Git Tag y actualiza automáticamente:
// 1. deno.json (version)
// 2. CITATION.cff (version y date-released)
// 3. CHANGELOG.md (mueve de [Unreleased] a [X.Y.Z] - YYYY-MM-DD)

import { exists } from "@std/fs";

interface CommitInfo {
  hash: string;
  subject: string;
  body: string;
  type: string;
  scope?: string;
  isBreaking: boolean;
  raw: string;
}

async function runGit(args: string[]): Promise<string> {
  const cmd = new Deno.Command("git", {
    args,
    stdout: "piped",
    stderr: "piped",
  });
  const output = await cmd.output();
  return new TextDecoder().decode(output.stdout).trim();
}

async function getLatestTag(): Promise<string | null> {
  try {
    // Buscar tags con formato semver completo vX.Y.Z
    const tagsOutput = await runGit([
      "tag",
      "-l",
      "v*.*.*",
      "--sort=-v:refname",
    ]);
    const firstTag = tagsOutput.split("\n")[0]?.trim();
    if (firstTag && firstTag.length > 0) {
      return firstTag;
    }
    const tag = await runGit([
      "describe",
      "--tags",
      "--abbrev=0",
      "--match",
      "v*.*.*",
    ]);
    return tag.length > 0 ? tag : null;
  } catch {
    return null;
  }
}

function parseSemVer(v: string): [number, number, number] {
  const parts = v.replace(/^v/, "").split(".").map((n) => parseInt(n, 10));
  return [parts[0] || 0, parts[1] || 0, parts[2] || 0];
}

function compareSemVer(a: string, b: string): number {
  const [majA, minA, patA] = parseSemVer(a);
  const [majB, minB, patB] = parseSemVer(b);
  if (majA !== majB) return majA - majB;
  if (minA !== minB) return minA - minB;
  return patA - patB;
}

async function getCommitsSince(tag: string | null): Promise<CommitInfo[]> {
  const range = tag ? `${tag}..HEAD` : "HEAD";
  const logFormat = "%h%x1f%s%x1f%b%x1e";
  const rawLog = await runGit(["log", range, `--pretty=format:${logFormat}`]);

  if (!rawLog) return [];

  const rawEntries = rawLog.split("\x1e").filter((e) => e.trim().length > 0);
  const commits: CommitInfo[] = [];

  const conventionalRegex =
    /^(feat|fix|perf|refactor|docs|style|test|chore|ci|build|revert)(\((.+)\))?(!)?:\s*(.+)$/i;

  for (const entry of rawEntries) {
    const parts = entry.split("\x1f");
    const hash = parts[0]?.trim() || "";
    const subject = parts[1]?.trim() || "";
    const body = parts[2]?.trim() || "";

    // Omitir commits de release propios, merges y skips
    if (
      subject.startsWith("chore(release):") ||
      subject.startsWith("Merge ") ||
      subject.includes("[skip ci]")
    ) {
      continue;
    }

    const match = subject.match(conventionalRegex);
    const hasBreakingMarker = subject.includes("!:") ||
      body.toUpperCase().includes("BREAKING CHANGE:") ||
      body.toUpperCase().includes("BREAKING-CHANGE:");

    if (match) {
      const type = match[1].toLowerCase();
      const scope = match[3];
      commits.push({
        hash,
        subject,
        body,
        type,
        scope,
        isBreaking: hasBreakingMarker || match[4] === "!",
        raw: subject,
      });
    } else {
      // Commit no convencional: considerar patch por defecto
      commits.push({
        hash,
        subject,
        body,
        type: "chore",
        isBreaking: hasBreakingMarker,
        raw: subject,
      });
    }
  }

  return commits;
}

function determineBumpType(
  commits: CommitInfo[],
): "major" | "minor" | "patch" | "none" {
  if (commits.length === 0) return "none";

  let hasMinor = false;
  let hasPatch = false;

  for (const c of commits) {
    if (c.isBreaking) {
      return "major";
    }
    if (c.type === "feat") {
      hasMinor = true;
    } else {
      hasPatch = true;
    }
  }

  if (hasMinor) return "minor";
  if (hasPatch) return "patch";
  return "none";
}

function calculateNextVersion(
  current: string,
  bump: "major" | "minor" | "patch",
): string {
  const parts = current.replace(/^v/, "").split(".").map((n) =>
    parseInt(n, 10)
  );
  let major = parts[0] || 1;
  let minor = parts[1] || 0;
  let patch = parts[2] || 0;

  switch (bump) {
    case "major":
      major += 1;
      minor = 0;
      patch = 0;
      break;
    case "minor":
      minor += 1;
      patch = 0;
      break;
    case "patch":
      patch += 1;
      break;
  }

  return `${major}.${minor}.${patch}`;
}

async function updateDenoJson(newVersion: string) {
  const content = await Deno.readTextFile("deno.json");
  const parsed = JSON.parse(content);
  parsed.version = newVersion;
  await Deno.writeTextFile("deno.json", JSON.stringify(parsed, null, 2) + "\n");
}

async function updateCitation(newVersion: string, dateStr: string) {
  if (!(await exists("CITATION.cff"))) return;
  let content = await Deno.readTextFile("CITATION.cff");
  content = content.replace(/^version:\s*".*"/m, `version: "${newVersion}"`);
  content = content.replace(
    /^date-released:\s*".*"/m,
    `date-released: "${dateStr}"`,
  );
  await Deno.writeTextFile("CITATION.cff", content);
}

async function updateChangelog(
  newVersion: string,
  dateStr: string,
  commits: CommitInfo[],
) {
  if (!(await exists("CHANGELOG.md"))) return;
  const content = await Deno.readTextFile("CHANGELOG.md");

  // Agrupar commits por categoría
  const features: string[] = [];
  const fixes: string[] = [];
  const maintenance: string[] = [];

  for (const c of commits) {
    const line = `- ${c.subject} (\`${c.hash}\`)`;
    if (c.isBreaking || c.type === "feat") {
      features.push(line);
    } else if (c.type === "fix") {
      fixes.push(line);
    } else {
      maintenance.push(line);
    }
  }

  let releaseSection = `\n## [${newVersion}] - ${dateStr}\n\n`;

  if (features.length > 0) {
    releaseSection += `### ✨ Added\n\n${features.join("\n")}\n\n`;
  }
  if (fixes.length > 0) {
    releaseSection += `### 🐛 Fixed\n\n${fixes.join("\n")}\n\n`;
  }
  if (maintenance.length > 0) {
    releaseSection += `### 🔄 Changed & Maintenance\n\n${
      maintenance.join("\n")
    }\n\n`;
  }

  releaseSection += "---\n";

  // Insertar justo después de ## [Unreleased]
  const unreleasedMarker = "## [Unreleased]";
  const pos = content.indexOf(unreleasedMarker);

  if (pos !== -1) {
    // Buscar el siguiente separador tras [Unreleased]
    const afterUnreleased = pos + unreleasedMarker.length;
    const nextDivider = content.indexOf("---", afterUnreleased);

    if (nextDivider !== -1) {
      const insertIndex = nextDivider + 4; // después de "---\n"
      const updated = content.slice(0, insertIndex) + releaseSection +
        content.slice(insertIndex);
      await Deno.writeTextFile("CHANGELOG.md", updated);
    } else {
      const updated = content.replace(
        unreleasedMarker,
        `${unreleasedMarker}\n${releaseSection}`,
      );
      await Deno.writeTextFile("CHANGELOG.md", updated);
    }
  }
}

async function main() {
  const isDryRun = Deno.args.includes("--dry-run");
  const forceBump = Deno.args.find((a) => a.startsWith("--bump="))?.split(
    "=",
  )[1];

  console.log(
    "🚀 [Nemesis Auto-Version] Iniciando motor de versionado semántico...",
  );

  // 1. Obtener versión actual de deno.json
  const denoContent = await Deno.readTextFile("deno.json");
  const denoJson = JSON.parse(denoContent);
  const currentVersion: string = denoJson.version || "1.0.0";

  console.log(`📌 Versión actual en deno.json: v${currentVersion}`);

  // 2. Obtener último Git Tag
  const latestTag = await getLatestTag();
  console.log(
    `🏷️  Último tag Git detectado: ${
      latestTag || "Ninguno (inicio de proyecto)"
    }`,
  );

  // 3. Obtener commits desde el último tag
  const commits = await getCommitsSince(latestTag);
  console.log(`📦 Commits evaluables encontrados: ${commits.length}`);

  for (const c of commits) {
    console.log(
      `   - [${c.type}] ${c.subject} ${c.isBreaking ? "💥 (BREAKING)" : ""}`,
    );
  }

  // 4. Determinar tipo de salto
  let bumpType: "major" | "minor" | "patch" | "none" = "none";
  if (forceBump === "major" || forceBump === "minor" || forceBump === "patch") {
    bumpType = forceBump;
  } else {
    bumpType = determineBumpType(commits);
  }

  console.log(`📊 Salto SemVer determinado: ${bumpType.toUpperCase()}`);

  if (bumpType === "none") {
    console.log(
      "✔ No hay commits que requieran un nuevo release. Versión al día.",
    );
    if (Deno.env.get("GITHUB_OUTPUT")) {
      const ghOutput = Deno.env.get("GITHUB_OUTPUT")!;
      await Deno.writeTextFile(ghOutput, "has_bump=false\n", { append: true });
    }
    Deno.exit(0);
  }

  // 5. Calcular nueva versión tomando la versión mayor entre deno.json y el tag
  const tagVersion = latestTag ? latestTag.replace(/^v/, "") : "0.0.0";
  const baseVersion = compareSemVer(currentVersion, tagVersion) >= 0
    ? currentVersion
    : tagVersion;
  const newVersion = calculateNextVersion(baseVersion, bumpType);
  const tagName = `v${newVersion}`;
  const today = new Date().toISOString().split("T")[0];

  console.log(`✨ Nueva versión calculada: ${tagName} (Fecha: ${today})`);

  if (isDryRun) {
    console.log("🔍 Modo Dry-Run activo: no se modificaron archivos.");
    Deno.exit(0);
  }

  // 6. Actualizar archivos
  console.log("📝 Actualizando deno.json, CITATION.cff y CHANGELOG.md...");
  await updateDenoJson(newVersion);
  await updateCitation(newVersion, today);
  await updateChangelog(newVersion, today, commits);

  // 7. Enviar variables a GitHub Actions
  if (Deno.env.get("GITHUB_OUTPUT")) {
    const ghOutput = Deno.env.get("GITHUB_OUTPUT")!;
    const outputs = [
      `has_bump=true`,
      `old_version=${currentVersion}`,
      `new_version=${newVersion}`,
      `tag_name=${tagName}`,
      `release_date=${today}`,
    ].join("\n") + "\n";
    await Deno.writeTextFile(ghOutput, outputs, { append: true });
  }

  console.log(
    `🎉 [Nemesis Auto-Version] Versión actualizada exitosamente a ${tagName}.`,
  );
}

if (import.meta.main) {
  await main();
}
