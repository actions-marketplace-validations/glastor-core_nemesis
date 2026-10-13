// scripts/verify-commit.ts
// Valida que el mensaje del commit siga la convención de .github/COMMIT_CONVENTION.md

const commitMsgFile = Deno.args[0];

if (!commitMsgFile) {
  console.error(
    "❌ [Nemesis Hook] Falta la ruta del archivo con el mensaje de commit.",
  );
  Deno.exit(1);
}

try {
  const content = await Deno.readTextFile(commitMsgFile);
  const firstLine = content.split("\n")[0].trim();

  // Eximir merges automáticos y reversiones estándar
  if (
    firstLine.startsWith("Merge ") ||
    firstLine.startsWith("Revert ") ||
    firstLine.startsWith("Initial commit")
  ) {
    Deno.exit(0);
  }

  // Expresión regular oficial basada en Conventional Commits
  const conventionalRegex =
    /^(revert: )?(feat|fix|polish|docs|style|refactor|perf|test|workflow|ci|chore|types)(\([\w.-]+\))?: .{1,80}$/;

  if (!conventionalRegex.test(firstLine)) {
    console.error(
      "\n❌ [Nemesis Hook] Mensaje de commit no cumple con Conventional Commits:\n",
    );
    console.error(`   "${firstLine}"\n`);
    console.error(
      "📋 Formato esperado: <tipo>(<alcance opcional>): <descripción>",
    );
    console.error(
      "   Tipos válidos: feat, fix, docs, style, refactor, perf, test, workflow, ci, chore, types, polish",
    );
    console.error("   Ejemplos correctos:");
    console.error("     feat(scanners): add native secret scanning fallback");
    console.error("     fix(hygiene): resolve windows path normalization");
    console.error("     docs: update usage guide in README\n");
    console.error(
      "📖 Consulta .github/COMMIT_CONVENTION.md para más información.\n",
    );
    Deno.exit(1);
  }

  console.log("✔  [Nemesis Hook] Mensaje de commit verificado correctamente.");
  Deno.exit(0);
} catch (err) {
  console.error(
    "❌ [Nemesis Hook] Error leyendo el archivo del mensaje de commit:",
    err,
  );
  Deno.exit(1);
}
