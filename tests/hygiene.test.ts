import { assertEquals } from "@std/assert";
import { join } from "@std/path";
import { ensureDir } from "@std/fs";
import { HygieneScanner } from "../src/scanners/hygiene.ts";
import { loadConfig } from "../src/config.ts";

Deno.test("HygieneScanner detects toxic files, missing permissions and conflict markers", async () => {
  const tempDir = await Deno.makeTempDir({ prefix: "nemesis_hygiene_test_" });

  try {
    // 1. Create a toxic file
    await Deno.writeTextFile(join(tempDir, ".env.local"), "SECRET_KEY=12345");

    // 2. Create another toxic file
    await Deno.writeTextFile(join(tempDir, "debug.log"), "some debug output");

    // 3. Create a workflow without permissions
    const wfDir = join(tempDir, ".github", "workflows");
    await ensureDir(wfDir);
    await Deno.writeTextFile(
      join(wfDir, "test-workflow.yml"),
      "name: Test\non: push\njobs:\n  test:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo ok\n",
    );

    // 4. Create a file with merge conflict markers
    await Deno.writeTextFile(
      join(tempDir, "conflicted.ts"),
      "const a = 1;\n<<<<<<< HEAD\nconst b = 2;\n=======\nconst b = 3;\n>>>>>>> feature\n",
    );

    const config = loadConfig([
      "--path",
      tempDir,
      "--output-dir",
      join(tempDir, ".reports"),
      "--hygiene",
    ]);

    const scanner = new HygieneScanner();
    const result = await scanner.run(config);

    assertEquals(result.summary.status, "success");

    // Check toxic file findings
    const toxicFindings = result.findings.filter((f) =>
      f.ruleId === "repo-junk-file"
    );
    assertEquals(toxicFindings.length >= 2, true);

    // Check workflow permissions finding
    const wfFindings = result.findings.filter((f) =>
      f.ruleId === "workflow-missing-permissions"
    );
    assertEquals(wfFindings.length, 1);

    // Check merge conflict marker finding
    const conflictFindings = result.findings.filter((f) =>
      f.ruleId === "repo-merge-conflict-marker"
    );
    assertEquals(conflictFindings.length, 1);
  } finally {
    await Deno.remove(tempDir, { recursive: true });
  }
});
