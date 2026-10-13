import { z } from "zod";
import * as yaml from "@std/yaml";
import { join } from "@std/path";
import { exists } from "@std/fs/exists";
import type { AuditFinding } from "../types.ts";

export const IgnoreRuleSchema = z.object({
  id: z.string().optional(),
  rule: z.string().optional(),
  cve: z.string().optional(),
  path: z.string().optional(),
  reason: z.string({
    required_error: "Debes especificar una 'reason' justificando la exclusión",
  }),
  expires: z.string().optional(), // ISO date "YYYY-MM-DD"
});

export const NemesisFileConfigSchema = z.object({
  version: z.string().optional().default("1"),
  ignore: z.array(IgnoreRuleSchema).optional().default([]),
  settings: z.object({
    maxFileSizeMb: z.number().optional(),
    requireLicense: z.boolean().optional(),
    allowedLicenses: z.array(z.string()).optional(),
  }).optional().default({}),
});

export type IgnoreRule = z.infer<typeof IgnoreRuleSchema>;
export type NemesisFileConfig = z.infer<typeof NemesisFileConfigSchema>;

export async function loadNemesisFileConfig(
  targetPath: string,
  customConfigPath?: string,
): Promise<NemesisFileConfig | null> {
  const possiblePaths = customConfigPath ? [customConfigPath] : [
    join(targetPath, ".nemesis.yml"),
    join(targetPath, ".nemesis.yaml"),
    join(targetPath, ".nemesis.json"),
  ];

  for (const p of possiblePaths) {
    if (await exists(p)) {
      try {
        const text = await Deno.readTextFile(p);
        let parsedRaw: unknown;
        if (p.endsWith(".json")) {
          parsedRaw = JSON.parse(text);
        } else {
          parsedRaw = yaml.parse(text);
        }
        return NemesisFileConfigSchema.parse(parsedRaw);
      } catch (err) {
        console.warn(
          `[Nemesis] Advertencia: Error parseando archivo de configuración "${p}":`,
          err,
        );
      }
    }
  }

  return null;
}

export function filterIgnoredFindings(
  findings: AuditFinding[],
  rules: IgnoreRule[],
): { active: AuditFinding[]; ignored: AuditFinding[] } {
  if (!rules || rules.length === 0) {
    return { active: findings, ignored: [] };
  }

  const now = new Date();
  const active: AuditFinding[] = [];
  const ignored: AuditFinding[] = [];

  for (const finding of findings) {
    let matchedRule: IgnoreRule | undefined;

    for (const rule of rules) {
      // Check expiration date
      if (rule.expires) {
        const expDate = new Date(rule.expires);
        if (!isNaN(expDate.getTime()) && now > expDate) {
          // Rule expired, skip
          continue;
        }
      }

      // Check ID match
      if (rule.id && (finding.id === rule.id || finding.id.includes(rule.id))) {
        matchedRule = rule;
        break;
      }

      // Check Rule/Check ID match
      if (
        rule.rule && finding.ruleId &&
        finding.ruleId.toLowerCase().includes(rule.rule.toLowerCase())
      ) {
        matchedRule = rule;
        break;
      }

      // Check CVE match
      if (
        rule.cve && finding.cve &&
        finding.cve.toUpperCase() === rule.cve.toUpperCase()
      ) {
        matchedRule = rule;
        break;
      }

      // Check File Path match
      if (rule.path && finding.file) {
        const normalizedFile = finding.file.replace(/\\/g, "/");
        const normalizedRule = rule.path.replace(/\\/g, "/");
        if (
          normalizedFile.includes(normalizedRule) ||
          normalizedFile === normalizedRule
        ) {
          matchedRule = rule;
          break;
        }
      }
    }

    if (matchedRule) {
      ignored.push({
        ...finding,
        ignored: true,
        ignoreReason: matchedRule.reason,
      });
    } else {
      active.push(finding);
    }
  }

  return { active, ignored };
}
