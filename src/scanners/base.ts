import type {
  AuditFinding,
  FindingCategory,
  NemesisConfig,
  ScannerSummary,
} from "../types.ts";

export interface ScannerResult {
  summary: ScannerSummary;
  findings: AuditFinding[];
}

export interface Scanner {
  name: string;
  category: FindingCategory;
  run(config: NemesisConfig): Promise<ScannerResult>;
}
