import * as github from "@actions/github";
import * as core from "@actions/core";

const COMMENT_TAG = "<!-- nemesis-audit-report-marker -->";

export async function upsertPrComment(
  token: string,
  markdownBody: string,
): Promise<void> {
  const context = github.context;
  const prNumber = context.payload.pull_request?.number;

  if (!prNumber) {
    if (core.isDebug()) {
      core.debug("Not a pull request event. Skipping PR comment.");
    }
    return;
  }

  const octokit = github.getOctokit(token);
  const { owner, repo } = context.repo;

  const fullBody = `${COMMENT_TAG}\n${markdownBody}`;

  try {
    // List existing comments to find previous Nemesis comment
    const { data: comments } = await octokit.rest.issues.listComments({
      owner,
      repo,
      issue_number: prNumber,
    });

    const existingComment = comments.find((c) =>
      c.body?.includes(COMMENT_TAG) || c.body?.includes("## 🛡️ Nemesis Security Audit Report")
    );

    if (existingComment) {
      await octokit.rest.issues.updateComment({
        owner,
        repo,
        comment_id: existingComment.id,
        body: fullBody,
      });
      core.info(`[Nemesis] Updated existing security audit comment #${existingComment.id} on PR #${prNumber}`);
    } else {
      await octokit.rest.issues.createComment({
        owner,
        repo,
        issue_number: prNumber,
        body: fullBody,
      });
      core.info(`[Nemesis] Created new security audit comment on PR #${prNumber}`);
    }
  } catch (err) {
    core.warning(`[Nemesis] Could not post PR comment: ${err instanceof Error ? err.message : String(err)}`);
  }
}
