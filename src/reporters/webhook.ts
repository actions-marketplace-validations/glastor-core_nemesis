import { AuditReport } from "../types.ts";

export async function sendWebhookNotification(
  report: AuditReport,
  options: {
    slackWebhookUrl?: string;
    discordWebhookUrl?: string;
  },
): Promise<void> {
  const { slackWebhookUrl, discordWebhookUrl } = options;
  if (!slackWebhookUrl && !discordWebhookUrl) return;

  const repo = report.repository || "Repository";
  const statusEmoji = report.passed ? "✅" : "🚨";
  const statusText = report.passed ? "AUDIT PASSED" : "AUDIT FAILED";
  const commitShort = report.commitSha ? report.commitSha.substring(0, 7) : "N/A";

  // 1. Slack Notification
  if (slackWebhookUrl) {
    try {
      const payload = {
        text: `${statusEmoji} *Nemesis Security Audit - ${statusText}* on \`${repo}\``,
        blocks: [
          {
            type: "header",
            text: {
              type: "plain_text",
              text: `${statusEmoji} Nemesis Audit: ${statusText}`,
            },
          },
          {
            type: "section",
            fields: [
              { type: "mrkdwn", text: `*Repository:*\n${repo}` },
              { type: "mrkdwn", text: `*Commit:*\n\`${commitShort}\`` },
              { type: "mrkdwn", text: `*Critical:*\n${report.counts.CRITICAL}` },
              { type: "mrkdwn", text: `*High:*\n${report.counts.HIGH}` },
              { type: "mrkdwn", text: `*Medium:*\n${report.counts.MEDIUM}` },
              { type: "mrkdwn", text: `*Total Findings:*\n${report.totalFindings}` },
            ],
          },
        ],
      };

      await fetch(slackWebhookUrl, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });
      console.log("[Nemesis] Slack notification dispatched successfully.");
    } catch (err) {
      console.warn("[Nemesis] Failed to dispatch Slack webhook:", err);
    }
  }

  // 2. Discord Notification
  if (discordWebhookUrl) {
    try {
      const color = report.passed ? 3066993 : 15158332; // Green vs Red in decimal
      const payload = {
        embeds: [
          {
            title: `${statusEmoji} Nemesis Security Audit: ${statusText}`,
            description: `Audit result for **${repo}** at commit \`${commitShort}\``,
            color,
            fields: [
              { name: "Critical", value: `${report.counts.CRITICAL}`, inline: true },
              { name: "High", value: `${report.counts.HIGH}`, inline: true },
              { name: "Medium", value: `${report.counts.MEDIUM}`, inline: true },
              { name: "Total Findings", value: `${report.totalFindings}`, inline: true },
              { name: "Ignored / Excluded", value: `${report.ignoredFindings.length}`, inline: true },
            ],
            timestamp: report.timestamp,
            footer: { text: "Nemesis Security Auditor" },
          },
        ],
      };

      await fetch(discordWebhookUrl, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });
      console.log("[Nemesis] Discord notification dispatched successfully.");
    } catch (err) {
      console.warn("[Nemesis] Failed to dispatch Discord webhook:", err);
    }
  }
}
