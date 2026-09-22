import { db } from "@/lib/db";
import { logAction } from "@/lib/audit";
import { parseEml } from "./eml-parser";
import { analyzeHeaders } from "./headers";
import { analyzeBody } from "./body";
import { analyzeAttachment, type AttachmentAnalysis } from "./attachments";
import { deriveVerdict, classifyThreat } from "./scoring";
import type { CaseSeverity } from "@prisma/client";

function severityFromScore(score: number): CaseSeverity {
  if (score >= 71) return "CRITICAL";
  if (score >= 45) return "HIGH";
  if (score >= 31) return "MEDIUM";
  if (score > 0) return "LOW";
  return "INFO";
}

export async function analyzeEmail(content: Buffer) {
  const email = await parseEml(content);
  const headerAnalysis = await analyzeHeaders(email.headers);
  const bodyAnalysis = await analyzeBody(email.primaryBody);

  const attachmentAnalyses: AttachmentAnalysis[] = [];
  for (const attachment of email.attachments) {
    attachmentAnalyses.push(await analyzeAttachment(attachment));
  }

  const attachmentScore = attachmentAnalyses.reduce((sum, a) => sum + a.score, 0);
  const totalScore = headerAnalysis.score + bodyAnalysis.score + attachmentScore;
  const verdict = deriveVerdict(totalScore);

  const allReasons = [
    ...headerAnalysis.reasons,
    ...bodyAnalysis.reasons,
    ...attachmentAnalyses.flatMap((a) => a.reasons),
  ];
  const threatClass = classifyThreat(allReasons);
  const mitreTechniques = [...new Set(attachmentAnalyses.flatMap((a) => a.mitreTechniques))];

  const kase = await db.case.create({
    data: {
      sourceType: "EMAIL_ANALYSIS",
      title: email.subject || "(no subject)",
      summary: `From: ${email.from} — ${threatClass?.threatType ?? "Email analysis"}`,
      severity: severityFromScore(totalScore),
      status: verdict === "benign" ? "RESOLVED" : "OPEN",
      verdict,
      riskScore: totalScore,
      resolvedAt: verdict === "benign" ? new Date() : null,
      metadata: {
        from: email.from,
        to: email.to,
        subject: email.subject,
        headerScore: headerAnalysis.score,
        bodyScore: bodyAnalysis.score,
        attachmentScore,
        totalScore,
        urls: bodyAnalysis.urls,
        suspiciousDomains: bodyAnalysis.suspiciousDomains,
        authResults: headerAnalysis.authResults,
        dkimSelector: headerAnalysis.dkimSelector,
        attachments: attachmentAnalyses,
        threatClass,
      } as never,
    },
  });

  if (headerAnalysis.reasons.length > 0) {
    await db.detection.create({
      data: {
        caseId: kase.id,
        source: "EMAIL_HEADER_AUTH",
        ruleId: `header-auth@@${Date.now()}`,
        title: "Header authentication findings",
        severity: severityFromScore(headerAnalysis.score),
        evidence: { reasons: headerAnalysis.reasons, authResults: headerAnalysis.authResults } as never,
      },
    });
  }

  if (bodyAnalysis.reasons.length > 0) {
    await db.detection.create({
      data: {
        caseId: kase.id,
        source: "EMAIL_BODY_URL",
        ruleId: `body-url@@${Date.now()}`,
        title: "Body/URL findings",
        severity: severityFromScore(bodyAnalysis.score),
        evidence: { reasons: bodyAnalysis.reasons, suspiciousDomains: bodyAnalysis.suspiciousDomains } as never,
      },
    });
  }

  for (const attachment of attachmentAnalyses) {
    if (attachment.reasons.length === 0) continue;
    await db.detection.create({
      data: {
        caseId: kase.id,
        source: "EMAIL_ATTACHMENT_FORENSICS",
        ruleId: `attachment-forensics@@${Date.now()}`,
        title: `${attachment.filename}: ${attachment.reasons[0]}`,
        severity: severityFromScore(attachment.score),
        evidence: attachment as never,
      },
    });
  }

  for (const hop of headerAnalysis.hops) {
    await db.timelineEntry.create({
      data: {
        caseId: kase.id,
        occurredAt: kase.createdAt,
        actor: hop.from,
        action: "mail_hop",
        detail: `Hop ${hop.hop} from ${hop.from} (${hop.ip}), delay ${hop.delay}`,
      },
    });
  }

  await logAction({
    caseId: kase.id,
    action: "forensics.email_analyzed",
    detail: { verdict, totalScore, mitreTechniques },
  });

  return kase.id;
}

export async function getEmailCase(caseId: string) {
  return db.case.findUnique({
    where: { id: caseId },
    include: {
      detections: { orderBy: { createdAt: "desc" } },
      timeline: { orderBy: { occurredAt: "asc" } },
    },
  });
}

export async function listEmailCases() {
  return db.case.findMany({
    where: { sourceType: "EMAIL_ANALYSIS" },
    orderBy: { createdAt: "desc" },
    take: 100,
  });
}
