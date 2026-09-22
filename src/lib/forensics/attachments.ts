import {
  shannonEntropy,
  obfuscationHeuristics,
  vbaSemanticAnalysis,
  structuralAnalysis,
  detectPolyglots,
  analyzeOleStreams,
  detectXlmMacros,
  pdfForensicSignals,
  inferMitreTechniques,
} from "./forensics";
import { SCORING_RULES } from "./scoring";
import type { ParsedAttachment } from "./eml-parser";

export interface AttachmentAnalysis {
  filename: string;
  contentType: string;
  size: number;
  entropy: number;
  score: number;
  reasons: string[];
  mitreTechniques: string[];
}

export async function analyzeAttachment(attachment: ParsedAttachment): Promise<AttachmentAnalysis> {
  const { content, filename } = attachment;
  const reasons: string[] = [];
  let score = 0;
  const signals: Record<string, boolean> = {};

  const entropy = shannonEntropy(content);
  if (entropy > 7.5) {
    score += SCORING_RULES.attachment.highEntropy;
    reasons.push(`High entropy (${entropy.toFixed(2)}) — possibly packed or encrypted content`);
  }

  const asText = content.toString("latin1");

  const obfScore = obfuscationHeuristics(asText);
  if (obfScore > 0) {
    score += obfScore;
    signals.obfuscation = true;
    reasons.push(`Obfuscation heuristics scored ${obfScore}`);
  }

  const vba = vbaSemanticAnalysis(asText);
  if (vba.autoExec && vba.suspiciousCalls.length > 0) {
    score += SCORING_RULES.attachment.vbaAutoExecWithCalls;
    signals.autoExec = true;
    signals.hasMacros = true;
    reasons.push(
      `Auto-executing macro with suspicious calls: ${vba.suspiciousCalls.join(", ")}`,
    );
  }
  if (vba.envFingerprinting) {
    signals.envFingerprinting = true;
    reasons.push("VBA performs environment/sandbox fingerprinting");
  }
  if (vba.stagingLogic) {
    signals.stagingLogic = true;
    reasons.push("VBA uses payload-staging string manipulation (Chr/Split/Join)");
  }

  const structural = await structuralAnalysis(content);
  if (structural.structureScore > 0) {
    score += structural.structureScore;
    reasons.push(`Archive contains risky files: ${structural.unexpectedFiles.join(", ")}`);
  }

  const polyglots = detectPolyglots(content);
  if (polyglots.length > 0) {
    score += SCORING_RULES.attachment.polyglot;
    signals.polyglot = true;
    reasons.push(...polyglots);
  }

  const ole = analyzeOleStreams(content);
  if (ole.oleAnomalies) {
    score += SCORING_RULES.attachment.oleAnomaly;
    signals.oleAnomaly = true;
    reasons.push(...ole.riskyStreams);
  }

  const xlm = detectXlmMacros(content);
  if (xlm.length > 0) {
    score += SCORING_RULES.attachment.xlmMacro;
    signals.xlmMacro = true;
    reasons.push(...xlm);
  }

  if (filename.toLowerCase().endsWith(".pdf")) {
    const pdf = pdfForensicSignals(content);
    if (pdf.hasJs || pdf.hasLaunch) {
      score += SCORING_RULES.attachment.pdfJsOrLaunch;
      signals.hasJs = pdf.hasJs;
      reasons.push(
        `PDF ${pdf.hasJs ? "contains JavaScript" : ""}${pdf.hasJs && pdf.hasLaunch ? " and " : ""}${pdf.hasLaunch ? "contains a /Launch action" : ""}`.trim(),
      );
    }
    if (pdf.suspiciousTags.length > 0) reasons.push(...pdf.suspiciousTags);
  }

  const doubleExtMatch = /\.[a-z0-9]{2,4}\.(exe|js|vbs|bat|cmd|scr|ps1)$/i.test(filename);
  if (doubleExtMatch) {
    signals.doubleExtension = true;
    score += 25;
    reasons.push(`Double file extension detected: ${filename}`);
  }

  return {
    filename,
    contentType: attachment.contentType,
    size: attachment.size,
    entropy,
    score,
    reasons,
    mitreTechniques: inferMitreTechniques(signals),
  };
}
