import { z } from "zod";

import { PROVIDER_KINDS, bedrockModelProblem, type ProviderKind } from "@/lib/ai/catalog";

// What a person types to add an AI provider, for the platform's providers
// and a client's own alike: checked here, then stored with its secret sealed
// (by the caller, with the platform's or the client's key).

export const AWS_REGION = /^[a-z]{2}(-gov|-iso[a-z]*)?-[a-z]+-\d$/;

export const providerInputSchema = z
  .object({
    id: z.string().optional(),
    name: z.string().trim().min(2).max(80),
    kind: z.enum(PROVIDER_KINDS as [ProviderKind, ...ProviderKind[]]),
    baseUrl: z.string().trim().max(300).optional().or(z.literal("")),
    model: z.string().trim().min(1).max(120),
    // Anthropic, Azure OpenAI or an OpenAI-compatible server's key; a Bedrock
    // API key.
    apiKey: z.string().trim().max(4000).optional(),
    // Bedrock with an access key pair instead.
    awsAccessKeyId: z.string().trim().max(128).optional(),
    awsSecretAccessKey: z.string().trim().max(256).optional(),
    awsSessionToken: z.string().trim().max(4000).optional(),
    isLocal: z.boolean().default(false),
    // Where inference runs (a residency label such as "india"); for Bedrock
    // the AWS region it calls.
    region: z.string().trim().toLowerCase().max(40).optional().or(z.literal("")),
  })
  .superRefine((p, ctx) => {
    const issue = (path: string, message: string) => ctx.addIssue({ code: "custom", path: [path], message });
    if (p.kind === "openai_compatible" || p.kind === "azure_openai") {
      if (!p.baseUrl) issue("baseUrl", p.kind === "azure_openai" ? "Azure OpenAI needs the resource's endpoint (https://NAME.openai.azure.com)" : "An OpenAI-compatible provider needs its base URL");
      else {
        let url: URL | null = null;
        try {
          url = new URL(p.baseUrl);
        } catch {
          issue("baseUrl", "The base URL isn't a URL");
        }
        if (url && !/^https?:$/.test(url.protocol)) issue("baseUrl", "The base URL starts with http:// or https://");
        if (url && p.kind === "azure_openai" && url.protocol !== "https:") issue("baseUrl", "An Azure OpenAI endpoint starts with https://");
      }
    }
    if (p.kind === "bedrock") {
      if (!p.region || !AWS_REGION.test(p.region)) issue("region", "Bedrock needs the AWS region it calls, such as ap-south-1");
      const problem = bedrockModelProblem(p.model);
      if (problem) issue("model", problem);
      if (!!p.awsAccessKeyId !== !!p.awsSecretAccessKey) issue("awsSecretAccessKey", "An access key needs both its ID and its secret");
      if (p.apiKey && p.awsAccessKeyId) issue("apiKey", "Give a Bedrock API key or an access key pair, not both");
    }
  });
export type ProviderInput = z.input<typeof providerInputSchema>;
export type ParsedProviderInput = z.output<typeof providerInputSchema>;

// The secret to seal, if the input brings a new one (blank keeps the stored
// one on an edit). Bedrock's is JSON so the kind of credential survives.
export function providerSecret(p: ParsedProviderInput): string | undefined {
  if (p.kind === "bedrock") {
    if (p.awsAccessKeyId && p.awsSecretAccessKey) return JSON.stringify({ accessKeyId: p.awsAccessKeyId, secretAccessKey: p.awsSecretAccessKey, ...(p.awsSessionToken ? { sessionToken: p.awsSessionToken } : {}) });
    return p.apiKey ? JSON.stringify({ apiKey: p.apiKey }) : undefined;
  }
  return p.apiKey || undefined;
}

// The columns other than the secret.
export function providerColumns(p: ParsedProviderInput) {
  return {
    name: p.name,
    kind: p.kind,
    baseUrl: p.kind === "openai_compatible" || p.kind === "azure_openai" ? p.baseUrl || null : null,
    model: p.model,
    isLocal: p.kind === "openai_compatible" ? p.isLocal : false,
    region: p.region || null,
  };
}
