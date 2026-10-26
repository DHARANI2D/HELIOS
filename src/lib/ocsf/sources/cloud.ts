import { ACTIVITY, CLASS, SEVERITY, STATUS, ocsfEvent, type OcsfEvent } from "@/lib/ocsf/schema";
import { MappingError, asArray, dateOf, get, num, str, type Raw } from "@/lib/ocsf/sources/util";

// Cloud control-plane audit logs to OCSF API Activity (sign-ins to
// Authentication): AWS CloudTrail records, Google Cloud audit log entries
// (LogEntry with an AuditLog protoPayload, as Pub/Sub delivers them), and
// Azure Activity Log events (the Microsoft.Insights eventtypes/management
// REST shape).

function verb(operation: string): number {
  const op = operation.split(/[./]/).pop() ?? operation;
  if (/^(create|put|run|start|insert|add|import|upload|register|generate|invite)/i.test(op) || /\/write$/i.test(operation)) return ACTIVITY.api.CREATE;
  if (/^(get|list|describe|lookup|search|read|download|export|view|batchget|head)/i.test(op) || /\/read$/i.test(operation)) return ACTIVITY.api.READ;
  if (/^(update|modify|set|attach|patch|change|enable|disable|associate|replace|tag|untag|reboot|stop)/i.test(op)) return ACTIVITY.api.UPDATE;
  if (/^(delete|remove|detach|terminate|destroy|purge|revoke|deregister|disassociate)/i.test(op) || /\/delete$/i.test(operation)) return ACTIVITY.api.DELETE;
  return ACTIVITY.OTHER;
}

// ---------------------------------------------------------------- AWS CloudTrail

export function cloudTrail(r: Raw): OcsfEvent {
  const name = str(r.eventName);
  if (!name) throw new MappingError("CloudTrail record has no eventName");
  const time = dateOf(r.eventTime);
  if (!time) throw new MappingError("CloudTrail record has no readable eventTime");
  const identity = (r.userIdentity ?? {}) as Raw;
  const arn = str(identity.arn);
  const userName = str(identity.userName, get(identity, "sessionContext.sessionIssuer.userName"), arn?.split("/").pop(), identity.principalId, identity.invokedBy);
  const error = str(r.errorCode);
  const common = {
    time,
    product: "AWS CloudTrail",
    vendor: "Amazon Web Services",
    uid: str(r.eventID),
    log_name: str(r.eventCategory) ?? "Management",
    activity_name: name,
    cloud: { provider: "AWS", region: str(r.awsRegion), account: { uid: str(r.recipientAccountId, identity.accountId) } },
    src_endpoint: { ip: str(r.sourceIPAddress)?.match(/^[\d.:a-f]+$/i) ? str(r.sourceIPAddress) : undefined, hostname: str(r.sourceIPAddress)?.match(/^[\d.:a-f]+$/i) ? undefined : str(r.sourceIPAddress) },
    status_id: error ? STATUS.FAILURE : STATUS.SUCCESS,
    status: error,
    status_detail: str(r.errorMessage),
    unmapped: { eventSource: r.eventSource, eventType: r.eventType, userAgent: r.userAgent, identityType: identity.type, accessKeyId: identity.accessKeyId, readOnly: r.readOnly, requestParameters: r.requestParameters },
  };
  if (name === "ConsoleLogin" || r.eventType === "AwsConsoleSignIn") {
    const outcome = str(get(r, "responseElements.ConsoleLogin"));
    return ocsfEvent(CLASS.AUTHENTICATION, ACTIVITY.auth.LOGON, {
      ...common,
      status_id: outcome === "Failure" || error ? STATUS.FAILURE : STATUS.SUCCESS,
      status_detail: str(r.errorMessage),
      severity_id: outcome === "Failure" ? SEVERITY.LOW : SEVERITY.INFORMATIONAL,
      user: { name: userName ?? "unknown", uid: arn, type: str(identity.type) },
      service: { name: "AWS Management Console" },
      is_mfa: str(get(r, "additionalEventData.MFAUsed")) === "Yes" ? true : str(get(r, "additionalEventData.MFAUsed")) === "No" ? false : undefined,
    });
  }
  const params = (r.requestParameters ?? {}) as Raw;
  const resource = str(params.bucketName, params.userName, params.roleName, params.instanceId, params.functionName, params.name, get(r, "resources.0.ARN"));
  return ocsfEvent(CLASS.API, verb(name), {
    ...common,
    severity_id: /AccessDenied|UnauthorizedOperation/.test(error ?? "") ? SEVERITY.LOW : SEVERITY.INFORMATIONAL,
    actor: { user: { name: userName ?? "unknown", uid: arn, type: str(identity.type) } },
    api: { operation: name, service: { name: str(r.eventSource) } },
    resources: resource ? [{ name: resource }] : asArray(r.resources).map((x) => ({ name: str(x.ARN), type: str(x.type) })),
  });
}

// ---------------------------------------------------------------- Google Cloud audit logs

export function gcpAudit(entry: Raw): OcsfEvent {
  const p = (entry.protoPayload ?? {}) as Raw;
  const method = str(p.methodName);
  if (!method) throw new MappingError("Cloud audit log entry has no protoPayload.methodName");
  const time = dateOf(entry.timestamp, entry.receiveTimestamp);
  if (!time) throw new MappingError("Cloud audit log entry has no readable timestamp");
  const code = num(get(p, "status.code")) ?? 0;
  const user = str(get(p, "authenticationInfo.principalEmail"), get(p, "authenticationInfo.principalSubject"));
  return ocsfEvent(CLASS.API, verb(method), {
    time,
    product: "Google Cloud Audit Logs",
    vendor: "Google",
    uid: str(entry.insertId),
    log_name: str(entry.logName)?.split("/").pop(),
    activity_name: method,
    severity_id: code === 7 ? SEVERITY.LOW : SEVERITY.INFORMATIONAL,
    status_id: code ? STATUS.FAILURE : STATUS.SUCCESS,
    // google.rpc.Code 7 is PERMISSION_DENIED.
    status: code === 7 ? "Permission denied" : code ? `code ${code}` : undefined,
    status_detail: str(get(p, "status.message")),
    actor: { user: { name: user ?? "unknown" } },
    api: { operation: method, service: { name: str(p.serviceName) } },
    src_endpoint: { ip: str(get(p, "requestMetadata.callerIp"))?.match(/^[\d.:a-f]+$/i) ? str(get(p, "requestMetadata.callerIp")) : undefined },
    cloud: { provider: "GCP", account: { uid: str(get(entry, "resource.labels.project_id")) } },
    resources: str(p.resourceName) ? [{ name: str(p.resourceName), type: str(get(entry, "resource.type")) }] : undefined,
    unmapped: { userAgent: get(p, "requestMetadata.callerSuppliedUserAgent"), severity: entry.severity, granted: asArray(p.authorizationInfo).map((a) => a.granted) },
  });
}

// ---------------------------------------------------------------- Azure Activity Log

// Diagnostic-setting exports carry the caller in identity.claims, keyed by claim URI.
function claim(r: Raw, name: string) {
  const claims = get(r, "identity.claims");
  if (!claims || typeof claims !== "object") return undefined;
  const c = claims as Raw;
  return c[`http://schemas.xmlsoap.org/ws/2005/05/identity/claims/${name}`] ?? c[name];
}

const AZURE_LEVEL: Record<string, number> = { critical: SEVERITY.CRITICAL, error: SEVERITY.HIGH, warning: SEVERITY.MEDIUM, informational: SEVERITY.INFORMATIONAL, verbose: SEVERITY.INFORMATIONAL };

export function azureActivity(r: Raw): OcsfEvent {
  const operation = str(get(r, "operationName.value"), r.operationName);
  if (!operation) throw new MappingError("Azure Activity event has no operationName");
  const time = dateOf(r.eventTimestamp, r.time);
  if (!time) throw new MappingError("Azure Activity event has no readable eventTimestamp");
  const status = str(get(r, "status.value"), r.status, r.resultType);
  const failed = /fail/i.test(status ?? "");
  return ocsfEvent(CLASS.API, verb(operation), {
    time,
    product: "Azure Activity Log",
    vendor: "Microsoft",
    uid: str(r.eventDataId, r.id),
    log_name: str(get(r, "category.value"), r.category) ?? "Administrative",
    activity_name: str(get(r, "operationName.localizedValue")) ?? operation,
    severity_id: AZURE_LEVEL[String(r.level ?? "").toLowerCase()] ?? SEVERITY.INFORMATIONAL,
    status_id: failed ? STATUS.FAILURE : /succeed|accepted|started/i.test(status ?? "") ? STATUS.SUCCESS : STATUS.UNKNOWN,
    status: status,
    status_detail: str(get(r, "subStatus.localizedValue"), get(r, "properties.statusMessage")),
    actor: { user: { name: str(r.caller, claim(r, "upn"), claim(r, "name")) ?? "unknown" } },
    api: { operation, service: { name: str(get(r, "resourceProviderName.value"), r.resourceProviderName, operation.split("/")[0]) } },
    src_endpoint: { ip: str(get(r, "httpRequest.clientIpAddress"), r.callerIpAddress, get(r, "claims.ipaddr")) },
    cloud: { provider: "Azure", account: { uid: str(r.subscriptionId) } },
    resources: str(r.resourceId) ? [{ name: str(r.resourceId), type: str(get(r, "resourceType.value")) }] : undefined,
    unmapped: { correlationId: r.correlationId, resourceGroupName: r.resourceGroupName, method: get(r, "httpRequest.method") },
  });
}
