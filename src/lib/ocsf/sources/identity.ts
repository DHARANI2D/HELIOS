import { ACTIVITY, CLASS, SEVERITY, STATUS, ocsfEvent, type OcsfEvent } from "@/lib/ocsf/schema";
import { MappingError, asArray, dateOf, get, num, str, type Raw } from "@/lib/ocsf/sources/util";

// Identity logs to OCSF: Microsoft Entra ID sign-ins and directory audits
// (Microsoft Graph v1.0 signIn and directoryAudit resources), the Okta System
// Log (LogEvent), and Google Workspace login activity (Admin SDK Reports API).

const need = (d: Date | null, what: string) => {
  if (!d) throw new MappingError(`${what} has no readable timestamp`);
  return d;
};

const RISK_SEVERITY: Record<string, number> = { high: SEVERITY.HIGH, medium: SEVERITY.MEDIUM, low: SEVERITY.LOW };

// ---------------------------------------------------------------- Entra ID

export function entraSignIn(r: Raw): OcsfEvent {
  const code = num(get(r, "status.errorCode")) ?? 0;
  const failed = code !== 0;
  const risk = RISK_SEVERITY[String(r.riskLevelDuringSignIn ?? r.riskLevelAggregated ?? "").toLowerCase()];
  return ocsfEvent(CLASS.AUTHENTICATION, ACTIVITY.auth.LOGON, {
    time: need(dateOf(r.createdDateTime), "Entra sign-in"),
    product: "Microsoft Entra ID",
    vendor: "Microsoft",
    uid: str(r.id),
    log_name: "signIns",
    severity_id: risk ?? (failed ? SEVERITY.LOW : SEVERITY.INFORMATIONAL),
    status_id: failed ? STATUS.FAILURE : STATUS.SUCCESS,
    status_detail: failed ? str(get(r, "status.failureReason"), `error ${code}`) : undefined,
    user: { name: str(r.userPrincipalName), uid: str(r.userId) },
    service: { name: str(r.resourceDisplayName, r.appDisplayName), uid: str(r.resourceId, r.appId) },
    src_endpoint: { ip: str(r.ipAddress), location: { country: str(get(r, "location.countryOrRegion")), city: str(get(r, "location.city")) } },
    device: { hostname: str(get(r, "deviceDetail.displayName")), os: str(get(r, "deviceDetail.operatingSystem")) ? { name: str(get(r, "deviceDetail.operatingSystem"))! } : undefined },
    logon_type: r.isInteractive === false ? "Non-interactive" : r.isInteractive === true ? "Interactive" : undefined,
    auth_protocol: str(r.clientAppUsed),
    unmapped: {
      appDisplayName: r.appDisplayName,
      conditionalAccessStatus: r.conditionalAccessStatus,
      riskLevelDuringSignIn: r.riskLevelDuringSignIn,
      riskState: r.riskState,
      riskEventTypes: r.riskEventTypes_v2 ?? r.riskEventTypes,
      browser: get(r, "deviceDetail.browser"),
      correlationId: r.correlationId,
      errorCode: code || undefined,
    },
  });
}

// Directory audit activities that are account changes; everything else is API Activity.
const ENTRA_ACCOUNT: Array<[RegExp, number]> = [
  [/^add user$/i, ACTIVITY.account.CREATE],
  [/^(delete|hard delete) user$/i, ACTIVITY.account.DELETE],
  [/^disable account$/i, ACTIVITY.account.DISABLE],
  [/^enable account$/i, ACTIVITY.account.ENABLE],
  [/^reset (user )?password/i, ACTIVITY.account.PASSWORD_RESET],
  [/^change (user )?password/i, ACTIVITY.account.PASSWORD_CHANGE],
  [/^add (eligible )?member to (role|group)/i, ACTIVITY.account.ATTACH_POLICY],
  [/^remove (eligible )?member from (role|group)/i, ACTIVITY.account.DETACH_POLICY],
  [/registered security info/i, ACTIVITY.account.MFA_ENABLE],
  [/deleted security info/i, ACTIVITY.account.MFA_DISABLE],
];

export function entraAudit(r: Raw): OcsfEvent {
  const name = str(r.activityDisplayName);
  if (!name) throw new MappingError("Entra audit record has no activityDisplayName");
  const time = need(dateOf(r.activityDateTime), "Entra audit record");
  const actorUser = str(get(r, "initiatedBy.user.userPrincipalName"), get(r, "initiatedBy.user.displayName"));
  const actorApp = str(get(r, "initiatedBy.app.displayName"), get(r, "initiatedBy.app.appId"));
  const targets = asArray(r.targetResources);
  const targetUser = targets.find((t) => String(t.type).toLowerCase() === "user");
  const failed = String(r.result ?? "").toLowerCase() === "failure";
  const common = {
    time,
    product: "Microsoft Entra ID",
    vendor: "Microsoft",
    uid: str(r.id),
    log_name: "directoryAudits",
    status_id: failed ? STATUS.FAILURE : STATUS.SUCCESS,
    status_detail: str(r.resultReason),
    actor: { user: actorUser ? { name: actorUser, uid: str(get(r, "initiatedBy.user.id")) } : undefined, app_name: actorApp },
    src_endpoint: { ip: str(get(r, "initiatedBy.user.ipAddress")) },
    resources: targets.map((t) => ({ name: str(t.userPrincipalName, t.displayName), uid: str(t.id), type: str(t.type) })),
    unmapped: { category: r.category, loggedByService: r.loggedByService, operationType: r.operationType, correlationId: r.correlationId, modifiedProperties: targets.flatMap((t) => asArray(t.modifiedProperties)).slice(0, 10) },
  };
  const account = ENTRA_ACCOUNT.find(([re]) => re.test(name));
  if (account) {
    const role = account[1] === ACTIVITY.account.ATTACH_POLICY && /role/i.test(name);
    return ocsfEvent(CLASS.ACCOUNT_CHANGE, account[1], {
      ...common,
      activity_name: name,
      severity_id: role ? SEVERITY.MEDIUM : SEVERITY.INFORMATIONAL,
      user: { name: str(targetUser?.userPrincipalName, targetUser?.displayName) ?? str(targets[0]?.displayName) ?? "unknown", uid: str(targetUser?.id) },
    });
  }
  return ocsfEvent(CLASS.API, ACTIVITY.OTHER, {
    ...common,
    activity_name: name,
    actor: { ...common.actor, user: common.actor.user ?? { name: actorApp ?? "unknown" } },
    api: { operation: name, service: { name: str(r.loggedByService, r.category) } },
  });
}

// ---------------------------------------------------------------- Okta

const OKTA_ACCOUNT: Record<string, number> = {
  "user.lifecycle.create": ACTIVITY.account.CREATE,
  "user.lifecycle.activate": ACTIVITY.account.ENABLE,
  "user.lifecycle.reactivate": ACTIVITY.account.ENABLE,
  "user.lifecycle.unsuspend": ACTIVITY.account.ENABLE,
  "user.lifecycle.suspend": ACTIVITY.account.DISABLE,
  "user.lifecycle.deactivate": ACTIVITY.account.DISABLE,
  "user.lifecycle.delete.initiated": ACTIVITY.account.DELETE,
  "user.account.update_password": ACTIVITY.account.PASSWORD_CHANGE,
  "user.account.reset_password": ACTIVITY.account.PASSWORD_RESET,
  "user.account.lock": ACTIVITY.account.LOCK,
  "user.account.unlock": ACTIVITY.account.UNLOCK,
  "user.account.privilege.grant": ACTIVITY.account.ATTACH_POLICY,
  "user.account.privilege.revoke": ACTIVITY.account.DETACH_POLICY,
  "group.user_membership.add": ACTIVITY.account.ATTACH_POLICY,
  "group.user_membership.remove": ACTIVITY.account.DETACH_POLICY,
  "user.mfa.factor.activate": ACTIVITY.account.MFA_ENABLE,
  "user.mfa.factor.deactivate": ACTIVITY.account.MFA_DISABLE,
  "user.mfa.factor.reset_all": ACTIVITY.account.MFA_DISABLE,
};

const OKTA_SEVERITY: Record<string, number> = { DEBUG: SEVERITY.INFORMATIONAL, INFO: SEVERITY.INFORMATIONAL, WARN: SEVERITY.MEDIUM, ERROR: SEVERITY.HIGH };

export function oktaLog(r: Raw): OcsfEvent {
  const type = str(r.eventType);
  if (!type) throw new MappingError("Okta log event has no eventType");
  const result = String(get(r, "outcome.result") ?? "").toUpperCase();
  const failed = result === "FAILURE" || result === "DENY";
  const actor = { name: str(get(r, "actor.alternateId"), get(r, "actor.displayName")), uid: str(get(r, "actor.id")) };
  const targets = asArray(r.target);
  const targetUser = targets.find((t) => t.type === "User");
  const common = {
    time: need(dateOf(r.published), "Okta log event"),
    product: "Okta",
    vendor: "Okta",
    uid: str(r.uuid),
    log_name: "System Log",
    activity_name: type,
    severity_id: OKTA_SEVERITY[String(r.severity ?? "INFO").toUpperCase()] ?? SEVERITY.INFORMATIONAL,
    status_id: failed ? STATUS.FAILURE : result === "SUCCESS" || result === "ALLOW" ? STATUS.SUCCESS : STATUS.UNKNOWN,
    status: result || undefined,
    status_detail: str(get(r, "outcome.reason")),
    message: str(r.displayMessage),
    src_endpoint: { ip: str(get(r, "client.ipAddress")), location: { country: str(get(r, "client.geographicalContext.country")), city: str(get(r, "client.geographicalContext.city")) } },
    unmapped: { legacyEventType: r.legacyEventType, userAgent: get(r, "client.userAgent.rawUserAgent"), zone: get(r, "client.zone"), credentialType: get(r, "authenticationContext.credentialType"), transaction: get(r, "transaction.id") },
  };
  if (type === "user.session.start" || type.startsWith("user.authentication.")) {
    return ocsfEvent(CLASS.AUTHENTICATION, ACTIVITY.auth.LOGON, {
      ...common,
      user: actor,
      service: type === "user.authentication.sso" ? { name: str(targets.find((t) => t.type === "AppInstance")?.displayName) } : { name: "Okta" },
      is_mfa: type === "user.authentication.auth_via_mfa" ? true : undefined,
      auth_protocol: str(get(r, "authenticationContext.credentialType"), get(r, "authenticationContext.authenticationProvider")),
    });
  }
  if (type === "user.session.end") return ocsfEvent(CLASS.AUTHENTICATION, ACTIVITY.auth.LOGOFF, { ...common, user: actor, service: { name: "Okta" } });
  if (OKTA_ACCOUNT[type] !== undefined) {
    return ocsfEvent(CLASS.ACCOUNT_CHANGE, OKTA_ACCOUNT[type], {
      ...common,
      user: { name: str(targetUser?.alternateId, targetUser?.displayName) ?? actor.name ?? "unknown", uid: str(targetUser?.id) },
      actor: { user: actor },
    });
  }
  return ocsfEvent(CLASS.API, ACTIVITY.OTHER, { ...common, actor: { user: actor.name ? actor : { name: "unknown" } }, api: { operation: type, service: { name: "Okta" } }, resources: targets.map((t) => ({ name: str(t.alternateId, t.displayName), uid: str(t.id), type: str(t.type) })) });
}

// ---------------------------------------------------------------- Google Workspace

const GOOGLE_HIGH = new Set(["gov_attack_warning", "suspicious_login", "suspicious_login_less_secure_app", "suspicious_programmatic_login"]);

function param(event: Raw, name: string) {
  const p = asArray(event.parameters).find((x) => x.name === name);
  return p ? (p.value ?? p.boolValue ?? p.multiValue ?? p.intValue) : undefined;
}

// One activity can carry several events (a challenge, then the success).
export function googleLogin(r: Raw): OcsfEvent[] {
  const time = need(dateOf(get(r, "id.time")), "Google Workspace activity");
  const user = { name: str(get(r, "actor.email")), uid: str(get(r, "actor.profileId")) };
  const events = asArray(r.events);
  if (!events.length) throw new MappingError("Google Workspace activity has no events");
  return events.map((e, i) => {
    const name = str(e.name) ?? "unknown";
    const challenge = param(e, "login_challenge_method");
    const common = {
      time,
      product: "Google Workspace",
      vendor: "Google",
      uid: `${str(get(r, "id.uniqueQualifier")) ?? time.getTime()}:${i}`,
      log_name: str(get(r, "id.applicationName")) ?? "login",
      activity_name: name,
      user,
      service: { name: "Google Workspace" },
      src_endpoint: { ip: str(r.ipAddress) },
      severity_id: GOOGLE_HIGH.has(name) ? SEVERITY.HIGH : name === "login_failure" ? SEVERITY.LOW : SEVERITY.INFORMATIONAL,
      is_mfa: Array.isArray(challenge) ? challenge.length > 0 : undefined,
      auth_protocol: str(param(e, "login_type")),
      unmapped: { isSuspicious: param(e, "is_suspicious"), challenge, customerId: get(r, "id.customerId") },
    };
    if (name === "logout") return ocsfEvent(CLASS.AUTHENTICATION, ACTIVITY.auth.LOGOFF, { ...common, status_id: STATUS.SUCCESS });
    if (name.startsWith("login_") || GOOGLE_HIGH.has(name)) {
      // A suspicious or challenged login may still have succeeded: its own success event says so.
      return ocsfEvent(CLASS.AUTHENTICATION, ACTIVITY.auth.LOGON, { ...common, status_id: name === "login_success" || name === "login_verification" ? STATUS.SUCCESS : name === "login_failure" ? STATUS.FAILURE : STATUS.OTHER });
    }
    if (/account_disabled/.test(name)) return ocsfEvent(CLASS.ACCOUNT_CHANGE, ACTIVITY.account.DISABLE, common);
    return ocsfEvent(CLASS.API, ACTIVITY.OTHER, { ...common, actor: { user }, api: { operation: name, service: { name: "Google Workspace" } } });
  });
}
