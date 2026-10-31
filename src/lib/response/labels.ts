import type { PlaybookActionType } from "@prisma/client";

// Response action names as people read them. Client-safe.
export const ACTION_LABEL: Record<PlaybookActionType, string> = {
  ISOLATE_HOST: "Isolate host",
  RELEASE_HOST: "Release host",
  BLOCK_IP: "Block IP",
  UNBLOCK_IP: "Unblock IP",
  NOTIFY_SLACK: "Notify channel",
  CREATE_TICKET: "Create ticket",
  KILL_PROCESS: "Kill process",
  COLLECT_LOGS: "Collect logs",
  REVOKE_AGENT: "Revoke AI agent",
  RESTORE_AGENT: "Restore AI agent",
  DISABLE_USER: "Disable account",
  ENABLE_USER: "Re-enable account",
  QUARANTINE_FILE: "Quarantine file",
  BLOCK_SENDER: "Block sender",
  PURGE_EMAIL: "Purge email",
  RESET_PASSWORD: "Reset password",
  COLLECT_FORENSICS: "Collect investigation package",
};

// Actions analysts and playbooks can ask for that the AI doesn't propose.
export const ANALYST_ONLY_ACTIONS = ["PURGE_EMAIL", "RESET_PASSWORD", "COLLECT_FORENSICS"] as const satisfies readonly PlaybookActionType[];
