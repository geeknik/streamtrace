import { api } from "./client";
import type { AuditEntry } from "./types";

export async function fetchAuditLog(
  action?: string,
  limit?: number,
  offset?: number,
): Promise<AuditEntry[]> {
  const params: Record<string, string> = {};
  if (action) {
    params.action = action;
  }
  if (limit !== undefined) {
    params.limit = String(limit);
  }
  if (offset !== undefined) {
    params.offset = String(offset);
  }
  return api.get<AuditEntry[]>("/audit", params);
}
