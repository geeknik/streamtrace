import { api } from "./client";
import type { LegalHold, HoldDetail } from "./types";

export interface CreateHoldRequest {
  name: string;
  description: string;
  hold_type: string;
  criteria: unknown;
  created_by: string;
  expires_at?: string;
}

export async function createHold(data: CreateHoldRequest): Promise<LegalHold> {
  return api.post<LegalHold>("/holds", data);
}

export async function listHolds(status?: string): Promise<LegalHold[]> {
  const params: Record<string, string> = {};
  if (status) {
    params.status = status;
  }
  return api.get<LegalHold[]>("/holds", params);
}

export async function getHold(id: string): Promise<HoldDetail> {
  return api.get<HoldDetail>(`/holds/${encodeURIComponent(id)}`);
}

export async function releaseHold(id: string): Promise<LegalHold> {
  return api.post<LegalHold>(
    `/holds/${encodeURIComponent(id)}/release`,
    {},
  );
}

export async function materializeHold(
  id: string,
): Promise<{ events_added: number }> {
  return api.post<{ events_added: number }>(
    `/holds/${encodeURIComponent(id)}/materialize`,
    {},
  );
}
