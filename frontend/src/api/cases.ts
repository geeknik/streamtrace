import { api } from "./client";
import type { Case, CaseDetail, EvidenceBundle, BundleVerification } from "./types";

export async function listCases(): Promise<Case[]> {
  return api.get<Case[]>("/cases");
}

export async function getCase(id: string): Promise<CaseDetail> {
  return api.get<CaseDetail>(`/cases/${encodeURIComponent(id)}`);
}

export async function createCase(data: {
  name: string;
  description: string;
}): Promise<Case> {
  return api.post<Case>("/cases", data);
}

export async function updateCase(
  id: string,
  data: Partial<{ name: string; description: string; status: string }>,
): Promise<Case> {
  return api.patch<Case>(`/cases/${encodeURIComponent(id)}`, data);
}

export async function deleteCase(id: string): Promise<void> {
  return api.del(`/cases/${encodeURIComponent(id)}`);
}

export async function addEventToCase(
  caseId: string,
  eventId: string,
  annotation: string,
): Promise<void> {
  return api.post(`/cases/${encodeURIComponent(caseId)}/events`, {
    event_id: eventId,
    annotation,
  });
}

export async function exportCase(
  caseId: string,
  format: "json" | "csv" | "markdown",
): Promise<string> {
  return api.get<string>(
    `/cases/${encodeURIComponent(caseId)}/export`,
    { format },
  );
}

export async function createBundle(caseId: string): Promise<EvidenceBundle> {
  return api.post<EvidenceBundle>(
    `/cases/${encodeURIComponent(caseId)}/bundle`,
    {},
  );
}

export async function verifyBundle(
  bundle: unknown,
): Promise<BundleVerification> {
  return api.post<BundleVerification>("/bundles/verify", bundle);
}
