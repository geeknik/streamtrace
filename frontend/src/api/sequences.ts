import { api } from "./client";
import type {
  DetectedSequence,
  ScanResponse,
  SequencePatternEntry,
} from "./types";

export async function listPatterns(): Promise<SequencePatternEntry[]> {
  return api.get<SequencePatternEntry[]>("/sequences/patterns");
}

export async function listDetectedSequences(
  limit?: number,
  offset?: number,
): Promise<DetectedSequence[]> {
  const params: Record<string, string> = {};
  if (limit !== undefined) params["limit"] = String(limit);
  if (offset !== undefined) params["offset"] = String(offset);
  return api.get<DetectedSequence[]>("/sequences/detected", params);
}

/**
 * Trigger a sequence scan. The backend reads start/end as query params
 * on a POST endpoint (no JSON body needed).
 */
export async function scanSequences(
  start: string,
  end: string,
): Promise<ScanResponse> {
  const qs = new URLSearchParams({ start, end }).toString();
  return api.post<ScanResponse>(`/sequences/scan?${qs}`, {});
}
