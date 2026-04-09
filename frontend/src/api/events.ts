import { api } from "./client";
import type {
  ForensicEvent,
  RawEventResponse,
  SearchResult,
  TimelineParams,
  TimelineResponse,
} from "./types";

/** Ensure datetime-local values ("YYYY-MM-DDTHH:mm") become full ISO 8601. */
function toIso(dt: string): string {
  if (!dt) return dt;
  // datetime-local gives "YYYY-MM-DDTHH:mm", API needs "YYYY-MM-DDTHH:mm:ssZ"
  if (dt.length === 16) return dt + ":00Z";
  if (!dt.endsWith("Z") && !dt.includes("+")) return dt + "Z";
  return dt;
}

function toStringRecord(params: TimelineParams): Record<string, string> {
  const out: Record<string, string> = {};
  if (params.start) out["start"] = toIso(params.start);
  if (params.end) out["end"] = toIso(params.end);
  if (params.event_type) out["event_type"] = params.event_type;
  if (params.actor_id) out["actor_id"] = params.actor_id;
  if (params.source_id) out["source_id"] = params.source_id;
  if (params.severity_min !== undefined)
    out["severity_min"] = String(params.severity_min);
  if (params.search) out["search"] = params.search;
  if (params.cursor) out["cursor"] = params.cursor;
  if (params.limit !== undefined) out["limit"] = String(params.limit);
  return out;
}

export async function fetchTimeline(
  params: TimelineParams,
): Promise<TimelineResponse> {
  return api.get<TimelineResponse>("/timeline", toStringRecord(params));
}

export async function fetchEvent(id: string): Promise<ForensicEvent> {
  return api.get<ForensicEvent>(`/events/${encodeURIComponent(id)}`);
}

export async function fetchEventRaw(id: string): Promise<RawEventResponse> {
  return api.get<RawEventResponse>(
    `/events/${encodeURIComponent(id)}/raw`,
  );
}

export async function fetchCorrelatedEvents(
  id: string,
  limit?: number,
): Promise<ForensicEvent[]> {
  const params: Record<string, string> = {};
  if (limit !== undefined) params["limit"] = String(limit);
  return api.get<ForensicEvent[]>(
    `/events/${encodeURIComponent(id)}/correlated`,
    params,
  );
}

export async function searchEvents(
  query: string,
  limit?: number,
  offset?: number,
): Promise<SearchResult> {
  const params: Record<string, string> = { q: query };
  if (limit !== undefined) params["limit"] = String(limit);
  if (offset !== undefined) params["offset"] = String(offset);
  return api.get<SearchResult>("/events/search", params);
}
