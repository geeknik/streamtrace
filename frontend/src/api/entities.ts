import { api } from "./client";
import type {
  CorrelationChain,
  Entity,
  EntityDetail,
  EntityGraph,
  EntitySearchBody,
  ForensicEvent,
} from "./types";

export async function fetchEntity(id: string): Promise<EntityDetail> {
  return api.get<EntityDetail>(`/entities/${encodeURIComponent(id)}`);
}

export async function fetchEntityTimeline(
  id: string,
  start: string,
  end: string,
  limit?: number,
): Promise<ForensicEvent[]> {
  const params: Record<string, string> = { start, end };
  if (limit !== undefined) params["limit"] = String(limit);
  return api.get<ForensicEvent[]>(
    `/entities/${encodeURIComponent(id)}/timeline`,
    params,
  );
}

export async function fetchEntityGraph(
  id: string,
  maxDepth?: number,
): Promise<EntityGraph> {
  const params: Record<string, string> = {};
  if (maxDepth !== undefined) params["max_depth"] = String(maxDepth);
  return api.get<EntityGraph>(
    `/entities/${encodeURIComponent(id)}/graph`,
    params,
  );
}

export async function listEntities(
  entityType?: string,
  limit?: number,
): Promise<Entity[]> {
  const params: Record<string, string> = {};
  if (entityType) params["entity_type"] = entityType;
  if (limit !== undefined) params["limit"] = String(limit);
  return api.get<Entity[]>("/entities", params);
}

export async function fetchCorrelationChain(
  seedEventId: string,
  timeWindowSecs?: number,
  maxDepth?: number,
): Promise<CorrelationChain> {
  const params: Record<string, string> = {
    seed_event_id: seedEventId,
  };
  if (timeWindowSecs !== undefined)
    params["time_window_secs"] = String(timeWindowSecs);
  if (maxDepth !== undefined) params["max_depth"] = String(maxDepth);
  return api.get<CorrelationChain>("/correlate/chain", params);
}

export async function searchEntities(
  body: EntitySearchBody,
): Promise<Entity[]> {
  return api.post<Entity[]>("/correlate/search", body);
}
