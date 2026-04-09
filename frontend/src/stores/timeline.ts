import { createStore } from "solid-js/store";
import type { ForensicEvent } from "../api/types";

export interface TimelineFilters {
  start: string;
  end: string;
  event_type: string;
  actor_id: string;
  source_id: string;
  severity_min: number;
  search: string;
}

export interface TimelineState {
  events: ForensicEvent[];
  loading: boolean;
  error: string | null;
  cursor: string | null;
  hasMore: boolean;
  filters: TimelineFilters;
  selectedEventId: string | null;
}

// Default to last 24 hours so the timeline shows data on first load.
function defaultStart(): string {
  const d = new Date(Date.now() - 24 * 60 * 60 * 1000);
  return d.toISOString().slice(0, 16); // "YYYY-MM-DDTHH:mm" for datetime-local
}

function defaultEnd(): string {
  const d = new Date();
  return d.toISOString().slice(0, 16);
}

const initialState: TimelineState = {
  events: [],
  loading: false,
  error: null,
  cursor: null,
  hasMore: false,
  filters: {
    start: defaultStart(),
    end: defaultEnd(),
    event_type: "",
    actor_id: "",
    source_id: "",
    severity_min: 0,
    search: "",
  },
  selectedEventId: null,
};

export const [timelineState, setTimelineState] =
  createStore<TimelineState>(initialState);
