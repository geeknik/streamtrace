import type { Component } from "solid-js";
import { Show, For, onMount } from "solid-js";
import { timelineState, setTimelineState } from "../../stores/timeline";
import { fetchTimeline } from "../../api/events";
import type { TimelineParams } from "../../api/types";
import { ApiError } from "../../api/client";
import TimelineControls from "./TimelineControls";
import TimelineEvent from "./TimelineEvent";

interface TimelineProps {
  onSelectEvent: (id: string) => void;
}

function buildParams(cursor?: string): TimelineParams {
  const f = timelineState.filters;
  return {
    start: f.start || undefined,
    end: f.end || undefined,
    event_type: f.event_type || undefined,
    actor_id: f.actor_id || undefined,
    source_id: f.source_id || undefined,
    severity_min: f.severity_min > 0 ? f.severity_min : undefined,
    search: f.search || undefined,
    cursor: cursor ?? undefined,
    limit: 50,
  };
}

async function loadTimeline(append: boolean): Promise<void> {
  setTimelineState("loading", true);
  setTimelineState("error", null);
  try {
    const cursor = append ? timelineState.cursor ?? undefined : undefined;
    const result = await fetchTimeline(buildParams(cursor));
    if (append) {
      setTimelineState("events", (prev) => [...prev, ...result.events]);
    } else {
      setTimelineState("events", result.events);
    }
    setTimelineState("cursor", result.next_cursor);
    setTimelineState("hasMore", result.has_more);
  } catch (err) {
    if (err instanceof ApiError) {
      if (err.status === 401) {
        setTimelineState("error", "Authentication required. Enter your Bearer token in the top-right corner and click Save.");
      } else {
        setTimelineState("error", `${err.code}: ${err.message}`);
      }
    } else {
      setTimelineState("error", "Failed to load timeline");
    }
  } finally {
    setTimelineState("loading", false);
  }
}

const Timeline: Component<TimelineProps> = (props) => {
  onMount(() => {
    // Auto-load on mount if we have a default date range.
    if (timelineState.filters.start && timelineState.filters.end) {
      void loadTimeline(false);
    }
  });

  function handleApply(): void {
    void loadTimeline(false);
  }

  function handleLoadMore(): void {
    void loadTimeline(true);
  }

  return (
    <div>
      <TimelineControls onApply={handleApply} />

      <Show when={timelineState.error}>
        <div class="error-msg" role="alert">
          {timelineState.error}
        </div>
      </Show>

      <Show when={timelineState.loading && timelineState.events.length === 0}>
        <div class="loading" aria-live="polite">
          Loading events...
        </div>
      </Show>

      <Show
        when={
          !timelineState.loading && timelineState.events.length === 0
        }
      >
        <div class="empty-state">
          No events found. Adjust your filters and click Apply.
        </div>
      </Show>

      <div class="split-view__list">
        <For each={timelineState.events}>
          {(event) => (
            <TimelineEvent
              event={event}
              selected={timelineState.selectedEventId === event.id}
              onSelect={props.onSelectEvent}
            />
          )}
        </For>
      </div>

      <Show when={timelineState.hasMore && !timelineState.loading}>
        <div style={{ "text-align": "center", "margin-top": "12px" }}>
          <button class="btn" onClick={handleLoadMore} type="button">
            Load more
          </button>
        </div>
      </Show>

      <Show when={timelineState.loading && timelineState.events.length > 0}>
        <div class="loading" aria-live="polite">
          Loading more...
        </div>
      </Show>
    </div>
  );
};

export default Timeline;
