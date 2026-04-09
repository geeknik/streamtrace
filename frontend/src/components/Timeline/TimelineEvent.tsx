import type { Component } from "solid-js";
import { Show } from "solid-js";
import type { ForensicEvent } from "../../api/types";

interface TimelineEventProps {
  event: ForensicEvent;
  selected: boolean;
  onSelect: (id: string) => void;
}

function severityLabel(severity: number): string {
  if (severity >= 5) return "critical";
  if (severity >= 4) return "high";
  if (severity >= 3) return "medium";
  if (severity >= 2) return "low";
  return "info";
}

function formatTimestamp(iso: string): string {
  try {
    return new Date(iso).toLocaleString();
  } catch {
    return iso;
  }
}

const TimelineEvent: Component<TimelineEventProps> = (props) => {
  const level = () => severityLabel(props.event.severity);

  return (
    <div
      class={`card${props.selected ? " card--selected" : ""}`}
      onClick={() => props.onSelect(props.event.id)}
      role="button"
      tabIndex={0}
      onKeyDown={(e) => {
        if (e.key === "Enter" || e.key === " ") {
          e.preventDefault();
          props.onSelect(props.event.id);
        }
      }}
      aria-label={`Event ${props.event.event_type}`}
    >
      <div class="card__header">
        <span class="card__title">{props.event.event_type}</span>
        <span class={`badge badge--${level()}`}>{level()}</span>
      </div>
      <div class="card__meta">
        <span class="timestamp">{formatTimestamp(props.event.occurred_at)}</span>
        <Show when={props.event.actor?.id}>
          <span>Actor: {props.event.actor!.id}</span>
        </Show>
        <span>
          Source: {props.event.source.source_name ?? props.event.source.source_id}
        </span>
      </div>
    </div>
  );
};

export default TimelineEvent;
