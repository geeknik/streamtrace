import type { Component } from "solid-js";
import { timelineState, setTimelineState } from "../../stores/timeline";
import type { TimelineFilters } from "../../stores/timeline";

interface TimelineControlsProps {
  onApply: () => void;
}

const SEVERITY_OPTIONS: { value: number; label: string }[] = [
  { value: 0, label: "All" },
  { value: 1, label: "Info" },
  { value: 2, label: "Low" },
  { value: 3, label: "Medium" },
  { value: 4, label: "High" },
  { value: 5, label: "Critical" },
];

const TimelineControls: Component<TimelineControlsProps> = (props) => {
  function updateFilter<K extends keyof TimelineFilters>(
    key: K,
    value: TimelineFilters[K],
  ): void {
    setTimelineState("filters", key, value);
  }

  return (
    <div class="filter-panel" role="search" aria-label="Timeline filters">
      <div class="form-group">
        <label class="form-label" for="filter-start">
          Start
        </label>
        <input
          id="filter-start"
          type="datetime-local"
          class="form-input"
          value={timelineState.filters.start}
          onInput={(e) => updateFilter("start", e.currentTarget.value)}
        />
      </div>
      <div class="form-group">
        <label class="form-label" for="filter-end">
          End
        </label>
        <input
          id="filter-end"
          type="datetime-local"
          class="form-input"
          value={timelineState.filters.end}
          onInput={(e) => updateFilter("end", e.currentTarget.value)}
        />
      </div>
      <div class="form-group">
        <label class="form-label" for="filter-event-type">
          Event Type
        </label>
        <input
          id="filter-event-type"
          type="text"
          class="form-input"
          placeholder="e.g. login"
          value={timelineState.filters.event_type}
          onInput={(e) => updateFilter("event_type", e.currentTarget.value)}
        />
      </div>
      <div class="form-group">
        <label class="form-label" for="filter-actor">
          Actor ID
        </label>
        <input
          id="filter-actor"
          type="text"
          class="form-input"
          placeholder="Actor ID"
          value={timelineState.filters.actor_id}
          onInput={(e) => updateFilter("actor_id", e.currentTarget.value)}
        />
      </div>
      <div class="form-group">
        <label class="form-label" for="filter-source">
          Source ID
        </label>
        <input
          id="filter-source"
          type="text"
          class="form-input"
          placeholder="Source ID"
          value={timelineState.filters.source_id}
          onInput={(e) => updateFilter("source_id", e.currentTarget.value)}
        />
      </div>
      <div class="form-group">
        <label class="form-label" for="filter-severity">
          Min Severity
        </label>
        <select
          id="filter-severity"
          class="form-select"
          value={timelineState.filters.severity_min}
          onChange={(e) =>
            updateFilter("severity_min", Number(e.currentTarget.value))
          }
        >
          {SEVERITY_OPTIONS.map((opt) => (
            <option value={opt.value}>{opt.label}</option>
          ))}
        </select>
      </div>
      <div class="form-group">
        <label class="form-label" for="filter-search">
          Search
        </label>
        <input
          id="filter-search"
          type="text"
          class="form-input"
          placeholder="Free text search"
          value={timelineState.filters.search}
          onInput={(e) => updateFilter("search", e.currentTarget.value)}
        />
      </div>
      <button class="btn btn--primary" onClick={() => props.onApply()} type="button">
        Apply
      </button>
    </div>
  );
};

export default TimelineControls;
