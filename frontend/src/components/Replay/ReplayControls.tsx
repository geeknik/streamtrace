import type { Component } from "solid-js";
import { createSignal, Show, For, onCleanup } from "solid-js";
import type { ForensicEvent } from "../../api/types";

const BASE_URL = import.meta.env.VITE_API_BASE_URL ?? "/v1";
const TOKEN_KEY = "streamtrace_token";
const MAX_REPLAY_EVENTS = 2000;

function getToken(): string | null {
  try {
    return localStorage.getItem(TOKEN_KEY);
  } catch {
    return null;
  }
}

function formatTimestamp(iso: string): string {
  try {
    return new Date(iso).toLocaleString();
  } catch {
    return iso;
  }
}

const ReplayControls: Component = () => {
  const [start, setStart] = createSignal("");
  const [end, setEnd] = createSignal("");
  const [speed, setSpeed] = createSignal(1);
  const [sourceId, setSourceId] = createSignal("");
  const [entityId, setEntityId] = createSignal("");
  const [playing, setPlaying] = createSignal(false);
  const [events, setEvents] = createSignal<ForensicEvent[]>([]);
  const [error, setError] = createSignal<string | null>(null);

  let eventSource: EventSource | null = null;

  function buildReplayUrl(): string {
    const params = new URLSearchParams();
    if (start()) params.set("start", start());
    if (end()) params.set("end", end());
    if (speed() !== 1) params.set("speed", String(speed()));
    if (sourceId().trim()) params.set("source_id", sourceId().trim());
    if (entityId().trim()) params.set("entity_id", entityId().trim());
    const token = getToken();
    if (token) params.set("token", token);
    const qs = params.toString();
    return `${BASE_URL}/replay${qs ? `?${qs}` : ""}`;
  }

  function startReplay(): void {
    if (!start() || !end()) {
      setError("Start and end time are required");
      return;
    }
    stopReplay();
    setError(null);
    setEvents([]);

    const url = buildReplayUrl();
    eventSource = new EventSource(url);

    eventSource.onmessage = (msg: MessageEvent) => {
      try {
        const event = JSON.parse(msg.data as string) as ForensicEvent;
        setEvents((prev) => {
          if (prev.length >= MAX_REPLAY_EVENTS) {
            return [...prev.slice(-MAX_REPLAY_EVENTS + 1), event];
          }
          return [...prev, event];
        });
      } catch {
        // Ignore malformed messages
      }
    };

    eventSource.onerror = () => {
      if (eventSource?.readyState === EventSource.CLOSED) {
        setPlaying(false);
      } else {
        setError("Connection lost. Replay stopped.");
        stopReplay();
      }
    };

    eventSource.addEventListener("done", () => {
      stopReplay();
    });

    setPlaying(true);
  }

  function stopReplay(): void {
    if (eventSource) {
      eventSource.close();
      eventSource = null;
    }
    setPlaying(false);
  }

  function handlePlayStop(): void {
    if (playing()) {
      stopReplay();
    } else {
      startReplay();
    }
  }

  function handleSpeedChange(e: Event): void {
    const target = e.target as HTMLInputElement;
    const val = parseFloat(target.value);
    if (!Number.isFinite(val) || val < 0) return;
    setSpeed(val);
    // Speed change requires reconnect
    if (playing()) {
      startReplay();
    }
  }

  onCleanup(() => {
    stopReplay();
  });

  return (
    <div>
      <div class="page-header">
        <h2 class="page-header__title">Replay</h2>
      </div>

      <div class="replay-controls">
        <div class="filter-panel">
          <div class="form-group">
            <label class="form-label" for="replay-start">
              Start
            </label>
            <input
              id="replay-start"
              class="form-input"
              type="datetime-local"
              value={start()}
              onInput={(e) => setStart((e.target as HTMLInputElement).value)}
              disabled={playing()}
            />
          </div>
          <div class="form-group">
            <label class="form-label" for="replay-end">
              End
            </label>
            <input
              id="replay-end"
              class="form-input"
              type="datetime-local"
              value={end()}
              onInput={(e) => setEnd((e.target as HTMLInputElement).value)}
              disabled={playing()}
            />
          </div>
          <div class="form-group">
            <label class="form-label" for="replay-speed">
              Speed: {speed() === 0 ? "Instant" : `${speed()}x`}
            </label>
            <input
              id="replay-speed"
              class="form-input"
              type="range"
              min="0"
              max="100"
              step="0.1"
              value={speed()}
              onInput={handleSpeedChange}
            />
          </div>
        </div>

        <div class="filter-panel">
          <div class="form-group">
            <label class="form-label" for="replay-source">
              Source ID (optional)
            </label>
            <input
              id="replay-source"
              class="form-input"
              type="text"
              placeholder="Filter by source..."
              value={sourceId()}
              onInput={(e) => setSourceId((e.target as HTMLInputElement).value)}
              disabled={playing()}
            />
          </div>
          <div class="form-group">
            <label class="form-label" for="replay-entity">
              Entity ID (optional)
            </label>
            <input
              id="replay-entity"
              class="form-input"
              type="text"
              placeholder="Filter by entity..."
              value={entityId()}
              onInput={(e) => setEntityId((e.target as HTMLInputElement).value)}
              disabled={playing()}
            />
          </div>
          <button
            class={`btn ${playing() ? "btn--danger" : "btn--primary"}`}
            type="button"
            onClick={handlePlayStop}
          >
            {playing() ? "Stop" : "Play"}
          </button>
        </div>
      </div>

      <Show when={error()}>
        <div class="error-msg" role="alert">
          {error()}
        </div>
      </Show>

      <div class="replay-status">
        <span class="badge badge--info">
          Events received: {events().length}
        </span>
        <Show when={playing()}>
          <span class="badge badge--open">Live</span>
        </Show>
      </div>

      <div class="replay-event-list" role="log" aria-live="polite">
        <For each={events()}>
          {(event) => (
            <div class="card">
              <div class="card__header">
                <span class="card__title">{event.event_type}</span>
                <span class="timestamp">
                  {formatTimestamp(event.occurred_at)}
                </span>
              </div>
              <div class="card__meta">
                <span>ID: {event.id}</span>
                <Show when={event.actor?.name}>
                  <span>Actor: {event.actor?.name}</span>
                </Show>
                <span>Source: {event.source.source_id}</span>
                <span>Severity: {event.severity}</span>
              </div>
            </div>
          )}
        </For>
      </div>
    </div>
  );
};

export default ReplayControls;
