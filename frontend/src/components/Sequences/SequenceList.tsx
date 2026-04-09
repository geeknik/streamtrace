import type { Component } from "solid-js";
import { createSignal, Show, For, onMount } from "solid-js";
import { listDetectedSequences, scanSequences } from "../../api/sequences";
import { ApiError } from "../../api/client";
import type { DetectedSequence, ScanResponse } from "../../api/types";

function formatTimestamp(iso: string): string {
  try {
    return new Date(iso).toLocaleString();
  } catch {
    return iso;
  }
}

function confidenceBadgeClass(confidence: number): string {
  if (confidence >= 0.9) return "badge badge--critical";
  if (confidence >= 0.7) return "badge badge--high";
  if (confidence >= 0.5) return "badge badge--medium";
  return "badge badge--low";
}

const SequenceList: Component = () => {
  const [sequences, setSequences] = createSignal<DetectedSequence[]>([]);
  const [loading, setLoading] = createSignal(false);
  const [error, setError] = createSignal<string | null>(null);
  const [expandedId, setExpandedId] = createSignal<string | null>(null);

  // Scan controls
  const [scanStart, setScanStart] = createSignal("");
  const [scanEnd, setScanEnd] = createSignal("");
  const [scanning, setScanning] = createSignal(false);
  const [scanResult, setScanResult] = createSignal<ScanResponse | null>(null);

  async function loadSequences(): Promise<void> {
    setLoading(true);
    setError(null);
    try {
      const results = await listDetectedSequences(100, 0);
      setSequences(results);
    } catch (err) {
      if (err instanceof ApiError) {
        setError(`${err.code}: ${err.message}`);
      } else {
        setError("Failed to load sequences");
      }
    } finally {
      setLoading(false);
    }
  }

  async function handleScan(): Promise<void> {
    const start = scanStart().trim();
    const end = scanEnd().trim();
    if (!start || !end) return;
    setScanning(true);
    setError(null);
    setScanResult(null);
    try {
      const result = await scanSequences(start, end);
      setScanResult(result);
      // Reload list after scan
      await loadSequences();
    } catch (err) {
      if (err instanceof ApiError) {
        setError(`${err.code}: ${err.message}`);
      } else {
        setError("Scan failed");
      }
    } finally {
      setScanning(false);
    }
  }

  function toggleExpanded(id: string): void {
    setExpandedId((prev) => (prev === id ? null : id));
  }

  onMount(() => {
    void loadSequences();
  });

  return (
    <div>
      <div class="page-header">
        <h2 class="page-header__title">Sequences</h2>
      </div>

      {/* Scan controls */}
      <div class="filter-panel">
        <div class="form-group">
          <label class="form-label" for="scan-start">
            Scan Start
          </label>
          <input
            id="scan-start"
            class="form-input"
            type="datetime-local"
            value={scanStart()}
            onInput={(e) => setScanStart((e.target as HTMLInputElement).value)}
          />
        </div>
        <div class="form-group">
          <label class="form-label" for="scan-end">
            Scan End
          </label>
          <input
            id="scan-end"
            class="form-input"
            type="datetime-local"
            value={scanEnd()}
            onInput={(e) => setScanEnd((e.target as HTMLInputElement).value)}
          />
        </div>
        <button
          class="btn btn--primary"
          type="button"
          disabled={scanning() || !scanStart() || !scanEnd()}
          onClick={() => void handleScan()}
        >
          {scanning() ? "Scanning..." : "Scan"}
        </button>
      </div>

      <Show when={scanResult()}>
        {(result) => (
          <div style={{ "margin-bottom": "12px", display: "flex", gap: "8px" }}>
            <span class="badge badge--info">
              Scanned: {result().events_scanned} events
            </span>
            <span class="badge badge--info">
              Patterns: {result().patterns_checked}
            </span>
            <span class="badge badge--open">
              Detected: {result().sequences_detected}
            </span>
          </div>
        )}
      </Show>

      <Show when={error()}>
        <div class="error-msg" role="alert">
          {error()}
        </div>
      </Show>

      <Show when={loading()}>
        <div class="loading" aria-live="polite">
          Loading sequences...
        </div>
      </Show>

      <Show when={!loading() && sequences().length === 0}>
        <div class="empty-state">No detected sequences.</div>
      </Show>

      <div>
        <For each={sequences()}>
          {(seq) => (
            <div
              class="card sequence-card"
              onClick={() => toggleExpanded(seq.id)}
              role="button"
              tabIndex={0}
              onKeyDown={(e) => {
                if (e.key === "Enter" || e.key === " ") {
                  e.preventDefault();
                  toggleExpanded(seq.id);
                }
              }}
            >
              <div class="card__header">
                <span class="card__title">{seq.pattern_name}</span>
                <span class={confidenceBadgeClass(seq.confidence)}>
                  {Math.round(seq.confidence * 100)}%
                </span>
              </div>
              <div class="card__meta">
                <Show when={seq.actor_id}>
                  <span>Actor: {seq.actor_id}</span>
                </Show>
                <span>Events: {seq.event_ids.length}</span>
                <span>
                  {formatTimestamp(seq.started_at)} -{" "}
                  {formatTimestamp(seq.ended_at)}
                </span>
              </div>

              <Show when={expandedId() === seq.id}>
                <div class="sequence-card__events">
                  <div class="detail-section__title">Event Chain</div>
                  <For each={seq.event_ids}>
                    {(eventId, idx) => (
                      <div class="detail-row">
                        <span class="detail-row__label">
                          Step {idx() + 1}
                        </span>
                        <span class="detail-row__value timestamp">
                          {eventId}
                        </span>
                      </div>
                    )}
                  </For>
                  <div class="detail-row">
                    <span class="detail-row__label">Detected</span>
                    <span class="detail-row__value timestamp">
                      {formatTimestamp(seq.detected_at)}
                    </span>
                  </div>
                </div>
              </Show>
            </div>
          )}
        </For>
      </div>
    </div>
  );
};

export default SequenceList;
