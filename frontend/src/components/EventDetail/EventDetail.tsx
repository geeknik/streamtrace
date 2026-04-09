import type { Component } from "solid-js";
import { Show, For, createSignal, createResource } from "solid-js";
import type { ForensicEvent, RawEventResponse } from "../../api/types";
import { fetchEvent, fetchEventRaw } from "../../api/events";

interface EventDetailProps {
  eventId: string;
  onClose: () => void;
}

function formatTimestamp(iso: string | null): string {
  if (!iso) return "--";
  try {
    return new Date(iso).toLocaleString();
  } catch {
    return iso;
  }
}

function severityLabel(severity: number): string {
  if (severity >= 5) return "critical";
  if (severity >= 4) return "high";
  if (severity >= 3) return "medium";
  if (severity >= 2) return "low";
  return "info";
}

const EventDetail: Component<EventDetailProps> = (props) => {
  const [activeTab, setActiveTab] = createSignal<"details" | "raw">("details");

  const [event] = createResource(
    () => props.eventId,
    (id) => fetchEvent(id),
  );

  const [rawEvent] = createResource(
    () => (activeTab() === "raw" ? props.eventId : null),
    (id) => (id ? fetchEventRaw(id) : undefined),
  );

  function renderDetailRow(label: string, value: string | undefined | null): ReturnType<Component> {
    if (!value) return null;
    return (
      <div class="detail-row">
        <span class="detail-row__label">{label}</span>
        <span class="detail-row__value">{value}</span>
      </div>
    );
  }

  return (
    <div class="detail-panel">
      <div class="detail-panel__header">
        <span class="detail-panel__title">
          {event()?.event_type ?? "Loading..."}
        </span>
        <button class="btn btn--small" onClick={props.onClose} type="button">
          Close
        </button>
      </div>

      <Show when={event.loading}>
        <div class="loading">Loading event details...</div>
      </Show>

      <Show when={event.error}>
        <div class="error-msg" role="alert">
          Failed to load event details.
        </div>
      </Show>

      <Show when={event()}>
        {(evt) => {
          const e = evt();
          const level = severityLabel(e.severity);
          return (
            <>
              <div class="tabs" role="tablist">
                <button
                  class={`tab${activeTab() === "details" ? " tab--active" : ""}`}
                  onClick={() => setActiveTab("details")}
                  type="button"
                  role="tab"
                  aria-selected={activeTab() === "details"}
                >
                  Details
                </button>
                <button
                  class={`tab${activeTab() === "raw" ? " tab--active" : ""}`}
                  onClick={() => setActiveTab("raw")}
                  type="button"
                  role="tab"
                  aria-selected={activeTab() === "raw"}
                >
                  Raw
                </button>
              </div>

              <Show when={activeTab() === "details"}>
                {/* Severity */}
                <div class="detail-section">
                  <span class={`badge badge--${level}`} style={{ "margin-bottom": "12px", display: "inline-block" }}>
                    Severity: {level}
                  </span>
                </div>

                {/* Timestamps */}
                <div class="detail-section">
                  <div class="detail-section__title">Timestamps</div>
                  {renderDetailRow("Occurred", formatTimestamp(e.occurred_at))}
                  {renderDetailRow("Observed", formatTimestamp(e.observed_at))}
                  {renderDetailRow("Received", formatTimestamp(e.received_at))}
                </div>

                {/* Actor */}
                <Show when={e.actor}>
                  <div class="detail-section">
                    <div class="detail-section__title">Actor</div>
                    {renderDetailRow("ID", e.actor?.id)}
                    {renderDetailRow("Name", e.actor?.name)}
                    {renderDetailRow("Type", e.actor?.actor_type)}
                  </div>
                </Show>

                {/* Subject */}
                <Show when={e.subject}>
                  <div class="detail-section">
                    <div class="detail-section__title">Subject</div>
                    {renderDetailRow("ID", e.subject?.id)}
                    {renderDetailRow("Name", e.subject?.name)}
                    {renderDetailRow("Type", e.subject?.subject_type)}
                  </div>
                </Show>

                {/* Object */}
                <Show when={e.object}>
                  <div class="detail-section">
                    <div class="detail-section__title">Object</div>
                    {renderDetailRow("ID", e.object?.id)}
                    {renderDetailRow("Name", e.object?.name)}
                    {renderDetailRow("Type", e.object?.object_type)}
                  </div>
                </Show>

                {/* Network */}
                <Show when={e.network}>
                  <div class="detail-section">
                    <div class="detail-section__title">Network</div>
                    {renderDetailRow("Src IP", e.network?.src_ip)}
                    {renderDetailRow("Dst IP", e.network?.dst_ip)}
                    {renderDetailRow("Src Port", e.network?.src_port?.toString())}
                    {renderDetailRow("Dst Port", e.network?.dst_port?.toString())}
                    {renderDetailRow("Protocol", e.network?.protocol)}
                  </div>
                </Show>

                {/* Device */}
                <Show when={e.device}>
                  <div class="detail-section">
                    <div class="detail-section__title">Device</div>
                    {renderDetailRow("ID", e.device?.device_id)}
                    {renderDetailRow("Name", e.device?.device_name)}
                    {renderDetailRow("Type", e.device?.device_type)}
                    {renderDetailRow("Hostname", e.device?.hostname)}
                  </div>
                </Show>

                {/* Source */}
                <div class="detail-section">
                  <div class="detail-section__title">Source</div>
                  {renderDetailRow("ID", e.source.source_id)}
                  {renderDetailRow("Type", e.source.source_type)}
                  {renderDetailRow("Name", e.source.source_name)}
                </div>

                {/* Tags */}
                <Show when={e.tags.length > 0}>
                  <div class="detail-section">
                    <div class="detail-section__title">Tags</div>
                    <div>
                      <For each={e.tags}>
                        {(tag) => <span class="tag">{tag}</span>}
                      </For>
                    </div>
                  </div>
                </Show>

                {/* Custom Fields */}
                <Show when={Object.keys(e.custom_fields).length > 0}>
                  <div class="detail-section">
                    <div class="detail-section__title">Custom Fields</div>
                    <pre class="code-block">
                      {JSON.stringify(e.custom_fields, null, 2)}
                    </pre>
                  </div>
                </Show>
              </Show>

              <Show when={activeTab() === "raw"}>
                <Show when={rawEvent.loading}>
                  <div class="loading">Loading raw event...</div>
                </Show>
                <Show when={rawEvent.error}>
                  <div class="error-msg" role="alert">
                    Failed to load raw event data.
                  </div>
                </Show>
                <Show when={rawEvent()}>
                  {(raw) => {
                    const r = raw() as RawEventResponse;
                    return (
                      <div>
                        <div class="detail-section">
                          <div class="detail-section__title">Hash Verification</div>
                          <div class="detail-row">
                            <span class="detail-row__label">Hash</span>
                            <span class="detail-row__value" style={{ "font-family": "var(--font-mono)", "font-size": "0.75rem" }}>
                              {r.hash}
                            </span>
                          </div>
                          <div class="detail-row">
                            <span class="detail-row__label">Status</span>
                            <span class={r.hash_verified ? "verified" : "unverified"}>
                              {r.hash_verified ? "Verified" : "Unverified"}
                            </span>
                          </div>
                        </div>
                        <div class="detail-section">
                          <div class="detail-section__title">Raw Content</div>
                          <pre class="code-block">{r.content}</pre>
                        </div>
                      </div>
                    );
                  }}
                </Show>
              </Show>
            </>
          );
        }}
      </Show>
    </div>
  );
};

export default EventDetail;
