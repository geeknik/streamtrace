import type { Component } from "solid-js";
import { createSignal, createResource, Show, For } from "solid-js";
import type { LegalHold, HoldDetail } from "../../api/types";
import {
  listHolds,
  createHold,
  getHold,
  releaseHold,
  materializeHold,
} from "../../api/holds";

function holdStatusClass(status: string): string {
  switch (status.toLowerCase()) {
    case "active":
      return "hold-badge hold-badge--active";
    case "released":
      return "hold-badge hold-badge--released";
    case "expired":
      return "hold-badge hold-badge--expired";
    default:
      return "hold-badge";
  }
}

const HoldList: Component = () => {
  const [statusFilter, setStatusFilter] = createSignal<string>("");
  const [selectedHoldId, setSelectedHoldId] = createSignal<string | null>(null);
  const [showCreate, setShowCreate] = createSignal(false);
  const [actionMsg, setActionMsg] = createSignal<string | null>(null);

  // Form state
  const [formName, setFormName] = createSignal("");
  const [formDesc, setFormDesc] = createSignal("");
  const [formType, setFormType] = createSignal("time_range");
  const [formCriteria, setFormCriteria] = createSignal("{}");
  const [formCreatedBy, setFormCreatedBy] = createSignal("");
  const [formExpiry, setFormExpiry] = createSignal("");

  const [holds, { refetch }] = createResource(
    () => statusFilter() || undefined,
    (status) => listHolds(status || undefined),
  );

  const [holdDetail] = createResource(
    () => selectedHoldId(),
    (id) => (id ? getHold(id) : Promise.resolve(null)),
  );

  async function handleCreate(): Promise<void> {
    try {
      let criteria: unknown;
      try {
        criteria = JSON.parse(formCriteria());
      } catch {
        setActionMsg("Invalid JSON in criteria field.");
        return;
      }

      await createHold({
        name: formName(),
        description: formDesc(),
        hold_type: formType(),
        criteria,
        created_by: formCreatedBy(),
        expires_at: formExpiry() || undefined,
      });

      setShowCreate(false);
      setFormName("");
      setFormDesc("");
      setFormCriteria("{}");
      setFormCreatedBy("");
      setFormExpiry("");
      setActionMsg(null);
      void refetch();
    } catch {
      setActionMsg("Failed to create hold.");
    }
  }

  async function handleRelease(id: string): Promise<void> {
    try {
      await releaseHold(id);
      setActionMsg("Hold released.");
      void refetch();
      setSelectedHoldId(null);
    } catch {
      setActionMsg("Failed to release hold.");
    }
  }

  async function handleMaterialize(id: string): Promise<void> {
    try {
      const result = await materializeHold(id);
      setActionMsg(`Materialized ${result.events_added} events.`);
      setSelectedHoldId(null);
      void refetch();
    } catch {
      setActionMsg("Failed to materialize hold events.");
    }
  }

  return (
    <div>
      <div class="page-header">
        <span class="page-header__title">Legal Holds</span>
        <button
          class="btn btn--primary btn--small"
          onClick={() => setShowCreate(true)}
          type="button"
        >
          New Hold
        </button>
      </div>

      <Show when={actionMsg()}>
        <div class="error-msg" style={{ "margin-bottom": "12px" }}>
          {actionMsg()}
        </div>
      </Show>

      {/* Status filter */}
      <div class="filter-panel" style={{ "margin-bottom": "12px" }}>
        <div class="form-group">
          <label class="form-label">Status</label>
          <select
            class="form-select"
            value={statusFilter()}
            onChange={(e) => {
              setStatusFilter(e.currentTarget.value);
              void refetch();
            }}
          >
            <option value="">All</option>
            <option value="active">Active</option>
            <option value="released">Released</option>
            <option value="expired">Expired</option>
          </select>
        </div>
      </div>

      <Show when={holds.loading}>
        <div class="loading">Loading holds...</div>
      </Show>

      <Show when={holds.error}>
        <div class="error-msg">Failed to load holds.</div>
      </Show>

      <Show when={holds() && (holds() as LegalHold[]).length === 0}>
        <div class="empty-state">No legal holds found.</div>
      </Show>

      <For each={holds()}>
        {(hold) => (
          <div
            class={`card${selectedHoldId() === hold.id ? " card--selected" : ""}`}
            onClick={() => setSelectedHoldId(hold.id)}
          >
            <div class="card__header">
              <span class="card__title">{hold.name}</span>
              <span class={holdStatusClass(hold.status)}>{hold.status}</span>
            </div>
            <div class="card__meta">
              <span>Type: {hold.hold_type}</span>
              <span>By: {hold.created_by}</span>
              <span class="timestamp">
                {new Date(hold.created_at).toLocaleString()}
              </span>
            </div>
          </div>
        )}
      </For>

      {/* Hold detail panel */}
      <Show when={selectedHoldId() && holdDetail()}>
        {(_detail) => {
          const d = holdDetail() as HoldDetail;
          if (!d) return null;
          return (
            <div class="detail-panel" style={{ "margin-top": "16px" }}>
              <div class="detail-panel__header">
                <span class="detail-panel__title">Hold Details</span>
                <button
                  class="btn btn--small"
                  onClick={() => setSelectedHoldId(null)}
                  type="button"
                >
                  Close
                </button>
              </div>
              <div class="detail-section">
                <div class="detail-row">
                  <span class="detail-row__label">Name</span>
                  <span class="detail-row__value">{d.hold.name}</span>
                </div>
                <div class="detail-row">
                  <span class="detail-row__label">Description</span>
                  <span class="detail-row__value">
                    {d.hold.description || "--"}
                  </span>
                </div>
                <div class="detail-row">
                  <span class="detail-row__label">Status</span>
                  <span class="detail-row__value">
                    <span class={holdStatusClass(d.hold.status)}>
                      {d.hold.status}
                    </span>
                  </span>
                </div>
                <div class="detail-row">
                  <span class="detail-row__label">Type</span>
                  <span class="detail-row__value">{d.hold.hold_type}</span>
                </div>
                <div class="detail-row">
                  <span class="detail-row__label">Events</span>
                  <span class="detail-row__value">{d.event_count}</span>
                </div>
                <div class="detail-row">
                  <span class="detail-row__label">Criteria</span>
                  <span class="detail-row__value">
                    <pre class="code-block">
                      {JSON.stringify(d.hold.criteria, null, 2)}
                    </pre>
                  </span>
                </div>
                <Show when={d.hold.expires_at}>
                  <div class="detail-row">
                    <span class="detail-row__label">Expires</span>
                    <span class="detail-row__value timestamp">
                      {new Date(d.hold.expires_at!).toLocaleString()}
                    </span>
                  </div>
                </Show>
              </div>
              <div style={{ display: "flex", gap: "8px", "margin-top": "12px" }}>
                <Show when={d.hold.status === "active"}>
                  <button
                    class="btn btn--danger btn--small"
                    onClick={() => void handleRelease(d.hold.id)}
                    type="button"
                  >
                    Release Hold
                  </button>
                  <button
                    class="btn btn--primary btn--small"
                    onClick={() => void handleMaterialize(d.hold.id)}
                    type="button"
                  >
                    Materialize Events
                  </button>
                </Show>
              </div>
            </div>
          );
        }}
      </Show>

      {/* Create modal */}
      <Show when={showCreate()}>
        <div class="modal-overlay" onClick={() => setShowCreate(false)}>
          <div class="modal" onClick={(e) => e.stopPropagation()}>
            <div class="modal__title">New Legal Hold</div>
            <div class="form-group" style={{ "margin-bottom": "12px" }}>
              <label class="form-label">Name</label>
              <input
                class="form-input"
                value={formName()}
                onInput={(e) => setFormName(e.currentTarget.value)}
                maxLength={200}
              />
            </div>
            <div class="form-group" style={{ "margin-bottom": "12px" }}>
              <label class="form-label">Description</label>
              <input
                class="form-input"
                value={formDesc()}
                onInput={(e) => setFormDesc(e.currentTarget.value)}
              />
            </div>
            <div class="form-group" style={{ "margin-bottom": "12px" }}>
              <label class="form-label">Hold Type</label>
              <select
                class="form-select"
                value={formType()}
                onChange={(e) => setFormType(e.currentTarget.value)}
              >
                <option value="time_range">Time Range</option>
                <option value="entity">Entity</option>
                <option value="case">Case</option>
                <option value="query">Query</option>
              </select>
            </div>
            <div class="form-group" style={{ "margin-bottom": "12px" }}>
              <label class="form-label">Criteria (JSON)</label>
              <textarea
                class="form-input"
                rows={4}
                value={formCriteria()}
                onInput={(e) => setFormCriteria(e.currentTarget.value)}
                style={{ "font-family": "var(--font-mono)", "font-size": "0.75rem" }}
              />
            </div>
            <div class="form-group" style={{ "margin-bottom": "12px" }}>
              <label class="form-label">Created By</label>
              <input
                class="form-input"
                value={formCreatedBy()}
                onInput={(e) => setFormCreatedBy(e.currentTarget.value)}
              />
            </div>
            <div class="form-group" style={{ "margin-bottom": "12px" }}>
              <label class="form-label">Expires At (optional, ISO 8601)</label>
              <input
                class="form-input"
                value={formExpiry()}
                onInput={(e) => setFormExpiry(e.currentTarget.value)}
                placeholder="2026-12-31T23:59:59Z"
              />
            </div>
            <div class="modal__actions">
              <button
                class="btn btn--small"
                onClick={() => setShowCreate(false)}
                type="button"
              >
                Cancel
              </button>
              <button
                class="btn btn--primary btn--small"
                onClick={() => void handleCreate()}
                disabled={!formName().trim() || !formCreatedBy().trim()}
                type="button"
              >
                Create
              </button>
            </div>
          </div>
        </div>
      </Show>
    </div>
  );
};

export default HoldList;
