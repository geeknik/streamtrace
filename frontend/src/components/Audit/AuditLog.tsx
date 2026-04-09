import type { Component } from "solid-js";
import { createSignal, createResource, Show, For } from "solid-js";
import type { AuditEntry } from "../../api/types";
import { fetchAuditLog } from "../../api/audit";

const PAGE_SIZE = 50;

const AuditLog: Component = () => {
  const [actionFilter, setActionFilter] = createSignal<string>("");
  const [offset, setOffset] = createSignal(0);
  const [expandedId, setExpandedId] = createSignal<number | null>(null);

  const [entries, { refetch }] = createResource(
    () => ({ action: actionFilter(), offset: offset() }),
    (params) =>
      fetchAuditLog(
        params.action || undefined,
        PAGE_SIZE,
        params.offset,
      ),
  );

  function handlePrev(): void {
    const newOffset = Math.max(0, offset() - PAGE_SIZE);
    setOffset(newOffset);
    void refetch();
  }

  function handleNext(): void {
    setOffset(offset() + PAGE_SIZE);
    void refetch();
  }

  function toggleExpand(id: number): void {
    setExpandedId(expandedId() === id ? null : id);
  }

  return (
    <div>
      <div class="page-header">
        <span class="page-header__title">Audit Log</span>
      </div>

      {/* Filter */}
      <div class="filter-panel" style={{ "margin-bottom": "12px" }}>
        <div class="form-group">
          <label class="form-label">Action Filter</label>
          <input
            class="form-input"
            value={actionFilter()}
            onInput={(e) => {
              setActionFilter(e.currentTarget.value);
              setOffset(0);
              void refetch();
            }}
            placeholder="e.g. case.status_changed"
          />
        </div>
      </div>

      <Show when={entries.loading}>
        <div class="loading">Loading audit log...</div>
      </Show>

      <Show when={entries.error}>
        <div class="error-msg">Failed to load audit log.</div>
      </Show>

      <Show when={entries() && (entries() as AuditEntry[]).length === 0}>
        <div class="empty-state">No audit entries found.</div>
      </Show>

      <For each={entries()}>
        {(entry) => (
          <div
            class="card audit-entry"
            onClick={() => toggleExpand(entry.id)}
          >
            <div class="card__header">
              <span class="card__title">
                <span class="audit-action">{entry.action}</span>
              </span>
              <span class="timestamp">
                {new Date(entry.occurred_at).toLocaleString()}
              </span>
            </div>
            <div class="card__meta">
              <span>Actor: {entry.actor}</span>
              <Show when={entry.target_type}>
                <span>
                  Target: {entry.target_type}
                  {entry.target_id ? ` (${entry.target_id})` : ""}
                </span>
              </Show>
            </div>
            <Show when={expandedId() === entry.id}>
              <div class="audit-detail">
                <pre class="code-block">
                  {JSON.stringify(entry.detail, null, 2)}
                </pre>
              </div>
            </Show>
          </div>
        )}
      </For>

      {/* Pagination */}
      <Show when={entries() && (entries() as AuditEntry[]).length > 0}>
        <div
          style={{
            display: "flex",
            gap: "8px",
            "justify-content": "center",
            "margin-top": "16px",
          }}
        >
          <button
            class="btn btn--small"
            onClick={handlePrev}
            disabled={offset() === 0}
            type="button"
          >
            Previous
          </button>
          <span
            style={{
              "font-size": "0.8125rem",
              color: "var(--text-secondary)",
              "align-self": "center",
            }}
          >
            Offset: {offset()}
          </span>
          <button
            class="btn btn--small"
            onClick={handleNext}
            disabled={(entries() as AuditEntry[]).length < PAGE_SIZE}
            type="button"
          >
            Next
          </button>
        </div>
      </Show>
    </div>
  );
};

export default AuditLog;
