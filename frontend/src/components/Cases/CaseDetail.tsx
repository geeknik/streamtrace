import type { Component } from "solid-js";
import { Show, For, createSignal, createResource } from "solid-js";
import type { CaseDetail as CaseDetailType, EvidenceBundle } from "../../api/types";
import { getCase, updateCase, exportCase, createBundle } from "../../api/cases";

interface CaseDetailProps {
  caseId: string;
  onClose: () => void;
}

const CaseDetail: Component<CaseDetailProps> = (props) => {
  const [addEventId, setAddEventId] = createSignal("");
  const [bundle, setBundle] = createSignal<EvidenceBundle | null>(null);
  const [bundleLoading, setBundleLoading] = createSignal(false);
  const [bundleError, setBundleError] = createSignal<string | null>(null);

  const [caseData, { refetch }] = createResource(
    () => props.caseId,
    (id) => getCase(id),
  );

  async function handleCloseCase(): Promise<void> {
    try {
      await updateCase(props.caseId, { status: "closed" });
      void refetch();
    } catch {
      // handled silently for MVP
    }
  }

  async function handleExport(format: "json" | "csv" | "markdown"): Promise<void> {
    try {
      const content = await exportCase(props.caseId, format);
      const blob = new Blob([content], { type: "text/plain" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `case-${props.caseId}.${format === "markdown" ? "md" : format}`;
      a.click();
      URL.revokeObjectURL(url);
    } catch {
      // handled silently for MVP
    }
  }

  async function handleGenerateBundle(): Promise<void> {
    setBundleLoading(true);
    setBundleError(null);
    setBundle(null);
    try {
      const result = await createBundle(props.caseId);
      setBundle(result);
    } catch {
      setBundleError("Failed to generate evidence bundle.");
    } finally {
      setBundleLoading(false);
    }
  }

  function handleDownloadBundle(): void {
    const b = bundle();
    if (!b) return;
    const json = JSON.stringify(b, null, 2);
    const blob = new Blob([json], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `evidence-bundle-${props.caseId}.json`;
    a.click();
    URL.revokeObjectURL(url);
  }

  return (
    <div class="detail-panel">
      <div class="detail-panel__header">
        <span class="detail-panel__title">Case Details</span>
        <button class="btn btn--small" onClick={props.onClose} type="button">
          Close
        </button>
      </div>

      <Show when={caseData.loading}>
        <div class="loading">Loading case...</div>
      </Show>

      <Show when={caseData.error}>
        <div class="error-msg" role="alert">
          Failed to load case details.
        </div>
      </Show>

      <Show when={caseData()}>
        {(cd) => {
          const c = cd() as CaseDetailType;
          return (
            <>
              <div class="detail-section">
                <div class="detail-section__title">Info</div>
                <div class="detail-row">
                  <span class="detail-row__label">Name</span>
                  <span class="detail-row__value">{c.name}</span>
                </div>
                <div class="detail-row">
                  <span class="detail-row__label">Status</span>
                  <span class="detail-row__value">
                    <span
                      class={`badge ${
                        c.status.toLowerCase() === "open" ||
                        c.status.toLowerCase() === "active"
                          ? "badge--open"
                          : "badge--closed"
                      }`}
                    >
                      {c.status}
                    </span>
                  </span>
                </div>
                <div class="detail-row">
                  <span class="detail-row__label">Description</span>
                  <span class="detail-row__value">
                    {c.description || "--"}
                  </span>
                </div>
                <div class="detail-row">
                  <span class="detail-row__label">Created by</span>
                  <span class="detail-row__value">{c.created_by}</span>
                </div>
                <div class="detail-row">
                  <span class="detail-row__label">Created</span>
                  <span class="detail-row__value timestamp">
                    {new Date(c.created_at).toLocaleString()}
                  </span>
                </div>
                <div class="detail-row">
                  <span class="detail-row__label">Updated</span>
                  <span class="detail-row__value timestamp">
                    {new Date(c.updated_at).toLocaleString()}
                  </span>
                </div>
              </div>

              {/* Pinned Events */}
              <div class="detail-section">
                <div class="detail-section__title">
                  Pinned Events ({c.events?.length ?? 0})
                </div>
                <Show when={!c.events || c.events.length === 0}>
                  <div
                    style={{
                      "font-size": "0.8125rem",
                      color: "var(--text-muted)",
                      padding: "8px 0",
                    }}
                  >
                    No events pinned to this case.
                  </div>
                </Show>
                <For each={c.events ?? []}>
                  {(ev) => (
                    <div class="card" style={{ cursor: "default" }}>
                      <div class="card__header">
                        <span class="card__title" style={{ "font-family": "var(--font-mono)", "font-size": "0.75rem" }}>
                          {ev.event_id}
                        </span>
                      </div>
                      <div class="card__meta">
                        <span>{ev.annotation || "No annotation"}</span>
                        <span class="timestamp">
                          Pinned: {new Date(ev.pinned_at).toLocaleString()}
                        </span>
                      </div>
                    </div>
                  )}
                </For>
              </div>

              {/* Add event input */}
              <div class="detail-section">
                <div class="detail-section__title">Add Event</div>
                <div class="search-bar">
                  <input
                    type="text"
                    class="search-bar__input"
                    placeholder="Event ID"
                    value={addEventId()}
                    onInput={(e) => setAddEventId(e.currentTarget.value)}
                    aria-label="Event ID to add"
                  />
                  <button
                    class="btn btn--primary btn--small"
                    disabled={!addEventId().trim()}
                    onClick={() => {
                      setAddEventId("");
                      void refetch();
                    }}
                    type="button"
                  >
                    Add
                  </button>
                </div>
              </div>

              {/* Evidence Bundle */}
              <div class="detail-section">
                <div class="detail-section__title">Evidence Bundle</div>
                <Show when={bundleError()}>
                  <div class="error-msg" style={{ "margin-bottom": "8px" }}>
                    {bundleError()}
                  </div>
                </Show>
                <Show when={!bundle()}>
                  <button
                    class="btn btn--primary btn--small"
                    onClick={() => void handleGenerateBundle()}
                    disabled={bundleLoading()}
                    type="button"
                  >
                    {bundleLoading()
                      ? "Generating..."
                      : "Generate Evidence Bundle"}
                  </button>
                </Show>
                <Show when={bundle()}>
                  {(_b) => {
                    const b = bundle()!;
                    return (
                      <div class="bundle-info">
                        <div class="detail-row">
                          <span class="detail-row__label">Version</span>
                          <span class="detail-row__value">
                            {b.manifest.bundle_version}
                          </span>
                        </div>
                        <div class="detail-row">
                          <span class="detail-row__label">Events</span>
                          <span class="detail-row__value">
                            {b.manifest.event_count}
                          </span>
                        </div>
                        <Show when={b.manifest.time_range}>
                          <div class="detail-row">
                            <span class="detail-row__label">Time Range</span>
                            <span class="detail-row__value timestamp">
                              {b.manifest.time_range!.start} -{" "}
                              {b.manifest.time_range!.end}
                            </span>
                          </div>
                        </Show>
                        <div class="detail-row">
                          <span class="detail-row__label">Generated</span>
                          <span class="detail-row__value timestamp">
                            {new Date(b.manifest.generated_at).toLocaleString()}
                          </span>
                        </div>
                        <div class="detail-row">
                          <span class="detail-row__label">Integrity</span>
                          <span class="detail-row__value">
                            {b.integrity.length} files hashed
                          </span>
                        </div>
                        <div class="detail-row">
                          <span class="detail-row__label">Chain Root</span>
                          <span
                            class="detail-row__value"
                            style={{ "font-family": "var(--font-mono)", "font-size": "0.7rem" }}
                          >
                            {b.chain.root_hash.substring(0, 32)}...
                          </span>
                        </div>
                        <div class="detail-row">
                          <span class="detail-row__label">Signature</span>
                          <span class="detail-row__value verified">
                            {b.signature.algorithm} signed at{" "}
                            {new Date(b.signature.signed_at).toLocaleString()}
                          </span>
                        </div>
                        <div style={{ "margin-top": "8px" }}>
                          <button
                            class="btn btn--primary btn--small"
                            onClick={handleDownloadBundle}
                            type="button"
                          >
                            Download Bundle
                          </button>
                        </div>
                      </div>
                    );
                  }}
                </Show>
              </div>

              {/* Actions */}
              <div
                style={{
                  display: "flex",
                  gap: "8px",
                  "flex-wrap": "wrap",
                  "margin-top": "16px",
                }}
              >
                <button
                  class="btn btn--danger btn--small"
                  onClick={() => void handleCloseCase()}
                  type="button"
                >
                  Close Case
                </button>
                <button
                  class="btn btn--small"
                  onClick={() => void handleExport("json")}
                  type="button"
                >
                  Export JSON
                </button>
                <button
                  class="btn btn--small"
                  onClick={() => void handleExport("csv")}
                  type="button"
                >
                  Export CSV
                </button>
                <button
                  class="btn btn--small"
                  onClick={() => void handleExport("markdown")}
                  type="button"
                >
                  Export Markdown
                </button>
              </div>
            </>
          );
        }}
      </Show>
    </div>
  );
};

export default CaseDetail;
