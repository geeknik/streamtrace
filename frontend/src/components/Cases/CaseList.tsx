import type { Component } from "solid-js";
import { Show, For, createSignal, onMount } from "solid-js";
import { casesState, setCasesState } from "../../stores/cases";
import { listCases, createCase } from "../../api/cases";
import { ApiError } from "../../api/client";

interface CaseListProps {
  onSelectCase: (id: string) => void;
  selectedCaseId: string | null;
}

const CaseList: Component<CaseListProps> = (props) => {
  const [showModal, setShowModal] = createSignal(false);
  const [newName, setNewName] = createSignal("");
  const [newDesc, setNewDesc] = createSignal("");
  const [creating, setCreating] = createSignal(false);

  async function loadCases(): Promise<void> {
    setCasesState("loading", true);
    setCasesState("error", null);
    try {
      const cases = await listCases();
      setCasesState("cases", cases);
    } catch (err) {
      if (err instanceof ApiError) {
        setCasesState("error", `${err.code}: ${err.message}`);
      } else {
        setCasesState("error", "Failed to load cases");
      }
    } finally {
      setCasesState("loading", false);
    }
  }

  onMount(() => {
    void loadCases();
  });

  async function handleCreate(): Promise<void> {
    const name = newName().trim();
    if (!name) return;
    setCreating(true);
    try {
      await createCase({ name, description: newDesc().trim() });
      setShowModal(false);
      setNewName("");
      setNewDesc("");
      void loadCases();
    } catch {
      // creation error handled silently for MVP
    } finally {
      setCreating(false);
    }
  }

  function statusBadgeClass(status: string): string {
    const lower = status.toLowerCase();
    if (lower === "open" || lower === "active") return "badge--open";
    return "badge--closed";
  }

  return (
    <div>
      <div class="page-header">
        <h2 class="page-header__title">Cases</h2>
        <button class="btn btn--primary" onClick={() => setShowModal(true)} type="button">
          New Case
        </button>
      </div>

      <Show when={casesState.error}>
        <div class="error-msg" role="alert">
          {casesState.error}
        </div>
      </Show>

      <Show when={casesState.loading}>
        <div class="loading">Loading cases...</div>
      </Show>

      <Show when={!casesState.loading && casesState.cases.length === 0 && !casesState.error}>
        <div class="empty-state">No cases yet. Create one to get started.</div>
      </Show>

      <For each={casesState.cases}>
        {(c) => (
          <div
            class={`card${props.selectedCaseId === c.id ? " card--selected" : ""}`}
            onClick={() => props.onSelectCase(c.id)}
            role="button"
            tabIndex={0}
            onKeyDown={(e) => {
              if (e.key === "Enter" || e.key === " ") {
                e.preventDefault();
                props.onSelectCase(c.id);
              }
            }}
          >
            <div class="card__header">
              <span class="card__title">{c.name}</span>
              <span class={`badge ${statusBadgeClass(c.status)}`}>
                {c.status}
              </span>
            </div>
            <div class="card__meta">
              <span>{c.description || "No description"}</span>
              <span class="timestamp">
                Created: {new Date(c.created_at).toLocaleDateString()}
              </span>
            </div>
          </div>
        )}
      </For>

      {/* Create Case Modal */}
      <Show when={showModal()}>
        <div
          class="modal-overlay"
          onClick={(e) => {
            if (e.target === e.currentTarget) setShowModal(false);
          }}
        >
          <div class="modal" role="dialog" aria-label="Create new case">
            <div class="modal__title">New Case</div>
            <div class="form-group" style={{ "margin-bottom": "12px" }}>
              <label class="form-label" for="new-case-name">
                Name
              </label>
              <input
                id="new-case-name"
                type="text"
                class="form-input"
                value={newName()}
                onInput={(e) => setNewName(e.currentTarget.value)}
                placeholder="Case name"
              />
            </div>
            <div class="form-group">
              <label class="form-label" for="new-case-desc">
                Description
              </label>
              <textarea
                id="new-case-desc"
                class="form-input"
                rows={3}
                value={newDesc()}
                onInput={(e) => setNewDesc(e.currentTarget.value)}
                placeholder="Case description"
                style={{ resize: "vertical" }}
              />
            </div>
            <div class="modal__actions">
              <button class="btn" onClick={() => setShowModal(false)} type="button">
                Cancel
              </button>
              <button
                class="btn btn--primary"
                onClick={() => void handleCreate()}
                disabled={creating() || !newName().trim()}
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

export default CaseList;
