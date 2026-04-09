import type { Component } from "solid-js";
import { createSignal, Show, For, onMount } from "solid-js";
import { entityState, setEntityState } from "../../stores/entities";
import { searchEntities } from "../../api/entities";
import { ApiError } from "../../api/client";
import type { Entity, EntitySearchBody } from "../../api/types";

interface EntityListProps {
  onSelectEntity: (id: string) => void;
  selectedEntityId: string | null;
}

const ENTITY_TYPES = ["", "user", "ip", "device", "host"] as const;

function entityTypeBadgeClass(entityType: string): string {
  switch (entityType) {
    case "user":
      return "entity-badge entity-badge--user";
    case "ip":
      return "entity-badge entity-badge--ip";
    case "device":
      return "entity-badge entity-badge--device";
    case "host":
      return "entity-badge entity-badge--host";
    default:
      return "entity-badge";
  }
}

function formatTimestamp(iso: string): string {
  try {
    return new Date(iso).toLocaleString();
  } catch {
    return iso;
  }
}

const EntityList: Component<EntityListProps> = (props) => {
  const [searchTerm, setSearchTerm] = createSignal("");
  const [error, setError] = createSignal<string | null>(null);

  async function loadEntities(): Promise<void> {
    setEntityState("loading", true);
    setError(null);
    try {
      const body: EntitySearchBody = {};
      const typeFilter = entityState.typeFilter;
      const term = searchTerm().trim();
      if (typeFilter) body.entity_type = typeFilter;
      if (term) body.identifier_contains = term;
      body.limit = 100;
      const results = await searchEntities(body);
      setEntityState("entities", results);
    } catch (err) {
      if (err instanceof ApiError) {
        setError(`${err.code}: ${err.message}`);
      } else {
        setError("Failed to load entities");
      }
    } finally {
      setEntityState("loading", false);
    }
  }

  onMount(() => {
    void loadEntities();
  });

  function handleTypeChange(e: Event): void {
    const target = e.target as HTMLSelectElement;
    setEntityState("typeFilter", target.value);
    void loadEntities();
  }

  function handleSearchInput(e: Event): void {
    const target = e.target as HTMLInputElement;
    setSearchTerm(target.value);
  }

  function handleSearchKeyDown(e: KeyboardEvent): void {
    if (e.key === "Enter") {
      void loadEntities();
    }
  }

  function handleEntityClick(entity: Entity): void {
    setEntityState("selectedEntityId", entity.id);
    props.onSelectEntity(entity.id);
  }

  return (
    <div>
      <div class="page-header">
        <h2 class="page-header__title">Entities</h2>
      </div>

      <div class="filter-panel">
        <div class="form-group">
          <label class="form-label" for="entity-type-filter">
            Type
          </label>
          <select
            id="entity-type-filter"
            class="form-select"
            value={entityState.typeFilter}
            onChange={handleTypeChange}
          >
            <For each={ENTITY_TYPES as unknown as string[]}>
              {(t) => (
                <option value={t}>{t === "" ? "All types" : t}</option>
              )}
            </For>
          </select>
        </div>

        <div class="form-group">
          <label class="form-label" for="entity-search">
            Identifier
          </label>
          <input
            id="entity-search"
            class="form-input"
            type="text"
            placeholder="Search identifier..."
            value={searchTerm()}
            onInput={handleSearchInput}
            onKeyDown={handleSearchKeyDown}
          />
        </div>

        <button class="btn btn--primary" type="button" onClick={() => void loadEntities()}>
          Search
        </button>
      </div>

      <Show when={error()}>
        <div class="error-msg" role="alert">
          {error()}
        </div>
      </Show>

      <Show when={entityState.loading}>
        <div class="loading" aria-live="polite">
          Loading entities...
        </div>
      </Show>

      <Show when={!entityState.loading && entityState.entities.length === 0}>
        <div class="empty-state">No entities found.</div>
      </Show>

      <div>
        <For each={entityState.entities}>
          {(entity) => (
            <div
              class={`card${props.selectedEntityId === entity.id ? " card--selected" : ""}`}
              onClick={() => handleEntityClick(entity)}
              role="button"
              tabIndex={0}
              onKeyDown={(e) => {
                if (e.key === "Enter" || e.key === " ") {
                  e.preventDefault();
                  handleEntityClick(entity);
                }
              }}
            >
              <div class="card__header">
                <span class="card__title">
                  {entity.display_name ?? entity.identifier}
                </span>
                <span class={entityTypeBadgeClass(entity.entity_type)}>
                  {entity.entity_type}
                </span>
              </div>
              <div class="card__meta">
                <span>ID: {entity.identifier}</span>
                <span>Events: {entity.event_count}</span>
                <span>First: {formatTimestamp(entity.first_seen_at)}</span>
                <span>Last: {formatTimestamp(entity.last_seen_at)}</span>
              </div>
            </div>
          )}
        </For>
      </div>
    </div>
  );
};

export default EntityList;
