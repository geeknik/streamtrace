import type { Component } from "solid-js";
import { createSignal, createResource, Show, For } from "solid-js";
import { fetchEntity } from "../../api/entities";
import { ApiError } from "../../api/client";
import type { EntityDetail as EntityDetailType, EntityRelationship } from "../../api/types";

interface EntityDetailProps {
  entityId: string;
  onClose: () => void;
  onNavigateEntity: (id: string) => void;
  onViewTimeline: (entityId: string) => void;
}

function formatTimestamp(iso: string): string {
  try {
    return new Date(iso).toLocaleString();
  } catch {
    return iso;
  }
}

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

async function loadEntity(id: string): Promise<EntityDetailType> {
  return fetchEntity(id);
}

const EntityDetailComponent: Component<EntityDetailProps> = (props) => {
  const [data] = createResource(() => props.entityId, loadEntity);
  const [showAttributes, setShowAttributes] = createSignal(false);

  function handleRelationshipClick(rel: EntityRelationship): void {
    const targetId =
      rel.source_entity === props.entityId
        ? rel.target_entity
        : rel.source_entity;
    props.onNavigateEntity(targetId);
  }

  return (
    <div class="detail-panel">
      <div class="detail-panel__header">
        <span class="detail-panel__title">Entity Detail</span>
        <button
          class="btn btn--small"
          type="button"
          onClick={props.onClose}
          aria-label="Close detail panel"
        >
          Close
        </button>
      </div>

      <Show when={data.error}>
        <div class="error-msg" role="alert">
          {data.error instanceof ApiError
            ? `${data.error.code}: ${data.error.message}`
            : "Failed to load entity"}
        </div>
      </Show>

      <Show when={data.loading}>
        <div class="loading" aria-live="polite">
          Loading entity...
        </div>
      </Show>

      <Show when={data()}>
        {(detail) => (
          <>
            <div class="detail-section">
              <div class="detail-section__title">Identity</div>
              <div class="detail-row">
                <span class="detail-row__label">Type</span>
                <span class="detail-row__value">
                  <span class={entityTypeBadgeClass(detail().entity.entity_type)}>
                    {detail().entity.entity_type}
                  </span>
                </span>
              </div>
              <div class="detail-row">
                <span class="detail-row__label">Identifier</span>
                <span class="detail-row__value">{detail().entity.identifier}</span>
              </div>
              <div class="detail-row">
                <span class="detail-row__label">Display Name</span>
                <span class="detail-row__value">
                  {detail().entity.display_name ?? "(none)"}
                </span>
              </div>
            </div>

            <div class="detail-section">
              <div class="detail-section__title">Activity</div>
              <div class="detail-row">
                <span class="detail-row__label">Event Count</span>
                <span class="detail-row__value">{detail().entity.event_count}</span>
              </div>
              <div class="detail-row">
                <span class="detail-row__label">First Seen</span>
                <span class="detail-row__value timestamp">
                  {formatTimestamp(detail().entity.first_seen_at)}
                </span>
              </div>
              <div class="detail-row">
                <span class="detail-row__label">Last Seen</span>
                <span class="detail-row__value timestamp">
                  {formatTimestamp(detail().entity.last_seen_at)}
                </span>
              </div>
            </div>

            <div class="detail-section">
              <div class="detail-section__title">
                <button
                  class="btn btn--small"
                  type="button"
                  onClick={() => setShowAttributes((v) => !v)}
                >
                  {showAttributes() ? "Hide" : "Show"} Attributes
                </button>
              </div>
              <Show when={showAttributes()}>
                <pre class="code-block">
                  {JSON.stringify(detail().entity.attributes, null, 2)}
                </pre>
              </Show>
            </div>

            <div class="detail-section">
              <div class="detail-section__title">Relationships</div>
              <Show when={detail().relationships.length === 0}>
                <div class="empty-state">No relationships.</div>
              </Show>
              <For each={detail().relationships}>
                {(rel) => {
                  const isSource = rel.source_entity === props.entityId;
                  const relatedId = isSource
                    ? rel.target_entity
                    : rel.source_entity;
                  return (
                    <div
                      class="card"
                      onClick={() => handleRelationshipClick(rel)}
                      role="button"
                      tabIndex={0}
                      onKeyDown={(e) => {
                        if (e.key === "Enter" || e.key === " ") {
                          e.preventDefault();
                          handleRelationshipClick(rel);
                        }
                      }}
                    >
                      <div class="card__header">
                        <span class="card__title">
                          {isSource ? "-> " : "<- "}
                          {relatedId}
                        </span>
                        <span class="tag">{rel.relationship}</span>
                      </div>
                      <div class="card__meta">
                        <span>Events: {rel.event_count}</span>
                        <span>
                          {formatTimestamp(rel.first_seen_at)} -{" "}
                          {formatTimestamp(rel.last_seen_at)}
                        </span>
                      </div>
                    </div>
                  );
                }}
              </For>
            </div>

            <div style={{ "margin-top": "12px" }}>
              <button
                class="btn btn--primary"
                type="button"
                onClick={() => props.onViewTimeline(props.entityId)}
              >
                View Timeline
              </button>
            </div>
          </>
        )}
      </Show>
    </div>
  );
};

export default EntityDetailComponent;
