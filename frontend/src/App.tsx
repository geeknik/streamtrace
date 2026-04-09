import type { Component } from "solid-js";
import { createSignal, Show, Match, Switch } from "solid-js";
import Shell from "./components/Layout/Shell";
import type { Route } from "./components/Layout/Sidebar";
import Timeline from "./components/Timeline/Timeline";
import EventDetail from "./components/EventDetail/EventDetail";
import SearchBar from "./components/Search/SearchBar";
import CaseList from "./components/Cases/CaseList";
import CaseDetail from "./components/Cases/CaseDetail";
import EntityList from "./components/Entities/EntityList";
import EntityDetailComponent from "./components/Entities/EntityDetail";
import EntityGraph from "./components/Entities/EntityGraph";
import SequenceList from "./components/Sequences/SequenceList";
import ReplayControls from "./components/Replay/ReplayControls";
import HoldList from "./components/Holds/HoldList";
import AuditLog from "./components/Audit/AuditLog";
import { setTimelineState, timelineState } from "./stores/timeline";
import { entityState, setEntityState } from "./stores/entities";

const App: Component = () => {
  const [route, setRoute] = createSignal<Route>("timeline");
  const [selectedCaseId, setSelectedCaseId] = createSignal<string | null>(null);
  const [entityView, setEntityView] = createSignal<"list" | "graph">("list");

  function handleSelectEvent(id: string): void {
    setTimelineState("selectedEventId", id);
  }

  function handleCloseEvent(): void {
    setTimelineState("selectedEventId", null);
  }

  function handleSelectCase(id: string): void {
    setSelectedCaseId(id);
  }

  function handleCloseCase(): void {
    setSelectedCaseId(null);
  }

  function handleSelectEntity(id: string): void {
    setEntityState("selectedEntityId", id);
  }

  function handleCloseEntity(): void {
    setEntityState("selectedEntityId", null);
  }

  function handleNavigateEntity(id: string): void {
    setEntityState("selectedEntityId", id);
  }

  function handleViewEntityTimeline(_entityId: string): void {
    // Switch to timeline view with the entity's actor_id filter
    setTimelineState("filters", "actor_id", _entityId);
    setRoute("timeline");
  }

  return (
    <Shell currentRoute={route()} onNavigate={setRoute}>
      <Switch>
        {/* Timeline view */}
        <Match when={route() === "timeline"}>
          <div
            class={
              timelineState.selectedEventId
                ? "split-view"
                : "split-view split-view--full"
            }
          >
            <div class="split-view__list">
              <Timeline onSelectEvent={handleSelectEvent} />
            </div>
            <Show when={timelineState.selectedEventId}>
              <div class="split-view__detail">
                <EventDetail
                  eventId={timelineState.selectedEventId!}
                  onClose={handleCloseEvent}
                />
              </div>
            </Show>
          </div>
        </Match>

        {/* Search view */}
        <Match when={route() === "search"}>
          <div
            class={
              timelineState.selectedEventId
                ? "split-view"
                : "split-view split-view--full"
            }
          >
            <div class="split-view__list">
              <SearchBar
                onSelectEvent={handleSelectEvent}
                selectedEventId={timelineState.selectedEventId}
              />
            </div>
            <Show when={timelineState.selectedEventId}>
              <div class="split-view__detail">
                <EventDetail
                  eventId={timelineState.selectedEventId!}
                  onClose={handleCloseEvent}
                />
              </div>
            </Show>
          </div>
        </Match>

        {/* Cases view */}
        <Match when={route() === "cases"}>
          <div
            class={
              selectedCaseId()
                ? "split-view"
                : "split-view split-view--full"
            }
          >
            <div class="split-view__list">
              <CaseList
                onSelectCase={handleSelectCase}
                selectedCaseId={selectedCaseId()}
              />
            </div>
            <Show when={selectedCaseId()}>
              <div class="split-view__detail">
                <CaseDetail
                  caseId={selectedCaseId()!}
                  onClose={handleCloseCase}
                />
              </div>
            </Show>
          </div>
        </Match>

        {/* Entities view */}
        <Match when={route() === "entities"}>
          <div
            class={
              entityState.selectedEntityId
                ? "split-view"
                : "split-view split-view--full"
            }
          >
            <div class="split-view__list">
              <div class="tabs" style={{ "margin-bottom": "12px" }}>
                <button
                  class={`tab${entityView() === "list" ? " tab--active" : ""}`}
                  type="button"
                  onClick={() => setEntityView("list")}
                >
                  List
                </button>
                <button
                  class={`tab${entityView() === "graph" ? " tab--active" : ""}`}
                  type="button"
                  onClick={() => setEntityView("graph")}
                  disabled={!entityState.selectedEntityId}
                >
                  Graph
                </button>
              </div>
              <Show when={entityView() === "list"}>
                <EntityList
                  onSelectEntity={handleSelectEntity}
                  selectedEntityId={entityState.selectedEntityId}
                />
              </Show>
              <Show when={entityView() === "graph" && entityState.selectedEntityId}>
                <EntityGraph
                  entityId={entityState.selectedEntityId!}
                  onSelectEntity={handleNavigateEntity}
                />
              </Show>
            </div>
            <Show when={entityState.selectedEntityId}>
              <div class="split-view__detail">
                <EntityDetailComponent
                  entityId={entityState.selectedEntityId!}
                  onClose={handleCloseEntity}
                  onNavigateEntity={handleNavigateEntity}
                  onViewTimeline={handleViewEntityTimeline}
                />
              </div>
            </Show>
          </div>
        </Match>

        {/* Sequences view */}
        <Match when={route() === "sequences"}>
          <div class="split-view split-view--full">
            <div class="split-view__list">
              <SequenceList />
            </div>
          </div>
        </Match>

        {/* Replay view */}
        <Match when={route() === "replay"}>
          <div class="split-view split-view--full">
            <div class="split-view__list">
              <ReplayControls />
            </div>
          </div>
        </Match>

        {/* Holds view */}
        <Match when={route() === "holds"}>
          <div class="split-view split-view--full">
            <div class="split-view__list">
              <HoldList />
            </div>
          </div>
        </Match>

        {/* Audit Log view */}
        <Match when={route() === "audit"}>
          <div class="split-view split-view--full">
            <div class="split-view__list">
              <AuditLog />
            </div>
          </div>
        </Match>
      </Switch>
    </Shell>
  );
};

export default App;
