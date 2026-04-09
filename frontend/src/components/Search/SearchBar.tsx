import type { Component } from "solid-js";
import { createSignal, Show, For } from "solid-js";
import { searchEvents } from "../../api/events";
import { ApiError } from "../../api/client";
import type { ForensicEvent } from "../../api/types";
import TimelineEvent from "../Timeline/TimelineEvent";

interface SearchBarProps {
  onSelectEvent: (id: string) => void;
  selectedEventId: string | null;
}

const SearchBar: Component<SearchBarProps> = (props) => {
  const [query, setQuery] = createSignal("");
  const [results, setResults] = createSignal<ForensicEvent[]>([]);
  const [total, setTotal] = createSignal(0);
  const [loading, setLoading] = createSignal(false);
  const [error, setError] = createSignal<string | null>(null);
  const [searched, setSearched] = createSignal(false);

  async function handleSearch(): Promise<void> {
    const q = query().trim();
    if (!q) return;
    setLoading(true);
    setError(null);
    setSearched(true);
    try {
      const result = await searchEvents(q, 50, 0);
      setResults(result.events);
      setTotal(result.total);
    } catch (err) {
      if (err instanceof ApiError) {
        setError(`${err.code}: ${err.message}`);
      } else {
        setError("Search failed");
      }
      setResults([]);
      setTotal(0);
    } finally {
      setLoading(false);
    }
  }

  function handleKeyDown(e: KeyboardEvent): void {
    if (e.key === "Enter") {
      void handleSearch();
    }
  }

  return (
    <div>
      <div class="search-bar">
        <input
          type="text"
          class="search-bar__input"
          placeholder="Search events..."
          value={query()}
          onInput={(e) => setQuery(e.currentTarget.value)}
          onKeyDown={handleKeyDown}
          aria-label="Search events"
        />
        <button
          class="btn btn--primary"
          onClick={() => void handleSearch()}
          disabled={loading()}
          type="button"
        >
          Search
        </button>
      </div>

      <Show when={error()}>
        <div class="error-msg" role="alert">
          {error()}
        </div>
      </Show>

      <Show when={loading()}>
        <div class="loading">Searching...</div>
      </Show>

      <Show when={searched() && !loading() && results().length === 0 && !error()}>
        <div class="empty-state">No results found.</div>
      </Show>

      <Show when={results().length > 0}>
        <div style={{ "margin-bottom": "8px", "font-size": "0.8125rem", color: "var(--text-secondary)" }}>
          {total()} result{total() !== 1 ? "s" : ""} found
        </div>
        <For each={results()}>
          {(event) => (
            <TimelineEvent
              event={event}
              selected={props.selectedEventId === event.id}
              onSelect={props.onSelectEvent}
            />
          )}
        </For>
      </Show>
    </div>
  );
};

export default SearchBar;
