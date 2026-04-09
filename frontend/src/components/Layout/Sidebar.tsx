import type { Component } from "solid-js";

export type Route =
  | "timeline"
  | "search"
  | "cases"
  | "entities"
  | "sequences"
  | "replay"
  | "holds"
  | "audit";

interface SidebarProps {
  currentRoute: Route;
  onNavigate: (route: Route) => void;
}

const navItems: { route: Route; label: string }[] = [
  { route: "timeline", label: "Timeline" },
  { route: "search", label: "Search" },
  { route: "cases", label: "Cases" },
  { route: "entities", label: "Entities" },
  { route: "sequences", label: "Sequences" },
  { route: "replay", label: "Replay" },
  { route: "holds", label: "Holds" },
  { route: "audit", label: "Audit Log" },
];

const Sidebar: Component<SidebarProps> = (props) => {
  return (
    <nav class="sidebar" aria-label="Main navigation">
      {navItems.map((item) => (
        <button
          class={`sidebar__nav-item${
            props.currentRoute === item.route
              ? " sidebar__nav-item--active"
              : ""
          }`}
          onClick={() => props.onNavigate(item.route)}
          type="button"
          aria-current={
            props.currentRoute === item.route ? "page" : undefined
          }
        >
          {item.label}
        </button>
      ))}
    </nav>
  );
};

export default Sidebar;
