import type { Component, JSX } from "solid-js";
import Header from "./Header";
import Sidebar from "./Sidebar";
import type { Route } from "./Sidebar";

interface ShellProps {
  currentRoute: Route;
  onNavigate: (route: Route) => void;
  children: JSX.Element;
}

const Shell: Component<ShellProps> = (props) => {
  return (
    <div class="shell">
      <Header />
      <Sidebar
        currentRoute={props.currentRoute}
        onNavigate={props.onNavigate}
      />
      <main class="main-content">{props.children}</main>
    </div>
  );
};

export default Shell;
