/* @refresh reload */
import { render } from "solid-js/web";
import App from "./App";
import "./styles/global.css";

const root = document.getElementById("root");

if (!root) {
  throw new Error("Root element #root not found in document");
}

render(() => <App />, root);
